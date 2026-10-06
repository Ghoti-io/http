#!/usr/bin/env python3
"""Write the tracked seeds of the HTTP/2 and HPACK fuzz corpora.

Usage: fuzz-seeds.py <corpus-dir>   (tests/fuzz/corpus)

The seeds are valid traffic and the RFC 7541 Appendix C blocks, so that a run
starts from inputs that reach deep into the codec and not from noise. The
fuzzers' options byte is documented at the top of each harness.
"""
import os
import struct
import sys

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def frame(t, flags, stream, payload=b""):
    return struct.pack(">I", len(payload))[1:] + bytes([t, flags]) + struct.pack(">I", stream) + payload


def settings(pairs=(), ack=False):
    return frame(4, 1 if ack else 0, 0, b"".join(struct.pack(">HI", k, v) for k, v in pairs))


def hdr(block, stream, flags=5):
    return frame(1, flags, stream, block)


# HPACK blocks by hand (RFC 7541 C.4.1, C.4.2 and a request with plain strings).
B_REQ = bytes.fromhex("828684418cf1e3c2e5f23a6ba0ab90f4ff")
B_REQ2 = bytes.fromhex("828684be5886a8eb10649cbf")
B_PLAIN = bytes.fromhex("8286844100") + b"\x0fwww.example.com"[:0] + bytes.fromhex("0f") + b"www.example.com"
B_POST = bytes.fromhex("8387844180") if False else bytes.fromhex("828684") + b"\x41\x0fwww.example.com"
B_POST = B_POST.replace(bytes.fromhex("82"), bytes.fromhex("83"), 1)  # :method POST


def write(d, name, data):
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)


def main(root):
    h2 = os.path.join(root, "h2conn")
    # options byte: bit0 role (1 client), bits1-3 profile, bit4 add preface+SETTINGS,
    # bit5 OOM pass, bit6 client opens a stream; byte 1 the split seed.
    srv = 0x10
    write(h2, "get.seed", bytes([srv, 1]) + settings(ack=True) + hdr(B_REQ, 1))
    write(h2, "post-body.seed", bytes([srv, 2]) + hdr(B_POST, 1, 4)
          + frame(0, 0, 1, b"hello ") + frame(0, 1, 1, b"world"))
    write(h2, "continuation.seed", bytes([srv, 3]) + frame(1, 1, 1, B_REQ[:5])
          + frame(9, 0, 1, B_REQ[5:9]) + frame(9, 4, 1, B_REQ[9:]))
    write(h2, "two-streams.seed", bytes([srv | 0x20, 4]) + hdr(B_REQ, 1) + hdr(B_REQ2, 3))
    write(h2, "ping-settings.seed", bytes([srv, 5]) + frame(6, 0, 0, b"12345678")
          + settings([(3, 10), (4, 1000), (0x99, 1)]) + settings(ack=True))
    write(h2, "window-update.seed", bytes([srv | 4, 6]) + hdr(B_POST, 1, 4)
          + frame(0, 0, 1, b"x" * 20) + frame(8, 0, 1, struct.pack(">I", 100))
          + frame(8, 0, 0, struct.pack(">I", 5)))
    write(h2, "rst-priority.seed", bytes([srv | 0x0a, 7]) + hdr(B_REQ, 1, 4)
          + frame(2, 0, 1, struct.pack(">IB", 0, 15)) + frame(3, 0, 1, struct.pack(">I", 8)))
    write(h2, "goaway.seed", bytes([srv, 8]) + hdr(B_REQ, 1) + frame(7, 0, 0, struct.pack(">II", 1, 0) + b"bye"))
    write(h2, "padded-data.seed", bytes([srv, 9]) + hdr(B_POST, 1, 4)
          + frame(0, 9, 1, b"\x03" + b"abc" + b"\x00" * 3))
    write(h2, "trailers.seed", bytes([srv, 10]) + hdr(B_POST, 1, 4) + frame(0, 0, 1, b"d")
          + hdr(bytes.fromhex("400161" "0131"), 1, 5))
    write(h2, "bad-preface.seed", bytes([0, 11]) + b"GET / HTTP/1.1\r\n\r\n")
    write(h2, "extension.seed", bytes([srv, 12]) + frame(0xee, 5, 3, b"ext") + settings([(0x99, 7)]))
    write(h2, "push-promise.seed", bytes([srv, 13]) + frame(5, 4, 1, struct.pack(">I", 2) + b"x"))
    write(h2, "continuation-flood.seed", bytes([srv | 0x08, 14]) + frame(1, 1, 1, b"\x82")
          + b"".join(frame(9, 0, 1, b"\x84") for _ in range(5)))
    write(h2, "client-response.seed", bytes([0x01 | 0x10 | 0x40, 15])
          + settings(ack=True) + hdr(bytes.fromhex("88"), 1, 4) + frame(0, 1, 1, b"ok"))
    write(h2, "client-interim.seed", bytes([0x01 | 0x10 | 0x40, 16])
          + hdr(bytes.fromhex("4803333033"), 1, 4) + hdr(bytes.fromhex("88"), 1, 5))

    hp = os.path.join(root, "hpack")
    # options: bits0-2 limit profile, bit3 OOM pass, bit4 small table; then
    # length-prefixed blocks.
    def blocks(*bs):
        return b"".join(bytes([len(b)]) + b for b in bs)
    write(hp, "c4-requests.seed", bytes([0x08]) + blocks(
        bytes.fromhex("828684418cf1e3c2e5f23a6ba0ab90f4ff"),
        bytes.fromhex("828684be5886a8eb10649cbf"),
        bytes.fromhex("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf")))
    write(hp, "c3-plain.seed", bytes([0x00]) + blocks(
        bytes.fromhex("828684410f7777772e6578616d706c652e636f6d"),
        bytes.fromhex("828684be58086e6f2d6361636865")))
    write(hp, "c6-small.seed", bytes([0x10]) + blocks(
        bytes.fromhex("488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3"),
        bytes.fromhex("4883640effc1c0bf")))
    write(hp, "size-update.seed", bytes([0x00]) + blocks(bytes.fromhex("3fe11f82"), bytes.fromhex("20" "3fe11f" "82")))
    write(hp, "bad-index.seed", bytes([0x00]) + blocks(bytes.fromhex("80")))
    write(hp, "huffman-bad.seed", bytes([0x00]) + blocks(bytes.fromhex("0001618107"), bytes.fromhex("000161820fff")))
    write(hp, "never-indexed.seed", bytes([0x00]) + blocks(bytes.fromhex("100870617373776f726406736563726574")))

    rt = os.path.join(root, "hpack-roundtrip")
    write(rt, "fields.seed", bytes([0, 0x90, 0x20, 0x41, 3]) + b"abc" + bytes([5]) + b"hello" + bytes([0x00, 0x95, 2, 0x55]) + b"xy")
    write(rt, "resize.seed", bytes([1, 0x90, 0x41, 0x40, 0x05, 0x91, 0x20, 0xc1, 2]) + b"zzzz" + bytes([4]) + b"data" + bytes([0x00]))
    write(rt, "custom-names.seed", bytes([0, 0x80, 3]) + b"name" + bytes([6]) + b"value1" + bytes([0x82, 2]) + b"nm" + bytes([2]) + b"v2")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])

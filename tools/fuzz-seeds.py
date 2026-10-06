#!/usr/bin/env python3
"""Write the tracked seeds of the HTTP/2, HPACK and WebSocket fuzz corpora.

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


def ws_frame(opcode, payload=b"", fin=True, masked=True, rsv=0, key=b"\x37\xfa\x21\x3d"):
    """One WebSocket frame, by hand from RFC 6455 section 5.2."""
    n = len(payload)
    out = bytes([(0x80 if fin else 0) | (rsv << 4) | opcode])
    m = 0x80 if masked else 0
    if n < 126:
        out += bytes([m | n])
    elif n < 65536:
        out += bytes([m | 126]) + struct.pack(">H", n)
    else:
        out += bytes([m | 127]) + struct.pack(">Q", n)
    if masked:
        out += key
        payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
    return out + payload


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

    ws(root)


def ws(root):
    # ws-conn: byte 0 options (bit0 client role, bits1-3 limit profile, bit4
    # deflate negotiated, bit5 OOM pass, bit6 echo, bit7 fix the mask bit),
    # byte 1 the split seed, byte 2 the deflate variant, then the peer's bytes.
    c = os.path.join(root, "ws-conn")
    srv = 0x00
    write(c, "text.seed", bytes([srv | 0x40, 1, 0]) + ws_frame(1, b"Hello"))
    write(c, "rfc-hello-masked.seed", bytes([srv, 2, 0]) + bytes.fromhex("818537fa213d7f9f4d5158"))
    write(c, "fragments-ping.seed", bytes([srv | 0x40, 3, 0]) + ws_frame(1, b"Hel", False) + ws_frame(9, b"p") + ws_frame(0, b"lo", True))
    write(c, "binary-large.seed", bytes([srv | 0x40, 4, 0]) + ws_frame(2, bytes(range(256)) * 2))
    write(c, "close.seed", bytes([srv, 5, 0]) + ws_frame(1, b"x") + ws_frame(8, struct.pack(">H", 1000) + b"bye"))
    write(c, "close-bad-code.seed", bytes([srv, 6, 0]) + ws_frame(8, struct.pack(">H", 1005)))
    write(c, "utf8-split.seed", bytes([srv, 7, 0]) + ws_frame(1, b"a\xe2\x82", False) + ws_frame(0, b"\xac", True))
    write(c, "utf8-bad.seed", bytes([srv, 8, 0]) + ws_frame(1, b"\xed\xa0\x80"))
    write(c, "unmasked.seed", bytes([srv, 9, 0]) + ws_frame(1, b"x", masked=False))
    write(c, "reserved-bit.seed", bytes([srv, 10, 0]) + ws_frame(1, b"x", rsv=2))
    write(c, "bad-opcode.seed", bytes([srv, 11, 0]) + ws_frame(3, b"x"))
    write(c, "long-ping.seed", bytes([srv, 12, 0]) + ws_frame(9, b"x" * 126))
    write(c, "flood.seed", bytes([srv | 0x08 | 0x80, 13, 0]) + b"".join(ws_frame(9, b"p") for _ in range(6)))
    write(c, "fragment-flood.seed", bytes([srv | 0x06, 14, 0]) + ws_frame(2, b"a", False) + b"".join(ws_frame(0, b"a", False) for _ in range(5)))
    write(c, "too-big.seed", bytes([srv | 0x04, 15, 0]) + ws_frame(2, b"x" * 40, False) + ws_frame(0, b"y" * 40, True))
    write(c, "client-unmasked.seed", bytes([1 | 0x40, 16, 0]) + ws_frame(1, b"Hello", masked=False) + ws_frame(9, b"p", masked=False))
    write(c, "client-masked.seed", bytes([1, 17, 0]) + ws_frame(1, b"Hello"))
    # permessage-deflate: RFC 7692 section 7.2.3's "Hello", and the same with BFINAL set.
    hello = bytes.fromhex("f248cdc9c90700")
    again = bytes.fromhex("f200110000")
    final = bytes.fromhex("f348cdc9c90700")
    d = bytes([srv | 0x10 | 0x40, 18, 0])
    write(c, "deflate-hello.seed", d + ws_frame(1, hello, rsv=4))
    write(c, "deflate-takeover.seed", d + ws_frame(1, hello, rsv=4) + ws_frame(1, again, rsv=4))
    write(c, "deflate-final-block.seed", d + ws_frame(1, final, rsv=4) + ws_frame(1, hello, rsv=4))
    write(c, "deflate-fragmented.seed", d + ws_frame(1, hello[:3], False, rsv=4) + ws_frame(0, hello[3:], True))
    write(c, "deflate-empty.seed", d + ws_frame(1, b"\x00", rsv=4) + ws_frame(2, b"\x00", rsv=4))
    write(c, "deflate-bad.seed", d + ws_frame(2, b"\xff\xff\xff\xff", rsv=4))
    write(c, "deflate-no-takeover.seed", bytes([srv | 0x10 | 0x40, 19, 0x05]) + ws_frame(1, hello, rsv=4) + ws_frame(1, hello, rsv=4))
    write(c, "deflate-rsv1-control.seed", d + ws_frame(9, b"", rsv=4))

    # ws-roundtrip: byte 0 the negotiation, byte 1 the cut seed, then operations.
    r = os.path.join(root, "ws-roundtrip")
    write(r, "plain.seed", bytes([0, 1, 0x05]) + b"hello" + bytes([0x95]) + b"\x00\x01\x02\x03\x04" + bytes([0x40]))
    write(r, "deflate.seed", bytes([1, 2, 0x04]) + b"lorem ipsum" + bytes([0x84]) + b"dolor sit amet" + bytes([0x24]) + b"consectetur adipiscing" + bytes([0x42]))
    write(r, "deflate-no-takeover.seed", bytes([7, 3, 0x03]) + b"abcabcabc" + bytes([0x83]) + b"abcabcabc" + bytes([0x31]) + b"p")
    write(r, "deflate-windows.seed", bytes([0x39, 4, 0x07]) + b"x" * 91 + bytes([0x87]) + b"y" * 91 + bytes([0xc0]))
    write(r, "fragments.seed", bytes([1, 5, 0x2f]) + bytes(range(97, 123)) * 20 + bytes([0xa5]) + b"abcde")

    # ws-handshake: byte 0 the server policy, byte 1 the client's offer, then fields.
    h = os.path.join(root, "ws-handshake")
    req = (b"Host: server.example.com\nUpgrade: websocket\nConnection: Upgrade\n"
           b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\nSec-WebSocket-Version: 13\n")
    write(h, "rfc.seed", bytes([0, 0]) + req + b"Sec-WebSocket-Protocol: chat, superchat\n")
    write(h, "deflate.seed", bytes([0x81, 0x01]) + req + b"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\n")
    write(h, "deflate-params.seed", bytes([0x8f, 0x1d]) + req + b"Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; server_max_window_bits=10, permessage-deflate\n")
    write(h, "response.seed", bytes([0x20, 0x01]) + b"Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover\nSec-WebSocket-Protocol: chat\n")
    write(h, "bad-version.seed", bytes([0, 0]) + req.replace(b"13", b"8"))
    write(h, "quoted.seed", bytes([0x81, 0x00]) + req + b'Sec-WebSocket-Extensions: permessage-deflate; server_max_window_bits="9"\n')


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])

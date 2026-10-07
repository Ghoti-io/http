# What the WebSocket codec enforces of RFC 7692 (permessage-deflate)

**Status:** describes what shipped (version 0.0.0).

permessage-deflate is the one extension this codec implements: `ws_deflate.h`
negotiates it, `ws_conn.h` runs it with the deflate encoder and decoder of the
`compress` library (a required dependency, as is `security`). Everything in
`rfc6455.md` applies; this is what is specific to the extension.

## Negotiation (section 7)

- A server accepts the first offer of `permessage-deflate` it can accept, and
  none after it; an offer with a parameter that is unknown, repeated or has an
  invalid value is declined and a later offer may still be taken (section 7.1:
  the server MUST decline it). Parameter names and the extension name are
  compared without regard to case; values may be quoted. A window is a decimal
  8 to 15 with no sign and no leading zero.
- `server_no_context_takeover` and `client_no_context_takeover`: the server
  responds with each that the client offered or that its own policy demands (a
  server may ask for either whether or not it was offered, section 7.1.1).
- `server_max_window_bits`: the tighter of the offer's and the policy's, written
  to the response; `client_max_window_bits` only if the offer named the
  parameter (with or without a value; section 7.1.2.2 forbids it otherwise), as
  the tighter of the offer's value and the policy's.
- A client (`ghttp_ws_deflate_client_verify`) fails the connection on a response
  that has an unknown or repeated parameter, an invalid value, `client_max_window_bits`
  where none was offered or without a value, a window larger than it offered,
  or that does not honour an offered `server_no_context_takeover` or
  `server_max_window_bits`.
- `make test` checks the property the two negotiations exist for: whatever a
  client offers and a server answers, the client accepts, and both ends agree
  on what the server and the client do (`fuzz_ws_handshake`).

## Compression and decompression (section 7.2)

- The first frame of a compressed message has RSV1 set; its continuations do
  not; control frames are never compressed (RSV1 there is an error). A message
  may be sent uncompressed on a connection that negotiated the extension
  (`ghttp_ws_conn_set_compress_min()`), and that leaves the context alone.
- A message is compressed as one deflate stream that ends with a sync flush;
  the trailing `00 00 ff ff` is not sent, and is supplied to the decompressor
  when the message ends. An empty message is the single octet `00`. The
  octets of RFC 7692 section 7.2.3's examples are in `test_ws_deflate.cpp`,
  from the compressor's own output and not copied from the specification's
  text into the code.
- A message must end at a block boundary once the trailer is appended: data cut
  off inside a block would read the trailer as more of itself, so a second empty
  stored block is fed after it and must be consumed whole with no output, or the
  message is refused (1007).
- A message whose last block has BFINAL set is accepted (section 7.2.3.4).
  The decompressor's stream is then over, so it starts afresh, **which ends
  context takeover for the next message even when it was negotiated**: this
  codec does not carry history across a final block. Octets after a final
  block are accepted if they are zero and at most four in all (section 7.2.3.4's
  example has one);
  anything else after it is an error.
- Context takeover is held to the agreement. With `*_no_context_takeover` the
  named side's compressor and the other side's decompressor start every message
  empty, so a peer that references the previous message when it was told not to
  is refused (1007).
- Windows: this end compresses with the window it agreed (8 to 15 bits) and
  decompresses with 15 bits whatever was agreed, so a peer that does not keep
  its window to the agreement is tolerated rather than refused. A window of 8
  bits is a real 256-octet window in the compress library (measured: a repeat
  400 octets back is found at 9 bits and not at 8), so it is negotiated as
  asked; zlib widens 8 to 9 silently, which a decompressor with 15 bits does
  not notice.

## Bounds (this library's addition)

Decompression is where a small message becomes a large one, so it is bounded
three ways, each judged as the output is made:

- the message limit, never exceeded by more than one octet and that octet is
  not kept: `ghttp_ws_inflate_update` asks the decoder for at most one octet
  past what is allowed;
- `max_expansion_ratio`: output octets per input octet of the message, with a
  slack of 256 octets so that a short message of a few octets may be a
  sentence. The default, 1032, is the format's own ceiling (a 258-octet match in
  two bits), so no valid stream is refused at the default. It is the
  connection's CPU bound: set it lower to refuse a bomb sooner. 0 is no ratio
  limit, and the message limit then bounds the output alone. The close reason
  says which fired, the size limit or the ratio;
- the size of what arrives compressed: the message limit and 1/64 of it and 16
  octets (an incompressible message of exactly the limit is a little larger
  compressed).

All three close the connection with 1009 and none of them is applied to a
message this end sends beyond the message limit.

The decompressor's own limits count over the life of a stream, which context
takeover makes the whole connection, so they are switched off and the counts
above are per message.

## The compress library's encoder, and what this codec does about it

The deflate encoder sizes its staging buffer at the first call that reaches it,
and a flush before any update (a first message that is empty, or the first after
a reset) sizes it for a flush of nothing. The first large update after that
returns `GCOMP_ERR_LIMIT`. `ws_deflate.c` makes one empty update after creating
or resetting the encoder (`prime_encoder`), which allocates the buffer at its
full size and does nothing else; `test_ws_deflate.cpp` has a test for it. The
fix belongs in the compress library, where this has been reported.

## Not provided

- A compression level, strategy or dictionary: the encoder's defaults.
- `client_max_window_bits` as a limit on what a server's decompressor accepts
  (see above: decompression is always 15 bits).
- Other extensions: see the hook in `rfc6455.md`.

# Ghoti.io HTTP

An HTTP/1.1, HTTP/2 and WebSocket codec: for HTTP/1.1 an incremental parser and a writer
for requests and responses, for HTTP/2 a frame codec, HPACK and a connection
state machine for a client or a server, for WebSocket the opening handshake, a
frame codec and a connection with permessage-deflate, bytes in and bytes out. It never opens a socket, reads a file, asks
for the time or starts a thread, so the same code serves a server, a client, a
test and a fuzzer, and it builds before an event loop or TLS exist. It
implements the message syntax and framing of RFC 9112 and refuses what that RFC
forbids, so that two parties reading one connection cannot be made to disagree
about where a message ends.

It is a codec and nothing more: no client, no server, no routing, no cookies, no
content codings, no HTTP/3, no server push, no stream priorities, and no WebSocket
over HTTP/2 (RFC 8441: the connection is carrier-neutral, the handshake for it is
a later story). A request target is classified into its four forms
and kept verbatim; decoding and normalising it belongs to the caller.

## What it enforces

[documentation/rfc9112.md](documentation/rfc9112.md) lists, rule by rule, what
the parser and writer enforce and what they leave alone. In short, a message is
refused with `GHTTP_ERR_CORRUPT` for:

- both `Content-Length` and `Transfer-Encoding`, or `Content-Length` values that
  differ;
- a `Transfer-Encoding` whose last coding is not `chunked`;
- a bare LF or CR, a NUL, or any other control character;
- whitespace before a field's colon, and obsolete line folding;
- a malformed chunk-size line, or chunk data not followed by CRLF;
- an HTTP/1.1 request without exactly one `Host`.

Every unbounded quantity (head size, line length, field count, body size, chunk
size, trailer size and count) is capped by `GHTTP_Limits`. Exceeding a cap is
`GHTTP_ERR_LIMIT` at the same input byte however the input is split; nothing is
ever truncated.

## HTTP/2

`ghttp_h2_conn_*` (`<ghoti.io/http/h2conn.h>`) is RFC 9113 as bytes in and bytes
out, by prior knowledge (`PRI * HTTP/2.0`): you feed it what arrived, write what
it queued, and give it a millisecond tick if its per-interval limits are to
renew. It tracks every window and refuses to write past one, emits the GOAWAY or
RST_STREAM bytes itself, and delivers requests and responses as the same
`GHTTP_Request` and `GHTTP_Response` as the HTTP/1.1 parser. `ghttp_hpack_*`
(`<ghoti.io/http/hpack.h>`) is the RFC 7541 header codec on its own. Every
unbounded quantity (frame, header block, CONTINUATION count, header list, table,
streams, SETTINGS, PING and RST_STREAM per interval, buffered bytes) is capped by
`GHTTP_H2Limits`, and a decision is the same however the input is cut.
[documentation/rfc9113.md](documentation/rfc9113.md) and
[documentation/hpack.md](documentation/hpack.md) list what is enforced, what is
not, and the extension seams.

## WebSocket

`ghttp_ws_*` is RFC 6455 and permessage-deflate (RFC 7692) as bytes in and bytes
out, for either end. The handshake (`<ghoti.io/http/ws_handshake.h>`) works on the
request and response objects the HTTP/1.1 parser gives and the writer takes: a
server validates a client's request, refuses with 400, 405, 426 or 431 as the RFC
says, or builds the `101` with the accept value, the chosen subprotocol and the
negotiated extensions; a client builds its request and checks the response.
The connection (`<ghoti.io/http/ws_conn.h>`) then takes the bytes after the
handshake and reports one event per message, Ping, Pong or Close, however the
input was cut; it queues the Pong and the Close reply itself, refuses an unmasked
client frame, a reserved bit, a bad opcode, a fragmented control frame and
invalid UTF-8 (even split across frames and reads) with the close code the RFC
names, and caps every unbounded quantity (a frame, a message after decompression,
fragments, control frames per interval, the handshake, extension parameters, and
the expansion ratio of a compressed message) with `GHTTP_WsLimits`, closing with
1009 at the limit and not after it. `ghttp_ws_conn_send_message()` and friends
write the frames, masking a client's with fresh keys from the kernel generator.
[documentation/rfc6455.md](documentation/rfc6455.md) and
[documentation/permessage-deflate.md](documentation/permessage-deflate.md) list
what is enforced, what is not, and the seams. SHA-1 and the random source come
from `security`, and deflate from `compress`; there is no build without them.

```c
GHTTP_WsServerOptions options;
ghttp_ws_server_options_default(&options);
options.enable_deflate = 1;
GHTTP_WsServerResult result;
ghttp_ws_server_handshake(request, &options, response, &result);   // request: parsed
ghttp_write_response_head(out, response);                          // the 101, or a refusal
if (result.accepted) {
  GHTTP_WsConn * conn;
  ghttp_ws_conn_create(NULL, GHTTP_WS_SERVER, NULL, &result.negotiated, &conn);
  // then: feed the socket's bytes to ghttp_ws_conn_feed(), write ghttp_ws_conn_output()
}
```

## Example

```c
#include <ghoti.io/http/http.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  GHTTP_Parser * parser = NULL;
  ghttp_parser_create(GHTTP_PARSE_REQUEST, NULL, NULL, &parser);

  const char * input = "GET /hello?name=world HTTP/1.1\r\nHost: example.com\r\n\r\n";
  size_t length = strlen(input), off = 0;
  GHTTP_Event ev;
  do {
    size_t used;
    if (ghttp_parser_feed(parser, input + off, length - off, &used, &ev) != GHTTP_OK) {
      break; /* close the connection */
    }
    off += used;
    if (ev == GHTTP_EVENT_HEAD) {
      const GHTTP_Request * r = ghttp_parser_request(parser);
      printf("%s %s\n", ghttp_request_method(r), ghttp_request_target(r));
    }
  } while (ev != GHTTP_EVENT_NEED_MORE);

  ghttp_parser_destroy(parser);
  return 0;
}
```

The input may arrive in pieces of any size, from one byte to a whole pipelined
burst; the events and the data behind them are the same. `examples/echo.c`
feeds three bytes at a time and answers with the writer.

## The parser

- `ghttp_parser_create(kind, limits, allocator, &parser)` makes a request
  parser (the server side) or a response parser (the client side). `NULL` limits
  and `NULL` allocator mean the defaults.
- `ghttp_parser_feed()` uses a prefix of the input and reports one event:
  `HEAD` (read it with `ghttp_parser_request()` or `ghttp_parser_response()`),
  `BODY` (`ghttp_parser_body()`: bytes already free of chunk framing, pointing
  into your buffer), `END` (the message is complete; trailers are in
  `ghttp_parser_trailers()`), or `NEED_MORE`. Call again with what is left until
  `NEED_MORE`. Bytes after a message's end begin the next message.
- Any error other than `GHTTP_ERR_INVALID` ends the stream: the parser keeps
  returning it, and the connection should be closed.
- `ghttp_parser_finish()` is the peer closing. A response body that has no
  length ends there; anywhere else it is `GHTTP_ERR_CORRUPT`, because a
  truncated body is never reported as a complete one.
- A response parser needs `ghttp_parser_expect_response_to("HEAD")` before the
  response to a HEAD (and `"CONNECT"` for a tunnel): the answer to a HEAD has no
  body whatever its headers say.
- `ghttp_parser_framing()` and `ghttp_parser_upgrade()` report how the body is
  framed and whether the message is a CONNECT or an upgrade. A 101, or a 2xx to
  CONNECT, ends HTTP reading: the parser uses no more input and the rest is
  the other protocol's.

## The writer

`ghttp_write_request_head()` and `ghttp_write_response_head()` append a head to
a `GHTTP_Buffer`; `ghttp_write_chunk()` and `ghttp_write_chunked_end()` frame a
chunked body. The writer checks heads with the parser's own head predicates
(`GHTTP_ERR_INVALID`): no CR, LF, NUL or other control character in a value, a
token method and field names, a legal target for the method, a Content-Length
that does not conflict with a Transfer-Encoding, an HTTP/1.1 request with
exactly one Host. It does not consult `GHTTP_Limits`, does not check that the
body you append matches the framing headers, and does not apply the bodyless
status rules. The objects it writes are
the objects the parser returns, so a message can be parsed, edited and written
again.

## Building

```bash
./bootstrap.sh                                  # at the workspace root
export PKG_CONFIG_PATH="$PWD/.local/share/pkgconfig"
make -C libs/http test PREFIX="$PWD/.local"
```

`make test` runs the unit tests and the gates: `check-symbols` (every exported
symbol carries the version namespace), `check-aliasing`, and `check-defects`,
`check-hpack-tables` (the generated HPACK tables are what RFC 7541 says),
`check-defects`, which plants defects in a copy of the source (accepting
Content-Length with Transfer-Encoding, ignoring a limit twice, a result that
depends on where the input was split, an HTTP/2 flow-control off by one, an
unbounded CONTINUATION run, an HPACK table-size update not enforced, a skipped
stream-state check, an unmasked WebSocket frame accepted, UTF-8 not carried across
fragments, a fragmented control frame allowed, an inflate bomb limit off) and
requires the tests to go red for each, and
`check-oracle`, which parses a generated corpus (valid and invalid) with this
library and with llhttp, h11 and Go's net/http in one pinned container image
and requires every disagreement to be explained by a rule in
`tools/oracle/known-disagreements.tsv`; the HTTP/2 half does the same for
connections and HPACK against nghttp2, h2 (Python) and Go's `x/net/http2`, with
`tools/oracle/known-h2-disagreements.tsv`.
It needs docker or podman and the image (`make oracle-build`), and **fails**
without them; `make check-oracle-gate` shows the gate going red for planted
defects. `make test-valgrind`,
`make test-asan`, `make coverage` and `make fuzz FUZZ_TIME=60` (libFuzzer, needs
clang) are the others. It depends on `cutil` (the allocator), `security` (SHA-1 and
the random source, for the WebSocket handshake and masking keys) and `compress`
(deflate, for permessage-deflate).

## Status

Version 0.0.0, Linux verified. The Windows and macOS branches of the Makefile
are copied from `model` and have not been run. Contributions are not being
accepted at this time; see [CONTRIBUTING.md](CONTRIBUTING.md).

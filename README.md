# Ghoti.io HTTP

An HTTP/1.1 codec: an incremental parser and a writer for requests and
responses, bytes in and bytes out. It never opens a socket, reads a file, asks
for the time or starts a thread, so the same code serves a server, a client, a
test and a fuzzer, and it builds before an event loop or TLS exist. It
implements the message syntax and framing of RFC 9112 and refuses what that RFC
forbids, so that two parties reading one connection cannot be made to disagree
about where a message ends.

It is a codec and nothing more: no client, no server, no routing, no cookies, no
content codings, no HTTP/2, no HTTP/3, and no WebSocket beyond reporting that a
message asks for an upgrade. A request target is classified into its four forms
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
chunked body. The writer refuses what the parser would refuse
(`GHTTP_ERR_INVALID`): a CR or LF in any value, a Content-Length with a
Transfer-Encoding, an HTTP/1.1 request with no Host. The objects it writes are
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
which plants four defects in a copy of the source (accepting Content-Length with
Transfer-Encoding, ignoring a limit twice, a result that depends on where the
input was split) and requires the tests to go red for each. `make test-valgrind`,
`make test-asan`, `make coverage` and `make fuzz FUZZ_TIME=60` (libFuzzer, needs
clang) are the others. It depends on `cutil` only, for the allocator.

## Status

Version 0.0.0, Linux verified. The Windows and macOS branches of the Makefile
are copied from `model` and have not been run. Contributions are not being
accepted at this time; see [CONTRIBUTING.md](CONTRIBUTING.md).

/*
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * Copyright (C) 2026 Corey Pennycuff
 *
 * This file is part of Ghoti.io HTTP.
 *
 * Ghoti.io HTTP is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * Ghoti.io HTTP is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file
 *
 * Parse a request that arrives in pieces, then answer it with the writer.
 *
 * The library never touches a socket: this program stands in for one by
 * handing the parser a request three bytes at a time, and prints the response
 * the writer produces where a server would send it.
 */

#include <ghoti.io/http/http.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  const char request[] = "POST /echo?x=1 HTTP/1.1\r\n"
                         "Host: example.com\r\n"
                         "Transfer-Encoding: chunked\r\n"
                         "\r\n"
                         "5\r\nhello\r\n6;note\r\n world\r\n0\r\n\r\n";

  GHTTP_Parser * parser = NULL;
  GHTTP_Response * response = NULL;
  GHTTP_Buffer * out = NULL;
  int status = 1;

  if (ghttp_parser_create(GHTTP_PARSE_REQUEST, NULL, NULL, &parser) != GHTTP_OK) {
    goto done;
  }

  char body[64];
  size_t body_len = 0;
  int finished = 0;
  size_t total = strlen(request);
  for (size_t at = 0; at < total && !finished; at += 3) {
    size_t piece = total - at < 3 ? total - at : 3;
    size_t off = 0;
    GHTTP_Event ev;
    do {
      size_t used = 0;
      GHTTP_Result r =
          ghttp_parser_feed(parser, request + at + off, piece - off, &used, &ev);
      if (r != GHTTP_OK) {
        fprintf(stderr, "parse failed: %s\n", ghttp_result_string(r));
        goto done;
      }
      off += used;
      if (ev == GHTTP_EVENT_HEAD) {
        const GHTTP_Request * q = ghttp_parser_request(parser);
        printf("%s %s\n", ghttp_request_method(q), ghttp_request_target(q));
      } else if (ev == GHTTP_EVENT_BODY) {
        const void * data;
        size_t n;
        ghttp_parser_body(parser, &data, &n);
        // A body that does not fit is refused, never cut short: the
        // Content-Length below would otherwise claim bytes that are not there.
        if (n > sizeof(body) - body_len) {
          fprintf(stderr, "body larger than this example's buffer\n");
          goto done;
        }
        memcpy(body + body_len, data, n);
        body_len += n;
      } else if (ev == GHTTP_EVENT_END) {
        finished = 1;
      }
    } while (ev != GHTTP_EVENT_NEED_MORE);
  }

  if (ghttp_response_create(NULL, &response) != GHTTP_OK
      || ghttp_buffer_create(NULL, &out) != GHTTP_OK) {
    goto done;
  }
  char length[16];
  snprintf(length, sizeof(length), "%zu", body_len);
  if (ghttp_headers_add(ghttp_response_headers(response), "Content-Type",
          "text/plain") != GHTTP_OK
      || ghttp_headers_add(ghttp_response_headers(response), "Content-Length",
          length) != GHTTP_OK
      || ghttp_write_response_head(out, response) != GHTTP_OK
      || ghttp_buffer_append(out, body, body_len) != GHTTP_OK) {
    goto done;
  }
  fwrite(ghttp_buffer_data(out), 1, ghttp_buffer_size(out), stdout);
  printf("\n");
  status = 0;

done:
  ghttp_buffer_destroy(out);
  ghttp_response_destroy(response);
  ghttp_parser_destroy(parser);
  return status;
}

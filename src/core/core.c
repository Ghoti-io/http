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
 * Result strings.
 */

#include <ghoti.io/http/macros.h>
#include <ghoti.io/http/core.h>
#include <string.h>

const char * ghttp_result_string(GHTTP_Result result) {
  switch (result) {
    case GHTTP_OK:
      return "No error";
    case GHTTP_ERR_IO:
      return "I/O error";
    case GHTTP_ERR_FORMAT:
      return "Not valid HTTP";
    case GHTTP_ERR_UNSUPPORTED:
      return "Unsupported HTTP feature";
    case GHTTP_ERR_LIMIT:
      return "Limit exceeded";
    case GHTTP_ERR_CORRUPT:
      return "Malformed or forbidden HTTP message";
    case GHTTP_ERR_OOM:
      return "Out of memory";
    case GHTTP_ERR_INVALID:
      return "Invalid argument";
    case GHTTP_ERR_INTERNAL:
      return "Internal error";
    case GHTTP_RESULT_COUNT:
    default:
      return "Unknown error";
  }
}


void ghttp_limits_default(GHTTP_Limits * limits) {
  if (!limits) {
    return;
  }
  // Field by field and not a struct literal: a literal would leave padding
  // and any member added later at whatever the compiler chose.
  memset(limits, 0, sizeof(*limits));
  limits->max_head_bytes = GHTTP_DEFAULT_MAX_HEAD_BYTES;
  limits->max_line_length = GHTTP_DEFAULT_MAX_LINE_LENGTH;
  limits->max_header_count = GHTTP_DEFAULT_MAX_HEADER_COUNT;
  limits->max_trailer_bytes = GHTTP_DEFAULT_MAX_TRAILER_BYTES;
  limits->max_trailer_count = GHTTP_DEFAULT_MAX_TRAILER_COUNT;
  limits->max_body_bytes = GHTTP_DEFAULT_MAX_BODY_BYTES;
  limits->max_chunk_size = GHTTP_DEFAULT_MAX_CHUNK_SIZE;
}

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
 * Request and response heads.
 */

#include <ghoti.io/http/macros.h>
#include <ghoti.io/http/request.h>
#include <ghoti.io/http/response.h>
#include "http_internal.h"
#include <ghoti.io/cutil/allocator.h>
#include <string.h>

struct GHTTP_Request {
  const GHTTP_Allocator * allocator;
  char * method;
  char * target;
  int minor;
  GHTTP_Headers * headers;
};

struct GHTTP_Response {
  const GHTTP_Allocator * allocator;
  int status;
  char * reason;
  int minor;
  GHTTP_Headers * headers;
};

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

GHTTP_Result ghttp_request_create(
    const GHTTP_Allocator * allocator, GHTTP_Request ** out) {
  if (!out) {
    return GHTTP_ERR_INVALID;
  }
  if (!allocator) {
    allocator = ghttp_allocator_default();
  }
  GHTTP_Request * r = gcu_allocator_calloc(allocator, 1, sizeof(*r));
  if (!r) {
    return GHTTP_ERR_OOM;
  }
  r->allocator = allocator;
  r->minor = 1;
  r->method = ghttp_strndup(allocator, "GET", 3);
  r->target = ghttp_strndup(allocator, "/", 1);
  GHTTP_Result res = (r->method && r->target)
      ? ghttp_headers_create(allocator, &r->headers)
      : GHTTP_ERR_OOM;
  if (res != GHTTP_OK) {
    ghttp_request_destroy(r);
    return res;
  }
  *out = r;
  return GHTTP_OK;
}

void ghttp_request_destroy(GHTTP_Request * r) {
  if (!r) {
    return;
  }
  const GHTTP_Allocator * a = r->allocator;
  gcu_allocator_free(a, r->method);
  gcu_allocator_free(a, r->target);
  ghttp_headers_destroy(r->headers);
  gcu_allocator_free(a, r);
}

GHTTP_Result ghttp_request_assign(GHTTP_Request * r, const char * method,
    size_t method_len, const char * target, size_t target_len, int minor) {
  char * m = ghttp_strndup(r->allocator, method, method_len);
  char * t = ghttp_strndup(r->allocator, target, target_len);
  if (!m || !t) {
    gcu_allocator_free(r->allocator, m);
    gcu_allocator_free(r->allocator, t);
    return GHTTP_ERR_OOM;
  }
  gcu_allocator_free(r->allocator, r->method);
  gcu_allocator_free(r->allocator, r->target);
  r->method = m;
  r->target = t;
  r->minor = minor;
  return GHTTP_OK;
}

GHTTP_Result ghttp_request_set_method(
    GHTTP_Request * r, const char * method) {
  if (!r || !method || !ghttp_is_token(method, strlen(method))) {
    return GHTTP_ERR_INVALID;
  }
  char * m = ghttp_strndup(r->allocator, method, strlen(method));
  if (!m) {
    return GHTTP_ERR_OOM;
  }
  gcu_allocator_free(r->allocator, r->method);
  r->method = m;
  return GHTTP_OK;
}

GHTTP_Result ghttp_request_set_target(GHTTP_Request * r, const char * target) {
  if (!r || !target || !ghttp_is_target_text(target, strlen(target))) {
    return GHTTP_ERR_INVALID;
  }
  char * t = ghttp_strndup(r->allocator, target, strlen(target));
  if (!t) {
    return GHTTP_ERR_OOM;
  }
  gcu_allocator_free(r->allocator, r->target);
  r->target = t;
  return GHTTP_OK;
}

GHTTP_Result ghttp_request_set_version(GHTTP_Request * r, int minor) {
  if (!r || (minor != 0 && minor != 1)) {
    return GHTTP_ERR_INVALID;
  }
  r->minor = minor;
  return GHTTP_OK;
}

const char * ghttp_request_method(const GHTTP_Request * r) {
  return r ? r->method : NULL;
}

const char * ghttp_request_target(const GHTTP_Request * r) {
  return r ? r->target : NULL;
}

int ghttp_request_version(const GHTTP_Request * r) {
  return r ? r->minor : 0;
}

GHTTP_Headers * ghttp_request_headers(GHTTP_Request * r) {
  return r ? r->headers : NULL;
}

const GHTTP_Headers * ghttp_request_headers_const(const GHTTP_Request * r) {
  return r ? r->headers : NULL;
}

GHTTP_Result ghttp_request_target_form(
    const GHTTP_Request * r, GHTTP_TargetForm * out) {
  if (!r || !out) {
    return GHTTP_ERR_INVALID;
  }
  GHTTP_TargetForm form;
  if (ghttp_target_classify(r->method, r->target, &form) != GHTTP_OK) {
    return GHTTP_ERR_INVALID;
  }
  *out = form;
  return GHTTP_OK;
}

GHTTP_Result ghttp_request_target_split(const GHTTP_Request * r,
    const char ** path, size_t * path_len, const char ** query,
    size_t * query_len) {
  GHTTP_TargetForm form;
  if (!r || ghttp_request_target_form(r, &form) != GHTTP_OK
      || form != GHTTP_TARGET_ORIGIN) {
    return GHTTP_ERR_INVALID;
  }
  const char * q = strchr(r->target, '?');
  size_t plen = q ? (size_t)(q - r->target) : strlen(r->target);
  if (path) {
    *path = r->target;
  }
  if (path_len) {
    *path_len = plen;
  }
  if (query) {
    *query = q ? q + 1 : NULL;
  }
  if (query_len) {
    *query_len = q ? strlen(q + 1) : 0;
  }
  return GHTTP_OK;
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

GHTTP_Result ghttp_response_create(
    const GHTTP_Allocator * allocator, GHTTP_Response ** out) {
  if (!out) {
    return GHTTP_ERR_INVALID;
  }
  if (!allocator) {
    allocator = ghttp_allocator_default();
  }
  GHTTP_Response * r = gcu_allocator_calloc(allocator, 1, sizeof(*r));
  if (!r) {
    return GHTTP_ERR_OOM;
  }
  r->allocator = allocator;
  r->minor = 1;
  r->status = 200;
  r->reason = ghttp_strndup(allocator, "OK", 2);
  GHTTP_Result res = r->reason ? ghttp_headers_create(allocator, &r->headers)
                               : GHTTP_ERR_OOM;
  if (res != GHTTP_OK) {
    ghttp_response_destroy(r);
    return res;
  }
  *out = r;
  return GHTTP_OK;
}

void ghttp_response_destroy(GHTTP_Response * r) {
  if (!r) {
    return;
  }
  const GHTTP_Allocator * a = r->allocator;
  gcu_allocator_free(a, r->reason);
  ghttp_headers_destroy(r->headers);
  gcu_allocator_free(a, r);
}

GHTTP_Result ghttp_response_assign(GHTTP_Response * r, int status,
    const char * reason, size_t reason_len, int minor) {
  char * s = ghttp_strndup(r->allocator, reason, reason_len);
  if (!s) {
    return GHTTP_ERR_OOM;
  }
  gcu_allocator_free(r->allocator, r->reason);
  r->reason = s;
  r->status = status;
  r->minor = minor;
  return GHTTP_OK;
}

GHTTP_Result ghttp_response_set_status(
    GHTTP_Response * r, int status, const char * reason) {
  if (!r || status < 100 || status > 999) {
    return GHTTP_ERR_INVALID;
  }
  if (!reason) {
    reason = "";
  }
  size_t n = strlen(reason);
  if (!ghttp_is_field_text(reason, n)) {
    return GHTTP_ERR_INVALID;
  }
  return ghttp_response_assign(r, status, reason, n, r->minor);
}

GHTTP_Result ghttp_response_set_version(GHTTP_Response * r, int minor) {
  if (!r || (minor != 0 && minor != 1)) {
    return GHTTP_ERR_INVALID;
  }
  r->minor = minor;
  return GHTTP_OK;
}

int ghttp_response_status(const GHTTP_Response * r) {
  return r ? r->status : 0;
}

const char * ghttp_response_reason(const GHTTP_Response * r) {
  return r ? r->reason : NULL;
}

int ghttp_response_version(const GHTTP_Response * r) {
  return r ? r->minor : 0;
}

GHTTP_Headers * ghttp_response_headers(GHTTP_Response * r) {
  return r ? r->headers : NULL;
}

const GHTTP_Headers * ghttp_response_headers_const(const GHTTP_Response * r) {
  return r ? r->headers : NULL;
}

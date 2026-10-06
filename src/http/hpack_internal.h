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
 * The HPACK static table, generated from RFC 7541 Appendix A.
 */

#ifndef GHOTI_IO_GHTTP_SRC_HTTP_HPACK_INTERNAL_H
#define GHOTI_IO_GHTTP_SRC_HTTP_HPACK_INTERNAL_H

#include <ghoti.io/http/macros.h>
#include "coding_internal.h"
#include <stddef.h>

typedef struct GHTTP_HpackStaticEntry {
  const char * name;
  size_t name_len;
  const char * value;
  size_t value_len;
} GHTTP_HpackStaticEntry;

/** Indexes 1 to 61; entry 0 is a placeholder and never used. */
extern const GHTTP_HpackStaticEntry ghttp_hpack_static_table[62];

#define GHTTP_HPACK_STATIC_COUNT 61u

#endif // GHOTI_IO_GHTTP_SRC_HTTP_HPACK_INTERNAL_H

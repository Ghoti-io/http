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
 * @file namespace.h
 *
 * Maps every public name of this library into its version namespace.
 *
 * Kept in one file rather than beside each declaration: a type rename has to
 * be in effect before any struct tag that uses the name, and an internal
 * header may define such a tag without including the public header that
 * declares the typedef.
 *
 * `make check-symbols` fails if an exported symbol is missing from this list.
 *
 * See CONVENTIONS.md section 4.
 */

#ifndef GHOTI_IO_GHTTP_NAMESPACE_H
#define GHOTI_IO_GHTTP_NAMESPACE_H

#include <ghoti.io/http/libver.h>

/// @cond HIDDEN_SYMBOLS

// Public types, renamed as well as the functions so that two versions whose
// structs differ in layout cannot be confused for one another. GCU_* names
// are deliberately absent: they are cutil's, and cutil has already renamed
// them.
#define GHTTP_Allocator GHOTIIO_HTTP(GHTTP_Allocator)
#define GHTTP_Buffer GHOTIIO_HTTP(GHTTP_Buffer)
#define GHTTP_Event GHOTIIO_HTTP(GHTTP_Event)
#define GHTTP_Field GHOTIIO_HTTP(GHTTP_Field)
#define GHTTP_Framing GHOTIIO_HTTP(GHTTP_Framing)
#define GHTTP_HeaderFraming GHOTIIO_HTTP(GHTTP_HeaderFraming)
#define GHTTP_Headers GHOTIIO_HTTP(GHTTP_Headers)
#define GHTTP_Limits GHOTIIO_HTTP(GHTTP_Limits)
#define GHTTP_Parser GHOTIIO_HTTP(GHTTP_Parser)
#define GHTTP_ParserKind GHOTIIO_HTTP(GHTTP_ParserKind)
#define GHTTP_Request GHOTIIO_HTTP(GHTTP_Request)
#define GHTTP_Response GHOTIIO_HTTP(GHTTP_Response)
#define GHTTP_Result GHOTIIO_HTTP(GHTTP_Result)
#define GHTTP_TargetForm GHOTIIO_HTTP(GHTTP_TargetForm)
#define GHTTP_Upgrade GHOTIIO_HTTP(GHTTP_Upgrade)

// Public functions.
#define ghttp_allocator_default GHOTIIO_HTTP(ghttp_allocator_default)
#define ghttp_buffer_append GHOTIIO_HTTP(ghttp_buffer_append)
#define ghttp_buffer_clear GHOTIIO_HTTP(ghttp_buffer_clear)
#define ghttp_buffer_create GHOTIIO_HTTP(ghttp_buffer_create)
#define ghttp_buffer_data GHOTIIO_HTTP(ghttp_buffer_data)
#define ghttp_buffer_destroy GHOTIIO_HTTP(ghttp_buffer_destroy)
#define ghttp_buffer_size GHOTIIO_HTTP(ghttp_buffer_size)
#define ghttp_headers_add GHOTIIO_HTTP(ghttp_headers_add)
#define ghttp_headers_at GHOTIIO_HTTP(ghttp_headers_at)
#define ghttp_headers_clear GHOTIIO_HTTP(ghttp_headers_clear)
#define ghttp_headers_count GHOTIIO_HTTP(ghttp_headers_count)
#define ghttp_headers_create GHOTIIO_HTTP(ghttp_headers_create)
#define ghttp_headers_destroy GHOTIIO_HTTP(ghttp_headers_destroy)
#define ghttp_headers_find GHOTIIO_HTTP(ghttp_headers_find)
#define ghttp_limits_default GHOTIIO_HTTP(ghttp_limits_default)
#define ghttp_parser_body GHOTIIO_HTTP(ghttp_parser_body)
#define ghttp_parser_create GHOTIIO_HTTP(ghttp_parser_create)
#define ghttp_parser_destroy GHOTIIO_HTTP(ghttp_parser_destroy)
#define ghttp_parser_expect_response_to GHOTIIO_HTTP(ghttp_parser_expect_response_to)
#define ghttp_parser_feed GHOTIIO_HTTP(ghttp_parser_feed)
#define ghttp_parser_finish GHOTIIO_HTTP(ghttp_parser_finish)
#define ghttp_parser_framing GHOTIIO_HTTP(ghttp_parser_framing)
#define ghttp_parser_request GHOTIIO_HTTP(ghttp_parser_request)
#define ghttp_parser_response GHOTIIO_HTTP(ghttp_parser_response)
#define ghttp_parser_trailers GHOTIIO_HTTP(ghttp_parser_trailers)
#define ghttp_parser_upgrade GHOTIIO_HTTP(ghttp_parser_upgrade)
#define ghttp_request_create GHOTIIO_HTTP(ghttp_request_create)
#define ghttp_request_destroy GHOTIIO_HTTP(ghttp_request_destroy)
#define ghttp_request_headers GHOTIIO_HTTP(ghttp_request_headers)
#define ghttp_request_headers_const GHOTIIO_HTTP(ghttp_request_headers_const)
#define ghttp_request_method GHOTIIO_HTTP(ghttp_request_method)
#define ghttp_request_set_method GHOTIIO_HTTP(ghttp_request_set_method)
#define ghttp_request_set_target GHOTIIO_HTTP(ghttp_request_set_target)
#define ghttp_request_set_version GHOTIIO_HTTP(ghttp_request_set_version)
#define ghttp_request_target GHOTIIO_HTTP(ghttp_request_target)
#define ghttp_request_target_form GHOTIIO_HTTP(ghttp_request_target_form)
#define ghttp_request_target_split GHOTIIO_HTTP(ghttp_request_target_split)
#define ghttp_request_version GHOTIIO_HTTP(ghttp_request_version)
#define ghttp_response_create GHOTIIO_HTTP(ghttp_response_create)
#define ghttp_response_destroy GHOTIIO_HTTP(ghttp_response_destroy)
#define ghttp_response_headers GHOTIIO_HTTP(ghttp_response_headers)
#define ghttp_response_headers_const GHOTIIO_HTTP(ghttp_response_headers_const)
#define ghttp_response_reason GHOTIIO_HTTP(ghttp_response_reason)
#define ghttp_response_set_status GHOTIIO_HTTP(ghttp_response_set_status)
#define ghttp_response_set_version GHOTIIO_HTTP(ghttp_response_set_version)
#define ghttp_response_status GHOTIIO_HTTP(ghttp_response_status)
#define ghttp_response_version GHOTIIO_HTTP(ghttp_response_version)
#define ghttp_result_string GHOTIIO_HTTP(ghttp_result_string)
#define ghttp_write_chunk GHOTIIO_HTTP(ghttp_write_chunk)
#define ghttp_write_chunked_end GHOTIIO_HTTP(ghttp_write_chunked_end)
#define ghttp_write_request_head GHOTIIO_HTTP(ghttp_write_request_head)
#define ghttp_write_response_head GHOTIIO_HTTP(ghttp_write_response_head)

// Internal functions: hidden from the shared library, renamed anyway so
// that there is one rule rather than two.
#define ghttp_buffer_truncate GHOTIIO_HTTP(ghttp_buffer_truncate)
#define ghttp_framing_from_headers GHOTIIO_HTTP(ghttp_framing_from_headers)
#define ghttp_headers_add_raw GHOTIIO_HTTP(ghttp_headers_add_raw)
#define ghttp_headers_list_has GHOTIIO_HTTP(ghttp_headers_list_has)
#define ghttp_ieq GHOTIIO_HTTP(ghttp_ieq)
#define ghttp_is_field_text GHOTIIO_HTTP(ghttp_is_field_text)
#define ghttp_is_target_text GHOTIIO_HTTP(ghttp_is_target_text)
#define ghttp_is_tchar GHOTIIO_HTTP(ghttp_is_tchar)
#define ghttp_is_token GHOTIIO_HTTP(ghttp_is_token)
#define ghttp_request_assign GHOTIIO_HTTP(ghttp_request_assign)
#define ghttp_request_validate GHOTIIO_HTTP(ghttp_request_validate)
#define ghttp_reserve GHOTIIO_HTTP(ghttp_reserve)
#define ghttp_response_assign GHOTIIO_HTTP(ghttp_response_assign)
#define ghttp_response_validate GHOTIIO_HTTP(ghttp_response_validate)
#define ghttp_strndup GHOTIIO_HTTP(ghttp_strndup)
#define ghttp_target_classify GHOTIIO_HTTP(ghttp_target_classify)
#define ghttp_trailers_validate GHOTIIO_HTTP(ghttp_trailers_validate)
#define ghttp_trim_ows GHOTIIO_HTTP(ghttp_trim_ows)

/// @endcond

#endif // GHOTI_IO_GHTTP_NAMESPACE_H

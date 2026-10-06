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
#define GHTTP_H2Conn GHOTIIO_HTTP(GHTTP_H2Conn)
#define GHTTP_H2ErrorCode GHOTIIO_HTTP(GHTTP_H2ErrorCode)
#define GHTTP_H2Event GHOTIIO_HTTP(GHTTP_H2Event)
#define GHTTP_H2EventType GHOTIIO_HTTP(GHTTP_H2EventType)
#define GHTTP_H2Extension GHOTIIO_HTTP(GHTTP_H2Extension)
#define GHTTP_H2ExtensionFn GHOTIIO_HTTP(GHTTP_H2ExtensionFn)
#define GHTTP_H2ExtensionKind GHOTIIO_HTTP(GHTTP_H2ExtensionKind)
#define GHTTP_H2Frame GHOTIIO_HTTP(GHTTP_H2Frame)
#define GHTTP_H2FrameError GHOTIIO_HTTP(GHTTP_H2FrameError)
#define GHTTP_H2FrameHeader GHOTIIO_HTTP(GHTTP_H2FrameHeader)
#define GHTTP_H2FrameType GHOTIIO_HTTP(GHTTP_H2FrameType)
#define GHTTP_H2Limits GHOTIIO_HTTP(GHTTP_H2Limits)
#define GHTTP_H2Priority GHOTIIO_HTTP(GHTTP_H2Priority)
#define GHTTP_H2Role GHOTIIO_HTTP(GHTTP_H2Role)
#define GHTTP_H2SettingId GHOTIIO_HTTP(GHTTP_H2SettingId)
#define GHTTP_H2Settings GHOTIIO_HTTP(GHTTP_H2Settings)
#define GHTTP_H2StreamMode GHOTIIO_HTTP(GHTTP_H2StreamMode)
#define GHTTP_HeaderFraming GHOTIIO_HTTP(GHTTP_HeaderFraming)
#define GHTTP_Headers GHOTIIO_HTTP(GHTTP_Headers)
#define GHTTP_HpackDecoder GHOTIIO_HTTP(GHTTP_HpackDecoder)
#define GHTTP_HpackEncoder GHOTIIO_HTTP(GHTTP_HpackEncoder)
#define GHTTP_HpackHuffman GHOTIIO_HTTP(GHTTP_HpackHuffman)
#define GHTTP_HpackIndexing GHOTIIO_HTTP(GHTTP_HpackIndexing)
#define GHTTP_HpackLimits GHOTIIO_HTTP(GHTTP_HpackLimits)
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
#define ghttp_h2_conn_can_open_stream GHOTIIO_HTTP(ghttp_h2_conn_can_open_stream)
#define ghttp_h2_conn_connection_recv_window GHOTIIO_HTTP(ghttp_h2_conn_connection_recv_window)
#define ghttp_h2_conn_connection_send_window GHOTIIO_HTTP(ghttp_h2_conn_connection_send_window)
#define ghttp_h2_conn_consume GHOTIIO_HTTP(ghttp_h2_conn_consume)
#define ghttp_h2_conn_create GHOTIIO_HTTP(ghttp_h2_conn_create)
#define ghttp_h2_conn_destroy GHOTIIO_HTTP(ghttp_h2_conn_destroy)
#define ghttp_h2_conn_error GHOTIIO_HTTP(ghttp_h2_conn_error)
#define ghttp_h2_conn_finish GHOTIIO_HTTP(ghttp_h2_conn_finish)
#define ghttp_h2_conn_feed GHOTIIO_HTTP(ghttp_h2_conn_feed)
#define ghttp_h2_conn_local_settings GHOTIIO_HTTP(ghttp_h2_conn_local_settings)
#define ghttp_h2_conn_output GHOTIIO_HTTP(ghttp_h2_conn_output)
#define ghttp_h2_conn_output_consume GHOTIIO_HTTP(ghttp_h2_conn_output_consume)
#define ghttp_h2_conn_output_size GHOTIIO_HTTP(ghttp_h2_conn_output_size)
#define ghttp_h2_conn_peer_settings GHOTIIO_HTTP(ghttp_h2_conn_peer_settings)
#define ghttp_h2_conn_ping GHOTIIO_HTTP(ghttp_h2_conn_ping)
#define ghttp_h2_conn_request GHOTIIO_HTTP(ghttp_h2_conn_request)
#define ghttp_h2_conn_reset_stream GHOTIIO_HTTP(ghttp_h2_conn_reset_stream)
#define ghttp_h2_conn_response GHOTIIO_HTTP(ghttp_h2_conn_response)
#define ghttp_h2_conn_send_data GHOTIIO_HTTP(ghttp_h2_conn_send_data)
#define ghttp_h2_conn_send_extension_frame GHOTIIO_HTTP(ghttp_h2_conn_send_extension_frame)
#define ghttp_h2_conn_send_request GHOTIIO_HTTP(ghttp_h2_conn_send_request)
#define ghttp_h2_conn_send_response GHOTIIO_HTTP(ghttp_h2_conn_send_response)
#define ghttp_h2_conn_send_trailers GHOTIIO_HTTP(ghttp_h2_conn_send_trailers)
#define ghttp_h2_conn_send_window GHOTIIO_HTTP(ghttp_h2_conn_send_window)
#define ghttp_h2_conn_set_extension_handler GHOTIIO_HTTP(ghttp_h2_conn_set_extension_handler)
#define ghttp_h2_conn_set_stream_mode GHOTIIO_HTTP(ghttp_h2_conn_set_stream_mode)
#define ghttp_h2_conn_shutdown GHOTIIO_HTTP(ghttp_h2_conn_shutdown)
#define ghttp_h2_conn_stream_count GHOTIIO_HTTP(ghttp_h2_conn_stream_count)
#define ghttp_h2_conn_stream_is_active GHOTIIO_HTTP(ghttp_h2_conn_stream_is_active)
#define ghttp_h2_conn_stream_mode GHOTIIO_HTTP(ghttp_h2_conn_stream_mode)
#define ghttp_h2_conn_stream_windows GHOTIIO_HTTP(ghttp_h2_conn_stream_windows)
#define ghttp_h2_conn_tick GHOTIIO_HTTP(ghttp_h2_conn_tick)
#define ghttp_h2_conn_trailers GHOTIIO_HTTP(ghttp_h2_conn_trailers)
#define ghttp_h2_error_string GHOTIIO_HTTP(ghttp_h2_error_string)
#define ghttp_h2_frame_header_check GHOTIIO_HTTP(ghttp_h2_frame_header_check)
#define ghttp_h2_frame_header_parse GHOTIIO_HTTP(ghttp_h2_frame_header_parse)
#define ghttp_h2_frame_header_write GHOTIIO_HTTP(ghttp_h2_frame_header_write)
#define ghttp_h2_frame_parse GHOTIIO_HTTP(ghttp_h2_frame_parse)
#define ghttp_h2_frame_setting_at GHOTIIO_HTTP(ghttp_h2_frame_setting_at)
#define ghttp_h2_frame_type_string GHOTIIO_HTTP(ghttp_h2_frame_type_string)
#define ghttp_h2_limits_default GHOTIIO_HTTP(ghttp_h2_limits_default)
#define ghttp_h2_settings_default GHOTIIO_HTTP(ghttp_h2_settings_default)
#define ghttp_h2_write_data GHOTIIO_HTTP(ghttp_h2_write_data)
#define ghttp_h2_write_frame GHOTIIO_HTTP(ghttp_h2_write_frame)
#define ghttp_h2_write_goaway GHOTIIO_HTTP(ghttp_h2_write_goaway)
#define ghttp_h2_write_header_block GHOTIIO_HTTP(ghttp_h2_write_header_block)
#define ghttp_h2_write_ping GHOTIIO_HTTP(ghttp_h2_write_ping)
#define ghttp_h2_write_priority GHOTIIO_HTTP(ghttp_h2_write_priority)
#define ghttp_h2_write_rst_stream GHOTIIO_HTTP(ghttp_h2_write_rst_stream)
#define ghttp_h2_write_settings GHOTIIO_HTTP(ghttp_h2_write_settings)
#define ghttp_h2_write_window_update GHOTIIO_HTTP(ghttp_h2_write_window_update)
#define ghttp_headers_add GHOTIIO_HTTP(ghttp_headers_add)
#define ghttp_headers_at GHOTIIO_HTTP(ghttp_headers_at)
#define ghttp_headers_clear GHOTIIO_HTTP(ghttp_headers_clear)
#define ghttp_headers_count GHOTIIO_HTTP(ghttp_headers_count)
#define ghttp_headers_create GHOTIIO_HTTP(ghttp_headers_create)
#define ghttp_headers_destroy GHOTIIO_HTTP(ghttp_headers_destroy)
#define ghttp_headers_find GHOTIIO_HTTP(ghttp_headers_find)
#define ghttp_hpack_decode GHOTIIO_HTTP(ghttp_hpack_decode)
#define ghttp_hpack_decoder_create GHOTIIO_HTTP(ghttp_hpack_decoder_create)
#define ghttp_hpack_decoder_destroy GHOTIIO_HTTP(ghttp_hpack_decoder_destroy)
#define ghttp_hpack_decoder_failed GHOTIIO_HTTP(ghttp_hpack_decoder_failed)
#define ghttp_hpack_decoder_set_max_table_size GHOTIIO_HTTP(ghttp_hpack_decoder_set_max_table_size)
#define ghttp_hpack_decoder_table_count GHOTIIO_HTTP(ghttp_hpack_decoder_table_count)
#define ghttp_hpack_decoder_table_entry GHOTIIO_HTTP(ghttp_hpack_decoder_table_entry)
#define ghttp_hpack_decoder_table_max GHOTIIO_HTTP(ghttp_hpack_decoder_table_max)
#define ghttp_hpack_decoder_table_size GHOTIIO_HTTP(ghttp_hpack_decoder_table_size)
#define ghttp_hpack_encode GHOTIIO_HTTP(ghttp_hpack_encode)
#define ghttp_hpack_encode_field GHOTIIO_HTTP(ghttp_hpack_encode_field)
#define ghttp_hpack_encoder_create GHOTIIO_HTTP(ghttp_hpack_encoder_create)
#define ghttp_hpack_encoder_destroy GHOTIIO_HTTP(ghttp_hpack_encoder_destroy)
#define ghttp_hpack_encoder_set_peer_table_size GHOTIIO_HTTP(ghttp_hpack_encoder_set_peer_table_size)
#define ghttp_hpack_encoder_table_count GHOTIIO_HTTP(ghttp_hpack_encoder_table_count)
#define ghttp_hpack_encoder_table_entry GHOTIIO_HTTP(ghttp_hpack_encoder_table_entry)
#define ghttp_hpack_encoder_table_max GHOTIIO_HTTP(ghttp_hpack_encoder_table_max)
#define ghttp_hpack_encoder_table_size GHOTIIO_HTTP(ghttp_hpack_encoder_table_size)
#define ghttp_hpack_limits_default GHOTIIO_HTTP(ghttp_hpack_limits_default)
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
#define GHTTP_H2MsgInfo GHOTIIO_HTTP(GHTTP_H2MsgInfo)
#define GHTTP_HpackStaticEntry GHOTIIO_HTTP(GHTTP_HpackStaticEntry)
#define ghttp_buffer_consume GHOTIIO_HTTP(ghttp_buffer_consume)
#define ghttp_buffer_truncate GHOTIIO_HTTP(ghttp_buffer_truncate)
#define ghttp_framing_from_headers GHOTIIO_HTTP(ghttp_framing_from_headers)
#define ghttp_h2msg_build_request GHOTIIO_HTTP(ghttp_h2msg_build_request)
#define ghttp_h2msg_build_response GHOTIIO_HTTP(ghttp_h2msg_build_response)
#define ghttp_h2msg_build_trailers GHOTIIO_HTTP(ghttp_h2msg_build_trailers)
#define ghttp_h2msg_list_size GHOTIIO_HTTP(ghttp_h2msg_list_size)
#define ghttp_h2msg_read_request GHOTIIO_HTTP(ghttp_h2msg_read_request)
#define ghttp_h2msg_read_response GHOTIIO_HTTP(ghttp_h2msg_read_response)
#define ghttp_h2msg_read_trailers GHOTIIO_HTTP(ghttp_h2msg_read_trailers)
#define ghttp_h2msg_status_has_no_content GHOTIIO_HTTP(ghttp_h2msg_status_has_no_content)
#define ghttp_headers_add_raw GHOTIIO_HTTP(ghttp_headers_add_raw)
#define ghttp_headers_list_has GHOTIIO_HTTP(ghttp_headers_list_has)
#define ghttp_hpack_static_table GHOTIIO_HTTP(ghttp_hpack_static_table)
#define ghttp_huff_code GHOTIIO_HTTP(ghttp_huff_code)
#define ghttp_huff_decode GHOTIIO_HTTP(ghttp_huff_decode)
#define ghttp_huff_encode GHOTIIO_HTTP(ghttp_huff_encode)
#define ghttp_huff_encoded_len GHOTIIO_HTTP(ghttp_huff_encoded_len)
#define ghttp_huff_len GHOTIIO_HTTP(ghttp_huff_len)
#define ghttp_huff_tree GHOTIIO_HTTP(ghttp_huff_tree)
#define ghttp_huff_tree_nodes GHOTIIO_HTTP(ghttp_huff_tree_nodes)
#define ghttp_ieq GHOTIIO_HTTP(ghttp_ieq)
#define ghttp_int_decode GHOTIIO_HTTP(ghttp_int_decode)
#define ghttp_int_encode GHOTIIO_HTTP(ghttp_int_encode)
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

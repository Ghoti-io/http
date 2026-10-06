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
 * @file h2frame.h
 *
 * HTTP/2 frames: RFC 9113 sections 4 and 6.
 *
 * The frame layer is stateless. A frame header is nine octets; a payload is
 * validated against its header alone (length, flags and stream identifier as
 * the type allows) and returned as views into the caller's bytes. What a frame
 * means for a stream, or for the connection, is the business of the connection
 * state machine (h2conn.h), not of this file.
 *
 * Every error carries what RFC 9113 says to do about it: an error code and
 * whether it ends the connection or only one stream.
 *
 * Writers append whole frames to a GHTTP_Buffer, which is restored to its size
 * on entry when a write fails. Padding is written as zeros.
 */

#ifndef GHOTI_IO_GHTTP_H2FRAME_H
#define GHOTI_IO_GHTTP_H2FRAME_H

#include <ghoti.io/http/buffer.h>
#include <ghoti.io/http/core.h>
#include <ghoti.io/http/macros.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Octets in a frame header. */
#define GHTTP_H2_FRAME_HEADER_SIZE 9u
/** The client connection preface (RFC 9113 section 3.4), 24 octets. */
#define GHTTP_H2_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define GHTTP_H2_PREFACE_SIZE 24u

#define GHTTP_H2_DEFAULT_MAX_FRAME_SIZE 16384u
#define GHTTP_H2_MAX_MAX_FRAME_SIZE 16777215u
#define GHTTP_H2_MAX_WINDOW 2147483647u
#define GHTTP_H2_DEFAULT_WINDOW 65535u
#define GHTTP_H2_MAX_STREAM_ID 2147483647u

/** Frame types (section 6). Others are legal and are extensions. */
typedef enum GHTTP_H2FrameType {
  GHTTP_H2_DATA = 0x0,
  GHTTP_H2_HEADERS = 0x1,
  GHTTP_H2_PRIORITY = 0x2,
  GHTTP_H2_RST_STREAM = 0x3,
  GHTTP_H2_SETTINGS = 0x4,
  GHTTP_H2_PUSH_PROMISE = 0x5,
  GHTTP_H2_PING = 0x6,
  GHTTP_H2_GOAWAY = 0x7,
  GHTTP_H2_WINDOW_UPDATE = 0x8,
  GHTTP_H2_CONTINUATION = 0x9
} GHTTP_H2FrameType;

#define GHTTP_H2_FLAG_END_STREAM 0x01u
#define GHTTP_H2_FLAG_ACK 0x01u
#define GHTTP_H2_FLAG_END_HEADERS 0x04u
#define GHTTP_H2_FLAG_PADDED 0x08u
#define GHTTP_H2_FLAG_PRIORITY 0x20u

/** Error codes (section 7). */
typedef enum GHTTP_H2ErrorCode {
  GHTTP_H2_NO_ERROR = 0x0,
  GHTTP_H2_PROTOCOL_ERROR = 0x1,
  GHTTP_H2_INTERNAL_ERROR = 0x2,
  GHTTP_H2_FLOW_CONTROL_ERROR = 0x3,
  GHTTP_H2_SETTINGS_TIMEOUT = 0x4,
  GHTTP_H2_STREAM_CLOSED = 0x5,
  GHTTP_H2_FRAME_SIZE_ERROR = 0x6,
  GHTTP_H2_REFUSED_STREAM = 0x7,
  GHTTP_H2_CANCEL = 0x8,
  GHTTP_H2_COMPRESSION_ERROR = 0x9,
  GHTTP_H2_CONNECT_ERROR = 0xa,
  GHTTP_H2_ENHANCE_YOUR_CALM = 0xb,
  GHTTP_H2_INADEQUATE_SECURITY = 0xc,
  GHTTP_H2_HTTP_1_1_REQUIRED = 0xd
} GHTTP_H2ErrorCode;

/** Setting identifiers (section 6.5.2). */
typedef enum GHTTP_H2SettingId {
  GHTTP_H2_SETTINGS_HEADER_TABLE_SIZE = 0x1,
  GHTTP_H2_SETTINGS_ENABLE_PUSH = 0x2,
  GHTTP_H2_SETTINGS_MAX_CONCURRENT_STREAMS = 0x3,
  GHTTP_H2_SETTINGS_INITIAL_WINDOW_SIZE = 0x4,
  GHTTP_H2_SETTINGS_MAX_FRAME_SIZE = 0x5,
  GHTTP_H2_SETTINGS_MAX_HEADER_LIST_SIZE = 0x6
} GHTTP_H2SettingId;

/** A name for an error code, such as "PROTOCOL_ERROR"; "UNKNOWN" if none. */
GHTTP_API const char * ghttp_h2_error_string(uint32_t code);

/** A name for a frame type, such as "HEADERS"; "UNKNOWN" if none. */
GHTTP_API const char * ghttp_h2_frame_type_string(uint8_t type);

/** The nine-octet header, decoded (section 4.1). */
typedef struct GHTTP_H2FrameHeader {
  uint32_t length;     ///< Payload octets, up to 2^24 - 1.
  uint8_t type;        ///< A GHTTP_H2FrameType, or an extension's.
  uint8_t flags;
  uint32_t stream_id;  ///< 31 bits; the reserved bit is dropped.
} GHTTP_H2FrameHeader;

/** Decode nine octets. Never fails: every bit pattern is a header. */
GHTTP_API void ghttp_h2_frame_header_parse(
    const uint8_t bytes[GHTTP_H2_FRAME_HEADER_SIZE], GHTTP_H2FrameHeader * out);

/** Encode a header into nine octets; the reserved bit is zero. */
GHTTP_API void ghttp_h2_frame_header_write(const GHTTP_H2FrameHeader * header,
    uint8_t out[GHTTP_H2_FRAME_HEADER_SIZE]);

/** What to do about a frame that is wrong. */
typedef struct GHTTP_H2FrameError {
  uint32_t code;       ///< A GHTTP_H2ErrorCode.
  int connection;      ///< Non-zero: a connection error. Zero: a stream error.
  uint32_t stream_id;  ///< The stream, for a stream error.
} GHTTP_H2FrameError;

/** Stream priority fields, parsed and not acted on (section 5.3.2). */
typedef struct GHTTP_H2Priority {
  uint32_t dependency;
  int exclusive;
  uint8_t weight;  ///< The wire value; the weight is this plus one.
} GHTTP_H2Priority;

/**
 * A frame's payload, decoded. Which members mean something depends on
 * @c header.type; the others are zero. Pointers refer to the bytes passed to
 * ghttp_h2_frame_parse().
 */
typedef struct GHTTP_H2Frame {
  GHTTP_H2FrameHeader header;
  /** DATA: the data. HEADERS, PUSH_PROMISE, CONTINUATION: the block fragment.
   *  GOAWAY: the debug data. Unknown type: the whole payload. Padding is
   *  never included. */
  const uint8_t * data;
  size_t data_len;
  uint32_t padding;       ///< Padding octets, with the Pad Length field: DATA, HEADERS, PUSH_PROMISE.
  int end_stream;         ///< DATA, HEADERS.
  int end_headers;        ///< HEADERS, PUSH_PROMISE, CONTINUATION.
  int ack;                ///< SETTINGS, PING.
  int has_priority;       ///< HEADERS with the PRIORITY flag; PRIORITY.
  GHTTP_H2Priority priority;
  uint32_t promised_stream_id;  ///< PUSH_PROMISE.
  uint32_t error_code;    ///< RST_STREAM, GOAWAY.
  uint32_t last_stream_id;      ///< GOAWAY.
  uint32_t increment;     ///< WINDOW_UPDATE.
  const uint8_t * settings;     ///< SETTINGS: header.length / 6 six-octet entries.
  size_t settings_count;
  uint8_t ping[8];        ///< PING.
  int known;              ///< Zero for a type this document does not define.
} GHTTP_H2Frame;

/**
 * Decode the payload that follows @p header.
 *
 * Checks what a frame alone can show (RFC 9113 sections 4.2 and 6): the length
 * against @p max_frame_size and against the type's own size, the stream
 * identifier (zero or not) the type requires, padding that fits, ACK frames
 * that carry nothing. An unknown type is accepted whole, as section 5.5
 * requires, and unknown flags are ignored. A zero WINDOW_UPDATE increment is
 * reported here too, as the stream or connection error it is.
 *
 * @param payload header->length octets.
 * @return GHTTP_OK, or GHTTP_ERR_CORRUPT with @p err filled in.
 */
GHTTP_API GHTTP_Result ghttp_h2_frame_parse(const GHTTP_H2FrameHeader * header,
    const uint8_t * payload, size_t max_frame_size, GHTTP_H2Frame * out,
    GHTTP_H2FrameError * err);

/**
 * What the header alone shows to be wrong: a length over @p max_frame_size, or
 * under what the type needs, or a stream identifier the type forbids. The
 * connection uses this to refuse a frame before buffering its payload.
 */
GHTTP_API GHTTP_Result ghttp_h2_frame_header_check(
    const GHTTP_H2FrameHeader * header, size_t max_frame_size,
    GHTTP_H2FrameError * err);

/** Entry @p index of a SETTINGS frame. */
GHTTP_API GHTTP_Result ghttp_h2_frame_setting_at(const GHTTP_H2Frame * frame,
    size_t index, uint16_t * id, uint32_t * value);

// ---------------------------------------------------------------------------
// Writers. @p max_frame_size is the receiver's, from its SETTINGS.
// ---------------------------------------------------------------------------

/** One DATA frame; @p pad_len zero octets of padding follow (0 for none, and a
 *  Pad Length field is written only if padded is non-zero). */
GHTTP_API GHTTP_Result ghttp_h2_write_data(GHTTP_Buffer * out,
    uint32_t stream_id, const void * data, size_t len, int end_stream,
    int padded, uint8_t pad_len);

/**
 * A header block as a HEADERS frame and as many CONTINUATION frames as the
 * block needs at @p max_frame_size (section 6.2, 6.10). END_STREAM goes on the
 * HEADERS frame; END_HEADERS on the last frame.
 */
GHTTP_API GHTTP_Result ghttp_h2_write_header_block(GHTTP_Buffer * out,
    uint32_t stream_id, const void * block, size_t len, int end_stream,
    size_t max_frame_size);

GHTTP_API GHTTP_Result ghttp_h2_write_priority(GHTTP_Buffer * out,
    uint32_t stream_id, const GHTTP_H2Priority * priority);

GHTTP_API GHTTP_Result ghttp_h2_write_rst_stream(
    GHTTP_Buffer * out, uint32_t stream_id, uint32_t error_code);

/** A SETTINGS frame of @p count (id, value) pairs, or an ACK (count 0). */
GHTTP_API GHTTP_Result ghttp_h2_write_settings(GHTTP_Buffer * out,
    const uint16_t * ids, const uint32_t * values, size_t count, int ack);

GHTTP_API GHTTP_Result ghttp_h2_write_ping(
    GHTTP_Buffer * out, const uint8_t data[8], int ack);

GHTTP_API GHTTP_Result ghttp_h2_write_goaway(GHTTP_Buffer * out,
    uint32_t last_stream_id, uint32_t error_code, const void * debug,
    size_t debug_len);

/** Increment 1 to 2^31 - 1; stream 0 is the connection. */
GHTTP_API GHTTP_Result ghttp_h2_write_window_update(
    GHTTP_Buffer * out, uint32_t stream_id, uint32_t increment);

/** A frame of any type, for extensions. The payload is written as given. */
GHTTP_API GHTTP_Result ghttp_h2_write_frame(GHTTP_Buffer * out, uint8_t type,
    uint8_t flags, uint32_t stream_id, const void * payload, size_t len);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GHTTP_H2FRAME_H

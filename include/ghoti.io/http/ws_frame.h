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
 * @file ws_frame.h
 *
 * WebSocket frames: RFC 6455 sections 5.1 to 5.5 and 7.4, and the UTF-8
 * validation of section 8.1.
 *
 * The frame layer is stateless. It reads and writes one frame header, applies
 * the masking key, validates UTF-8 a piece at a time and says which close
 * codes may appear on the wire. What a frame means for a message, and for the
 * connection, is the business of ws_conn.h.
 *
 * A header is validated against itself alone: the opcode must be defined,
 * a control frame must be final and carry at most 125 octets, the length must
 * use the shortest of its three encodings and its top bit must be clear.
 * Whether a reserved bit is allowed, and whether the frame must be masked,
 * depend on the connection and are decided there.
 */

#ifndef GHOTI_IO_GHTTP_WS_FRAME_H
#define GHOTI_IO_GHTTP_WS_FRAME_H

#include <ghoti.io/http/core.h>
#include <ghoti.io/http/macros.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The opcodes of RFC 6455 section 5.2 that are defined. */
typedef enum GHTTP_WsOpcode {
  GHTTP_WS_OP_CONTINUATION = 0x0,
  GHTTP_WS_OP_TEXT = 0x1,
  GHTTP_WS_OP_BINARY = 0x2,
  GHTTP_WS_OP_CLOSE = 0x8,
  GHTTP_WS_OP_PING = 0x9,
  GHTTP_WS_OP_PONG = 0xA
} GHTTP_WsOpcode;

/** The longest frame header: two octets, an 8-octet length and a masking key. */
#define GHTTP_WS_MAX_HEADER_LEN 14u
/** The most payload a control frame may carry (section 5.5). */
#define GHTTP_WS_MAX_CONTROL_PAYLOAD 125u

/** A decoded frame header. */
typedef struct GHTTP_WsFrameHeader {
  size_t size;         ///< sizeof(GHTTP_WsFrameHeader); set by the caller when writing, by the parser when reading.
  int fin;             ///< The FIN bit.
  int rsv1;            ///< RSV1 (permessage-deflate's "compressed" bit).
  int rsv2;            ///< RSV2.
  int rsv3;            ///< RSV3.
  uint8_t opcode;      ///< A ::GHTTP_WsOpcode.
  int masked;          ///< The MASK bit.
  uint8_t mask_key[4]; ///< The masking key; meaningful when @c masked.
  uint64_t payload_len;///< Octets of payload.
  size_t header_len;   ///< Octets the header occupies on the wire; set by the parser and the writer.
  uint64_t reserved[2];
} GHTTP_WsFrameHeader;

/** Whether @p opcode is a control opcode (high bit of the nibble set). */
GHTTP_API int ghttp_ws_opcode_is_control(uint8_t opcode);

/**
 * Whether @p opcode is one RFC 6455 defines: 0, 1, 2, 8, 9 and 10. 3 to 7 and
 * 11 to 15 are reserved and a receiver fails the connection on them.
 */
GHTTP_API int ghttp_ws_opcode_is_defined(uint8_t opcode);

/**
 * Read a frame header from the start of @p data.
 *
 * @param data The bytes.
 * @param len How many.
 * @param[out] out Receives the header when one was read.
 * @param[out] used Octets the header occupies; 0 when @p len is too short to
 *   tell, in which case nothing else is written and the caller supplies more.
 * @return GHTTP_OK (a header, or not yet enough input: see @p used);
 *   GHTTP_ERR_CORRUPT for an undefined opcode, a fragmented or oversized
 *   control frame, a length not in its shortest encoding or with the top bit
 *   set; GHTTP_ERR_INVALID for a NULL argument. The decision is made on the
 *   fewest octets that make it, never on how many were offered.
 */
GHTTP_API GHTTP_Result ghttp_ws_frame_header_parse(const void * data,
    size_t len, GHTTP_WsFrameHeader * out, size_t * used);

/**
 * Write a frame header.
 *
 * @param header The header; @c header_len is ignored. The mask key is written
 *   only if @c masked.
 * @param[out] out At least ::GHTTP_WS_MAX_HEADER_LEN octets.
 * @param[out] written How many octets were written.
 * @return GHTTP_OK; GHTTP_ERR_INVALID for what the parser would refuse
 *   (undefined opcode, a control frame that is fragmented or longer than 125,
 *   a length of 2^63 or more) or a NULL argument.
 */
GHTTP_API GHTTP_Result ghttp_ws_frame_header_write(
    const GHTTP_WsFrameHeader * header, uint8_t * out, size_t * written);

/**
 * Apply a masking key (RFC 6455 section 5.3) in place. Masking is its own
 * inverse.
 *
 * @param data The payload bytes.
 * @param len How many.
 * @param key The four-octet key.
 * @param offset The position of data[0] within the frame's payload, so that a
 *   payload masked a piece at a time gives the whole payload's result.
 */
GHTTP_API void ghttp_ws_mask(
    void * data, size_t len, const uint8_t key[4], uint64_t offset);

/** An incremental UTF-8 validator (RFC 3629): no overlong forms, no surrogates, nothing above U+10FFFF. */
typedef struct GHTTP_WsUtf8 {
  uint8_t need; ///< Continuation octets still owed.
  uint8_t lo;   ///< The lowest value the next octet may have.
  uint8_t hi;   ///< The highest.
} GHTTP_WsUtf8;

/** Start validating a new text. */
GHTTP_API void ghttp_ws_utf8_init(GHTTP_WsUtf8 * v);

/**
 * Validate the next piece. The text may be cut anywhere, including inside a
 * code point.
 *
 * @return GHTTP_OK, or GHTTP_ERR_CORRUPT at the first invalid octet; the
 *   validator is then unusable until ghttp_ws_utf8_init().
 */
GHTTP_API GHTTP_Result ghttp_ws_utf8_feed(
    GHTTP_WsUtf8 * v, const void * data, size_t len);

/** Whether the text so far ends on a code point boundary, i.e. may end here. */
GHTTP_API int ghttp_ws_utf8_complete(const GHTTP_WsUtf8 * v);

/**
 * Whether @p code may appear in a Close frame (section 7.4): 1000 to 1003,
 * 1007 to 1014 and 3000 to 4999. The values 1004, 1005, 1006 and 1015 are
 * reserved for use by a local application and never sent; 0 to 999 are
 * unused and 1016 to 2999 are reserved for later definition.
 */
GHTTP_API int ghttp_ws_close_code_is_valid(uint16_t code);

/** The close code values of RFC 6455 section 7.4.1 that this codec itself sends or reports. */
enum {
  GHTTP_WS_CLOSE_NORMAL = 1000,
  GHTTP_WS_CLOSE_GOING_AWAY = 1001,
  GHTTP_WS_CLOSE_PROTOCOL_ERROR = 1002,
  GHTTP_WS_CLOSE_UNSUPPORTED_DATA = 1003,
  GHTTP_WS_CLOSE_NO_STATUS = 1005,
  GHTTP_WS_CLOSE_ABNORMAL = 1006,
  GHTTP_WS_CLOSE_INVALID_PAYLOAD = 1007,
  GHTTP_WS_CLOSE_POLICY_VIOLATION = 1008,
  GHTTP_WS_CLOSE_MESSAGE_TOO_BIG = 1009,
  GHTTP_WS_CLOSE_MANDATORY_EXTENSION = 1010,
  GHTTP_WS_CLOSE_INTERNAL_ERROR = 1011
};

/**
 * Every unbounded quantity of the handshake and the connection, each a hard
 * cap. Initialise with ghttp_ws_limits_default().
 *
 * The control-frame count works as in h2conn.h: the interval is @c interval_ms
 * of the clock the caller supplies with ghttp_ws_conn_tick(). **A connection
 * that is never ticked has no interval: its control-frame cap is a total for the
 * connection's whole life** (and it dies of it, with 1008, after that many
 * Pings, Pongs and Closes): safe, because nothing is left unbounded, and wrong
 * for a long-lived connection, which must tick.
 *
 * A limit is a hard cap: every field must be non-zero, except
 * @c max_expansion_ratio where 0 means no ratio limit, and
 * @c max_frame_payload may not exceed @c max_message_bytes; the creating
 * functions return GHTTP_ERR_INVALID otherwise.
 */
typedef struct GHTTP_WsLimits {
  size_t size;  ///< sizeof(GHTTP_WsLimits); set by _default().
  /**
   * The payload of one frame as it arrives (compressed, if it is; a compressed
   * frame may be up to 1/64 of this and 16 octets larger, the overhead of the
   * extension, before it is refused). A frame over it is refused at its header.
   */
  uint64_t max_frame_payload;
  /**
   * One message after decompression, exact: no octet past it is delivered or
   * held beyond the one that shows the limit was passed. What arrives
   * compressed is bounded separately, by this plus 1/64 of it and 16 octets (an
   * incompressible message of the full size is a little larger compressed), so
   * "closes before the limit is exceeded by more than one unit" is exact for an
   * uncompressed message and the inflated size, and is that much looser for the
   * compressed octets.
   */
  uint64_t max_message_bytes;
  /** Frames in one message, the first included. */
  uint32_t max_fragments;
  /** Control frames (Ping, Pong, Close) received per interval. */
  uint32_t max_control_per_interval;
  /** Length of an interval, in milliseconds. */
  uint32_t interval_ms;
  /**
   * Octets of output queued and not yet taken (replies to Ping, Close, what
   * the caller sends). A peer that provokes replies faster than they are
   * written ends the connection with 1008.
   */
  size_t max_buffered_bytes;
  /** The handshake's header fields: names and values of the whole request or response. */
  size_t max_handshake_bytes;
  /** Extension offers in a handshake (at most 32 are ever read). */
  uint32_t max_extension_offers;
  /** Parameters of one extension offer (at most 16 are ever read). */
  uint32_t max_extension_params;
  /**
   * Output octets per input octet of a permessage-deflate message. 1032 is
   * the format's own ceiling (a 258-octet match in two bits), so no valid
   * stream is refused at the default; lower it to refuse a bomb sooner. 0 is no
   * ratio limit (the message limit still applies). The count has a slack of 256
   * octets, so that a message of a few octets may still be a sentence.
   */
  uint64_t max_expansion_ratio;
  uint64_t reserved[4];
} GHTTP_WsLimits;

#define GHTTP_WS_DEFAULT_MAX_FRAME_PAYLOAD ((uint64_t)16 << 20)  ///< The default, 16 MiB.
#define GHTTP_WS_DEFAULT_MAX_MESSAGE_BYTES ((uint64_t)16 << 20)  ///< The default, 16 MiB.
#define GHTTP_WS_DEFAULT_MAX_FRAGMENTS 1024u  ///< The default, 1024.
#define GHTTP_WS_DEFAULT_MAX_CONTROL_PER_INTERVAL 128u  ///< The default, 128.
#define GHTTP_WS_DEFAULT_INTERVAL_MS 10000u  ///< The default, 10 seconds.
#define GHTTP_WS_DEFAULT_MAX_BUFFERED_BYTES ((size_t)1 << 20)  ///< The default, 1 MiB.
#define GHTTP_WS_DEFAULT_MAX_HANDSHAKE_BYTES 8192u  ///< The default, 8 KiB.
#define GHTTP_WS_DEFAULT_MAX_EXTENSION_OFFERS 8u  ///< The default, 8.
#define GHTTP_WS_DEFAULT_MAX_EXTENSION_PARAMS 8u  ///< The default, 8.
#define GHTTP_WS_DEFAULT_MAX_EXPANSION_RATIO 1032u  ///< The default, 1032.

/** The defaults above. */
GHTTP_API void ghttp_ws_limits_default(GHTTP_WsLimits * limits);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GHTTP_WS_FRAME_H

/*
 * Copyright (c) 2025 Maxence Younsi <maxence.younsi@insa-lyon.fr> and Pierre Weisse <pierre.weisse@insa-lyon.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _PACKET_PROCESSOR_H_
#define _PACKET_PROCESSOR_H_

#include "pmacct.h"
#include "bgp/bgp.h"
#include "bmp/bmp.h"
#include <time.h>

typedef int (* bgp_parse_msg_f) (struct bgp_peer *peer, time_t time, int online);
typedef u_int32_t (* bmp_process_packet_f) (char * buf, u_int32_t buf_len, struct bmp_peer *peer, int *term);
typedef int (* bmp_peer_init_f) (struct bmp_peer *peer, int func_type);
typedef void (* bmp_peer_close_f) (struct bmp_peer *peer, int func_type);

/// Packet processor, set of functions called to parse a received bmp/bgp buffer
typedef struct packet_processor {
    bgp_parse_msg_f bgp_parse_msg;
    bmp_process_packet_f bmp_process_packet;
    bmp_peer_init_f bmp_peer_init;
    bmp_peer_close_f bmp_peer_close;
} packet_processor_t;

/// The in-use packet processor. Should not change after config has been loaded.
/// Defaults to pmacct callbacks
extern packet_processor_t pprocessor;

/// Use dynlib to load the parsing library located at "lib_path"
/// "lib_path" can be libname.so, or a relative/absolute path (see man @dlopen)
extern enum dynlib_result packet_processor_dynload(const char* lib_path);

#endif
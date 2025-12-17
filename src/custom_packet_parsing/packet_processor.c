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

#include "packet_processor.h"
#include "dynamic_loading.h"

packet_processor active_packet_processor = DEFAULT_PACKET_PROCESSOR;

enum dynlib_result load_parsing_lib(const char* lib_path) {
  packet_processor processor = {0};
  const enum dynlib_result result = dynlib_load_and_resolve((struct dynlib){
      .path = lib_path,
      .table = (dynlib_table){
        {"bgp_parse_msg", (void**) &processor.bgp_parse_msg},
        {"bmp_process_packet", (void**) &processor.bmp_process_packet},
        {"bmp_peer_init", (void**) &processor.bmp_peer_init},
        {"bmp_peer_close", (void**) &processor.bmp_peer_close},
        {NULL,NULL}
      },
    }
  );

  // On dynlib success, actually set active packet processor to the loaded library
  if (result == DL_Success) {
    active_packet_processor = processor;
  }

  return result;
}

/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2023 by Paolo Lucente
*/

/*
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
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

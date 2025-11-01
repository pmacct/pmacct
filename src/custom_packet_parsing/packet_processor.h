#ifndef _PACKET_PROCESSOR_H_
#define _PACKET_PROCESSOR_H_

#include "pmacct.h"
#include "bgp/bgp.h"
#include "bmp/bmp.h"
#include <time.h>

/// Packet processor, set of functions called to parse a received bmp/bgp buffer
typedef struct {
    int (* bgp_parse_msg) (struct bgp_peer *peer, time_t time, int online);
    u_int32_t (* bmp_process_packet) (char * buf, u_int32_t buf_len, struct bmp_peer *peer, int *term);
    int (* bmp_peer_init) (struct bmp_peer *peer, int func_type);
    void (* bmp_peer_close) (struct bmp_peer *peer, int func_type);
} packet_processor;

/// The in-use packet processor. Should not change after config has been loaded.
/// Defaults to @DEFAULT_PACKET_PROCESSOR
extern packet_processor active_packet_processor;

const static packet_processor DEFAULT_PACKET_PROCESSOR = {
    bgp_parse_msg,
    bmp_process_packet,
    bmp_peer_init,
    bmp_peer_close
  };

/// Use dynlib to load the parsing library located at "lib_path"
/// "lib_path" can be libname.so, or a relative/absolute path (see man @dlopen)
extern enum dynlib_result load_parsing_lib(const char* lib_path);

#endif
#ifndef _PACKET_PROCESSOR_H_
#define _PACKET_PROCESSOR_H_

#include "pmacct.h"
#include "bgp/bgp_msg.h"
#include "bmp/bmp_msg.h"
#include "bmp/bmp_util.h"



typedef struct {
    int (* bgp_parse_msg) (struct bgp_peer *, time_t, int);
    u_int32_t (* bmp_process_packet) (char *, u_int32_t, struct bmp_peer *, int *);
    int (* bmp_peer_init) (struct bmp_peer *, int);
    void (* bmp_peer_close) (struct bmp_peer *, int);
} packet_processor;


extern packet_processor DEFAULT_PACKET_PROCESSOR;

#endif
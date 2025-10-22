#include "packet_processor.h"

packet_processor DEFAULT_PACKET_PROCESSOR = {
    bgp_parse_msg,
    bmp_process_packet,
    bmp_peer_init,
    bmp_peer_close
};
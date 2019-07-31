#include "pmacct.h"
#include "bgp/bgp.h"
#include "bmp.h"


struct bmp_peer *bmp_peers = NULL;
u_int32_t (*bmp_route_info_modulo)(struct bgp_peer *, path_id_t *, int) = NULL;
struct bgp_rt_structs *bmp_routing_db = NULL;
struct bgp_misc_structs *bmp_misc_db = NULL;

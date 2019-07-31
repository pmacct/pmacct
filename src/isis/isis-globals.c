#include "pmacct.h"
#include "isis.h"

struct thread_master *master = NULL;
struct isis *isis = NULL;
struct in_addr router_id_zebra;
struct timeval isis_now, isis_spf_deadline, isis_psnp_deadline;
struct igp_map_entry ime;
pcap_dumper_t *idmm_fd = NULL;
u_int32_t glob_isis_seq_num = 0; 
struct sysid_fragment sysid_fragment_table[MAX_IGP_MAP_NODES];

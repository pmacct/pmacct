#ifdef WITH_CUSTOM_PRINT_PLUGIN

#include "pmacct.h"

#if (!defined __CUSTOM_PRINT_PLUGIN_C)
#define EXT extern
#else
#define EXT
#endif


struct pkt_primitives;
struct pkt_bgp_primitives;
struct pkt_nat_primitives;
struct pkt_mpls_primitives;
struct pkt_tunnel_primitives;
struct pkt_vlen_hdr_primitives;
struct timeval;
struct config;

struct custom_print_plugin_{
	void *lib_handle;

	int (*plugin_init)(const char *);
	int (*plugin_destroy)();
	int (*open_file)(const char *,int);
	int (*print)(u_int64_t,
				 u_int64_t,
				 u_int8_t,
				 struct pkt_primitives *,
				 struct pkt_bgp_primitives *,
				 struct pkt_nat_primitives *,
				 struct pkt_mpls_primitives *,
				 struct pkt_tunnel_primitives *,
				 char *,
				 struct pkt_vlen_hdr_primitives *,
				 pm_counter_t,
				 pm_counter_t,
				 pm_counter_t,
				 u_int32_t,
				 struct timeval *,
				 struct pkt_stitching *);
	int (*flush_file)();
	int (*close_file)();
	char* (*get_error_text)();
};

EXT struct custom_print_plugin_ custom_print_plugin;
#endif

#undef EXT

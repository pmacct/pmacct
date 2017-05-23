/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2017 by Paolo Lucente
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

/*
    Originally based on:
    ndpi_util.h | nDPI | Copyright (C) 2011-17 - ntop.org
*/

/*
#define NDPI_MAX_NUM_READER_THREADS	16
#define NDPI_IDLE_SCAN_PERIOD		10
#define NDPI_MAX_IDLE_TIME		30000
#define NDPI_IDLE_SCAN_BUDGET		1024
*/
#define NDPI_NUM_ROOTS			512
#define NDPI_MAXFLOWS			200000000
#define NDPI_TICK_RESOLUTION		1000

/* flow tracking */
typedef struct ndpi_flow_info {
  u_int32_t lower_ip;
  u_int32_t upper_ip;
  u_int16_t lower_port;
  u_int16_t upper_port;
  u_int8_t detection_completed, protocol, src_to_dst_direction;
  u_int16_t vlan_id;
  struct ndpi_flow_struct *ndpi_flow;
  char lower_name[48], upper_name[48];
  u_int8_t ip_version;
  u_int64_t last_seen;
  u_int64_t bytes;
  u_int32_t packets;

  // result only, not used for flow identification
  ndpi_protocol detected_protocol;

  char info[96];
  char host_server_name[192];
  char bittorent_hash[41];

  struct {
    char client_info[48], server_info[48];
  } ssh_ssl;

  void *src_id, *dst_id;
} ndpi_flow_info_t;

/* flow statistics info */
typedef struct ndpi_stats {
  u_int32_t guessed_flow_protocols;
  u_int64_t raw_packet_count;
  u_int64_t ip_packet_count;
  u_int64_t total_wire_bytes, total_ip_bytes, total_discarded_bytes;
  u_int64_t protocol_counter[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
  u_int64_t protocol_counter_bytes[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
  u_int32_t protocol_flows[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
  u_int32_t ndpi_flow_count;
  u_int64_t tcp_count, udp_count;
  u_int64_t mpls_count, pppoe_count, vlan_count, fragmented_count;
  u_int64_t packet_len[6];
  u_int16_t max_packet_len;
} ndpi_stats_t;

/* flow preferences */
typedef struct ndpi_workflow_prefs {
  u_int8_t decode_tunnels;
  u_int8_t quiet_mode;
  u_int32_t num_roots;
  u_int32_t max_ndpi_flows;
} ndpi_workflow_prefs_t;

struct ndpi_workflow;

/* workflow, flow, user data */
typedef void (*ndpi_workflow_callback_ptr) (struct ndpi_workflow *, struct ndpi_flow_info *, void *);

/* workflow main structure */
typedef struct ndpi_workflow {
  u_int64_t last_time;

  struct ndpi_workflow_prefs prefs;
  struct ndpi_stats stats;

  ndpi_workflow_callback_ptr __flow_detected_callback;
  void * __flow_detected_udata;
  ndpi_workflow_callback_ptr __flow_giveup_callback;
  void * __flow_giveup_udata;

  /* allocated by prefs */
  void **ndpi_flows_root;
  struct ndpi_detection_module_struct *ndpi_struct;
} ndpi_workflow_t;

/* Any unsigned integer type with at least 32 bits may be used as
 * accumulator type for fast crc32-calulation, but unsigned long is
 * probably the optimal choice for most systems. */
typedef unsigned long ndpi_accum_t;

#if (!defined __NDPI_UTIL_C)
#define EXT extern
#else
#define EXT
#endif
/* global vars */
EXT u_int32_t ndpi_current_memory, ndpi_max_memory;
EXT NDPI_PROTOCOL_BITMASK ndpi_all;
EXT struct ndpi_workflow *ndpi_wfl;
EXT struct ndpi_workflow_prefs ndpi_wfl_prefs;

/* prototypes */
/* XXX: remove wrappers parameters and use ndpi global, when their initialization will be fixed... */
EXT struct ndpi_workflow * ndpi_workflow_init(const struct ndpi_workflow_prefs *);

/* workflow main free function */
EXT void ndpi_workflow_free(struct ndpi_workflow *);

/* Free flow_info ndpi support structures but not the flow_info itself
 *
 * XXX: remove! Half freeing things is bad!
 */
EXT void ndpi_free_flow_info_half(struct ndpi_flow_info *);

/* Process a packet and update the workflow  */
EXT struct ndpi_proto ndpi_workflow_process_packet (struct ndpi_workflow *, struct packet_ptrs *);

/* compare two nodes in workflow */
EXT int ndpi_workflow_node_cmp(const void *, const void *);
EXT void process_ndpi_collected_info(struct ndpi_workflow *, struct ndpi_flow_info *);
#undef EXT

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

#define NDPI_IDLE_SCAN_PERIOD		10
#define NDPI_IDLE_MAX_TIME		600
#define NDPI_IDLE_SCAN_BUDGET		1024
#define NDPI_NUM_ROOTS			512
#define NDPI_MAXFLOWS			200000000
#define NDPI_TICK_RESOLUTION		1000
#define NDPI_GIVEUP_PROTO_TCP		10
#define NDPI_GIVEUP_PROTO_UDP		8
#define NDPI_GIVEUP_PROTO_OTHER		8	

/* flow tracking */
typedef struct ndpi_flow_info {
  u_int32_t lower_ip;
  u_int32_t upper_ip;
  u_int16_t lower_port;
  u_int16_t upper_port;
  u_int8_t detection_completed;
  u_int8_t guess_completed;
  u_int8_t tcp_finished;
  u_int8_t protocol;
  u_int8_t src_to_dst_direction;
  u_int16_t vlan_id;
  struct ndpi_flow_struct *ndpi_flow;
  u_int8_t ip_version;
  u_int64_t last_seen;
  u_int64_t bytes;
  u_int32_t packets;

  /* result only, not used for flow identification */
  ndpi_protocol detected_protocol;

  void *src_id;
  void *dst_id;
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
  u_int8_t protocol_guess;
  u_int32_t num_roots;
  u_int32_t max_ndpi_flows;
  u_int32_t idle_scan_period;
  u_int32_t idle_max_time;
  u_int32_t idle_scan_budget; 
  u_int8_t giveup_proto_tcp;
  u_int8_t giveup_proto_udp;
  u_int8_t giveup_proto_other;
} ndpi_workflow_prefs_t;

struct ndpi_workflow;

/* workflow main structure */
typedef struct ndpi_workflow {
  u_int64_t last_time;

  u_int64_t last_idle_scan_time;
  u_int32_t num_idle_flows;
  u_int32_t idle_scan_idx;
  struct ndpi_flow_info *idle_flows[NDPI_IDLE_SCAN_BUDGET];

  struct ndpi_workflow_prefs prefs;
  struct ndpi_stats stats;

  /* allocated by prefs */
  void **ndpi_flows_root;
  struct ndpi_detection_module_struct *ndpi_struct;
} ndpi_workflow_t;

#if (!defined __NDPI_UTIL_C)
#define EXT extern
#else
#define EXT
#endif
/* global vars */
EXT struct ndpi_workflow *ndpi_wfl;

/* prototypes */
EXT struct ndpi_workflow * ndpi_workflow_init();

/* Free flow_info ndpi support structures but not the flow_info itself */
EXT void ndpi_free_flow_info_half(struct ndpi_flow_info *);

/* Process a packet and update the workflow  */
EXT struct ndpi_proto ndpi_workflow_process_packet(struct ndpi_workflow *, struct packet_ptrs *);

/* compare two nodes in workflow */
EXT int ndpi_workflow_node_cmp(const void *, const void *);

EXT struct ndpi_flow_info *ndpi_get_flow_info(struct ndpi_workflow *, struct packet_ptrs *, u_int16_t, const struct ndpi_iphdr *,
						const struct ndpi_ipv6hdr *, u_int16_t, u_int16_t, u_int16_t, struct ndpi_tcphdr **,
						struct ndpi_udphdr **, u_int16_t *, u_int16_t *, struct ndpi_id_struct **,
						struct ndpi_id_struct **, u_int8_t *, u_int8_t **, u_int16_t *, u_int8_t *);
EXT struct ndpi_flow_info *ndpi_get_flow_info6(struct ndpi_workflow *, struct packet_ptrs *, u_int16_t, const struct ndpi_ipv6hdr *,
						u_int16_t, struct ndpi_tcphdr **, struct ndpi_udphdr **, u_int16_t *, u_int16_t *,
						struct ndpi_id_struct **, struct ndpi_id_struct **, u_int8_t *, u_int8_t **,
						u_int16_t *, u_int8_t *);
EXT struct ndpi_proto ndpi_packet_processing(struct ndpi_workflow *, struct packet_ptrs *, const u_int64_t, u_int16_t,
						const struct ndpi_iphdr *, struct ndpi_ipv6hdr *, u_int16_t, u_int16_t, u_int16_t); 

EXT u_int16_t ndpi_node_guess_undetected_protocol(struct ndpi_workflow *, struct ndpi_flow_info *);
EXT void ndpi_idle_flows_cleanup(struct ndpi_workflow *);

EXT int ndpi_node_idle_scan_walker(const void *, const pm_VISIT, const int, void *);
#undef EXT

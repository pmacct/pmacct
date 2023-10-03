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

#ifndef PLUGIN_CMN_AVRO_H
#define PLUGIN_CMN_AVRO_H

/* includes */
#ifdef WITH_SERDES
#include <libserdes/serdes-avro.h>
#endif

/* defines */
#ifdef WITH_AVRO
/* libavro-c bails out with generic error messages on typical cases
   where schema and actual data encoding are not matching. This small
   wrapper aims to identify what line in the code does specifically
   cause the issue */
#define pm_avro_check(call) \
  do { \
    if ((call) != 0) { \
      Log(LOG_ERR, "ERROR: %s\n", avro_strerror()); \
      assert(1 == 0); \
    } \
} while (0)

#define	AVRO_ACCT_DATA_SID	0
#define	AVRO_ACCT_INIT_SID	1
#define	AVRO_ACCT_CLOSE_SID	2

/* prototypes */
extern void compose_label_avro_schema_opt(avro_schema_t);
extern void compose_label_avro_schema_nonopt(avro_schema_t);
extern void compose_tcpflags_avro_schema(avro_schema_t);
extern void compose_tunnel_tcpflags_avro_schema(avro_schema_t);
extern void compose_fwd_status_avro_schema(avro_schema_t);
extern void compose_mpls_label_stack_schema(avro_schema_t);
extern void compose_srv6_segment_ipv6_list_schema(avro_schema_t);
extern void compose_str_linked_list_to_avro_array_schema(avro_schema_t, const char *);
extern int compose_label_avro_data_opt(char *, avro_value_t);
extern int compose_label_avro_data_nonopt(char *, avro_value_t);
extern int compose_tcpflags_avro_data(size_t, avro_value_t);
extern int compose_tunnel_tcpflags_avro_data(size_t, avro_value_t);
extern int compose_mpls_label_stack_data(u_int32_t *, int, avro_value_t);
extern int compose_srv6_segment_ipv6_list_data(struct host_addr *, int, avro_value_t);
extern int compose_fwd_status_avro_data(size_t, avro_value_t);
extern int compose_str_linked_list_to_avro_array_data(const char *, const char *, avro_value_t);

extern void pm_avro_exit_gracefully(int);

extern avro_schema_t p_avro_schema_build_acct_data(u_int64_t, u_int64_t, u_int64_t);
extern avro_schema_t p_avro_schema_build_acct_init();
extern avro_schema_t p_avro_schema_build_acct_close();
extern void p_avro_schema_add_writer_id(avro_schema_t);
extern void add_writer_name_and_pid_avro(avro_value_t, char *, pid_t);
extern void add_writer_name_and_pid_avro_v2(avro_value_t, struct dynname_tokens *);

extern avro_value_t compose_avro_acct_data(u_int64_t, u_int64_t, u_int64_t, u_int8_t,
  struct pkt_primitives *, struct pkt_bgp_primitives *,
  struct pkt_nat_primitives *, struct pkt_mpls_primitives *,
  struct pkt_tunnel_primitives *, u_char *,
  struct pkt_vlen_hdr_primitives *, pm_counter_t,
  pm_counter_t, pm_counter_t, u_int8_t, u_int8_t,
  struct timeval *, struct pkt_stitching *, avro_value_iface_t *);
extern avro_value_t compose_avro_acct_init(char *, pid_t, avro_value_iface_t *);
extern avro_value_t compose_avro_acct_close(char *, pid_t, int, int, int, avro_value_iface_t *);
extern void write_avro_schema_to_file(char *, avro_schema_t);
extern void write_avro_schema_to_file_with_suffix(char *, char *, char *, avro_schema_t);
extern char *write_avro_schema_to_memory(avro_schema_t);
extern char *compose_avro_purge_schema(avro_schema_t, char *);
extern char *compose_avro_schema_name(char *, char *);
extern void write_avro_json_record_to_file(FILE *, avro_value_t);
extern char *write_avro_json_record_to_buf(avro_value_t);

#ifdef WITH_SERDES
extern void p_avro_serdes_logger(serdes_t *, int, const char *, const char *, void *);
extern serdes_schema_t *compose_avro_schema_registry_name(char *, int, avro_schema_t, char *, char *, char *);
extern serdes_schema_t *compose_avro_schema_registry_name_2(char *, int, avro_schema_t, char *, char *, char *);
#endif

/* global variables */
extern avro_schema_t p_avro_acct_schema, p_avro_acct_init_schema, p_avro_acct_close_schema;
typedef void (*compose_bgp_comm_to_avro_array_schema_type)(avro_schema_t, const char *);
typedef int (*compose_bgp_comm_to_avro_array_data_type)(const char *, const char *, avro_value_t);
typedef void (*compose_as_path_to_avro_array_schema_type)(avro_schema_t, const char *);
typedef int (*compose_as_path_to_avro_array_data_type)(const char *, const char *, avro_value_t);
extern compose_bgp_comm_to_avro_array_schema_type compose_bgp_comm_to_avro_array_schema;
extern compose_bgp_comm_to_avro_array_data_type compose_bgp_comm_to_avro_array_data;
extern compose_as_path_to_avro_array_schema_type compose_as_path_to_avro_array_schema;
extern compose_as_path_to_avro_array_data_type compose_as_path_to_avro_array_data;
#endif

#endif //PLUGIN_CMN_AVRO_H

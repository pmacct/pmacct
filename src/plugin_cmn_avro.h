/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2020 by Paolo Lucente
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
extern void pm_avro_exit_gracefully(int);

extern avro_schema_t p_avro_schema_build_acct_data(u_int64_t wtc, u_int64_t wtc_2);
extern avro_schema_t p_avro_schema_build_acct_init();
extern avro_schema_t p_avro_schema_build_acct_close();
extern void p_avro_schema_add_writer_id(avro_schema_t);
extern void add_writer_name_and_pid_avro(avro_value_t, char *, pid_t);

extern avro_value_t compose_avro_acct_data(u_int64_t wtc, u_int64_t wtc_2, u_int8_t flow_type,
  struct pkt_primitives *pbase, struct pkt_bgp_primitives *pbgp,
  struct pkt_nat_primitives *pnat, struct pkt_mpls_primitives *pmpls,
  struct pkt_tunnel_primitives *ptun, u_char *pcust,
  struct pkt_vlen_hdr_primitives *pvlen, pm_counter_t bytes_counter,
  pm_counter_t packet_counter, pm_counter_t flow_counter, u_int32_t tcp_flags,
  struct timeval *basetime, struct pkt_stitching *stitch,
  avro_value_iface_t *iface);
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
#endif

#endif //PLUGIN_CMN_AVRO_H

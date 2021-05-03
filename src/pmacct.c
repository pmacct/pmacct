/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2021 by Paolo Lucente
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

#include <time.h>

/* include */
#include "pmacct.h"
#include "pmacct-data.h"
#include "addr.h"
#include "imt_plugin.h"
#include "bgp/bgp_packet.h"
#include "bgp/bgp.h"
#include "rpki/rpki.h"

//Freaking mess with  _XOPEN_SOURCE and non-std int types, so fwd decl
extern char *strptime(const char *s, const char *format, struct tm *tm);

/* prototypes */
int Recv(int, unsigned char **);
void print_ex_options_error();
void write_status_header_formatted();
void write_status_header_csv();
void write_class_table_header();
char *write_sep(char *, int *);
int CHECK_Q_TYPE(int);
int check_data_sizes(struct query_header *, struct pkt_data *);
void client_counters_merge_sort(void *, int, int, int, int);
void client_counters_merge(void *, int, int, int, int, int);
int pmc_sanitize_buf(char *);
void pmc_trim_all_spaces(char *);
char *pmc_extract_token(char **, int);
u_int16_t pmc_bgp_rd_type_get(u_int16_t);
int pmc_bgp_rd2str(char *, rd_t *);
int pmc_bgp_str2rd(rd_t *, char *);
char *pmc_compose_json(u_int64_t, u_int64_t, u_int8_t, struct pkt_primitives *,
			struct pkt_bgp_primitives *, struct pkt_legacy_bgp_primitives *,
			struct pkt_nat_primitives *, struct pkt_mpls_primitives *,
			struct pkt_tunnel_primitives *, u_char *,
			struct pkt_vlen_hdr_primitives *, pm_counter_t, pm_counter_t,
			pm_counter_t, u_int32_t, struct timeval *, int, int);
void pmc_append_rfc3339_timezone(char *, int, const struct tm *);
void pmc_compose_timestamp(char *, int, struct timeval *, int, int, int);
void pmc_custom_primitive_header_print(char *, int, struct imt_custom_primitive_entry *, int);
void pmc_custom_primitive_value_print(char *, int, u_char *, struct imt_custom_primitive_entry *, int);
void pmc_vlen_prims_get(struct pkt_vlen_hdr_primitives *, pm_cfgreg_t, char **);
void pmc_printf_csv_label(struct pkt_vlen_hdr_primitives *, pm_cfgreg_t, char *, char *);
void pmc_lower_string(char *);
char *pmc_ndpi_get_proto_name(u_int16_t);
const char *pmc_rpki_roa_print(u_int8_t);
u_int8_t pmc_rpki_str2roa(char *);

/* vars */
struct imt_custom_primitives pmc_custom_primitives_registry;
struct stripped_class *class_table = NULL;
int want_ipproto_num, ct_idx, ct_num;

/* functions */
int CHECK_Q_TYPE(int type)
{
  if (!type) return 0;

  if (type & WANT_RESET) type ^= WANT_RESET;
  if (type & WANT_ERASE) type ^= WANT_ERASE;
  if (type & WANT_LOCK_OP) type ^= WANT_LOCK_OP;

  return type;
}

void usage_client(char *prog)
{
  printf("%s %s (%s)\n", PMACCT_USAGE_HEADER, PMACCT_VERSION, PMACCT_BUILD);
  printf("Usage: %s [query]\n\n", prog);
  printf("Queries:\n");
  printf("  -h\tShow this page\n");
  printf("  -s\tShow statistics\n"); 
  printf("  -N\t<matching data>[';'<matching data>] | 'file:'<filename> \n\tMatch primitives; print counters only (requires -c)\n");
  printf("  -M\t<matching data>[';'<matching data>] | 'file:'<filename> \n\tMatch primitives; print formatted table (requires -c)\n");
  printf("  -n\t<bytes | packets | flows | all> \n\tSelect the counters to print (applies to -N)\n");
  printf("  -S\tSum counters instead of returning a single counter for each request (applies to -N)\n");
  printf("  -a\tDisplay all table fields (even those currently unused)\n");
  printf("  -c\t< src_mac | dst_mac | vlan | cos | src_host | dst_host | src_net | dst_net | src_mask | dst_mask | \n\t src_port | dst_port | tos | proto | src_as | dst_as | sum_mac | sum_host | sum_net | sum_as | \n\t sum_port | in_iface | out_iface | tag | tag2 | flows | class | std_comm | ext_comm | lrg_comm | \n\t med | local_pref | as_path | dst_roa | peer_src_ip | peer_dst_ip | peer_src_as | peer_dst_as | \n\t src_as_path | src_std_comm | src_ext_comm | src_lrg_comm | src_med | src_local_pref | src_roa | \n\t mpls_vpn_rd | mpls_pw_id | etype | sampling_rate | sampling_direction | post_nat_src_host | \n\t post_nat_dst_host | post_nat_src_port | post_nat_dst_port | nat_event | tunnel_src_mac | \n\t tunnel_dst_mac | tunnel_src_host | tunnel_dst_host | tunnel_protocol | tunnel_tos | \n\t tunnel_src_port | tunnel_dst_port | vxlan | timestamp_start | timestamp_end | timestamp_arrival | \n\t mpls_label_top | mpls_label_bottom |  mpls_stack_depth | label | src_host_country | \n\t dst_host_country | export_proto_seqno | export_proto_version | export_proto_sysid | \n\t src_host_pocode | dst_host_pocode | src_host_coords | dst_host_coords > \n\tSelect primitives to match (required by -N and -M)\n");
  printf("  -T\t<bytes | packets | flows>,[<# how many>] \n\tOutput top N statistics (applies to -M and -s)\n");
  printf("  -e\tClear statistics\n");
  printf("  -i\tShow time (in seconds) since statistics were last cleared (ie. pmacct -e)\n");
  printf("  -r\tReset counters (applies to -N and -M)\n");
  printf("  -l\tPerform locking of the table\n");
  printf("  -t\tShow memory table status\n");
  printf("  -C\tShow classifiers table\n");
  printf("  -U\tShow custom primitives table\n");
  printf("  -p\t<file> \n\tSocket for client-server communication (DEFAULT: /tmp/collect.pipe)\n");
  printf("  -O\tSet output < formatted | csv | json | event_formatted | event_csv > (applies to -M and -s)\n");
  printf("  -E\tSet sparator for CSV format\n");
  printf("  -I\tSet timestamps in 'since Epoch' format\n");
  printf("  -u\tLeave IP protocols in numerical format\n");
  printf("  -0\tAlways set timestamps to UTC (even if the timezone configured on the system is different)\n"); 
  printf("  -V\tPrint version and exit\n");
  printf("\n");
  printf("  See QUICKSTART file in the distribution for examples\n");
  printf("\n");
  printf("For suggestions, critics, bugs, contact me: %s.\n", MANTAINER);
}

void version_client(char *prog)
{
  printf("%s %s (%s)\n", PMACCT_USAGE_HEADER, PMACCT_VERSION, PMACCT_BUILD);
  printf("%s\n\n", PMACCT_COMPILE_ARGS);
  printf("For suggestions, critics, bugs, contact me: %s.\n", MANTAINER);
}

int pmc_sanitize_buf(char *buf)
{
  int x = 0, valid_char = 0;

  pmc_trim_all_spaces(buf);
  while (x < strlen(buf)) {
    if (!isspace(buf[x])) valid_char++;
    x++;
  }
  if (!valid_char) return TRUE;
  if (buf[0] == '!') return TRUE;

  return FALSE;
}

void pmc_trim_all_spaces(char *buf)
{
  int i = 0, len;

  len = strlen(buf);

  /* trimming all spaces */
  while (i <= len) {
    if (isspace(buf[i])) {
      strlcpy(&buf[i], &buf[i+1], len);
      len--;
    }
    else i++;
  }
}

void print_ex_options_error()
{
  printf("ERROR: -s, -t, -N, -M and -C options are each mutually exclusive.\n\n");
  exit(1);
}

void write_stats_header_formatted(pm_cfgreg_t what_to_count, pm_cfgreg_t what_to_count_2, u_int8_t have_wtc, int is_event)
{
  if (!have_wtc) {
    printf("TAG         ");
    printf("TAG2        ");
    printf("CLASS             ");
    printf("IN_IFACE    ");
    printf("OUT_IFACE   ");
#if defined HAVE_L2
    printf("SRC_MAC            ");
    printf("DST_MAC            ");
    printf("VLAN   ");
    printf("COS ");
    printf("ETYPE  ");
#endif
    printf("SRC_AS      ");
    printf("DST_AS      "); 
    printf("COMMS                    ");
    printf("SRC_COMMS                ");
    printf("AS_PATH                  ");
    printf("SRC_AS_PATH              ");
    printf("PREF     ");
    printf("SRC_PREF ");
    printf("MED     ");
    printf("SRC_MED ");
    printf("SRC_ROA ");
    printf("DST_ROA ");
    printf("PEER_SRC_AS ");
    printf("PEER_DST_AS ");
    printf("PEER_SRC_IP                                    ");
    printf("PEER_DST_IP                                    ");
    printf("SRC_IP                                         ");
    printf("DST_IP                                         ");
    printf("SRC_MASK  ");
    printf("DST_MASK  ");
    printf("SRC_PORT  ");
    printf("DST_PORT  ");
    printf("TCP_FLAGS  ");
    printf("PROTOCOL    ");
    printf("TOS    ");
#if defined (WITH_GEOIP) || defined (WITH_GEOIPV2)
    printf("SH_COUNTRY  ");
    printf("DH_COUNTRY  "); 
#endif
#if defined (WITH_GEOIPV2)
    printf("SH_POCODE     ");
    printf("DH_POCODE     ");
    printf("SH_LAT        ");
    printf("SH_LON        ");
    printf("DH_LAT        ");
    printf("DH_LON        "); 
#endif
    printf("SAMPLING_RATE ");
    printf("SAMPLING_DIRECTION ");

    printf("POST_NAT_SRC_IP                                ");
    printf("POST_NAT_DST_IP                                ");
    printf("POST_NAT_SRC_PORT  ");
    printf("POST_NAT_DST_PORT  ");
    printf("NAT_EVENT ");

    printf("MPLS_LABEL_TOP  ");
    printf("MPLS_LABEL_BOTTOM  ");
    printf("MPLS_STACK_DEPTH  ");

    printf("TUNNEL_SRC_MAC     ");
    printf("TUNNEL_DST_MAC     ");
    printf("TUNNEL_SRC_IP                                  ");
    printf("TUNNEL_DST_IP                                  ");
    printf("TUNNEL_PROTOCOL  ");
    printf("TUNNEL_TOS  ");
    printf("TUNNEL_SRC_PORT  ");
    printf("TUNNEL_DST_PORT  ");

    printf("TIMESTAMP_START                ");
    printf("TIMESTAMP_END                  ");
    printf("TIMESTAMP_ARRIVAL              ");
    printf("TIMESTAMP_EXPORT               ");
    printf("EXPORT_PROTO_SEQNO  ");
    printf("EXPORT_PROTO_VERSION  ");
    printf("EXPORT_PROTO_SYSID  ");

    /* all custom primitives printed here */
    {
      char cp_str[SRVBUFLEN];
      int cp_idx;

      for (cp_idx = 0; cp_idx < pmc_custom_primitives_registry.num; cp_idx++) {
        pmc_custom_primitive_header_print(cp_str, SRVBUFLEN, &pmc_custom_primitives_registry.primitive[cp_idx], TRUE);
        printf("%s  ", cp_str);
      }
    }

    if (!is_event) {
      printf("PACKETS               ");
      printf("FLOWS                 ");
      printf("BYTES\n");
    }
    else printf("\n");
  }
  else {
    if (what_to_count & COUNT_TAG) printf("TAG         ");
    if (what_to_count & COUNT_TAG2) printf("TAG2        ");
    if (what_to_count & COUNT_CLASS) printf("CLASS             ");
#if defined (WITH_NDPI)
    if (what_to_count_2 & COUNT_NDPI_CLASS) printf("CLASS             "); 
#endif
    if (what_to_count & COUNT_IN_IFACE) printf("IN_IFACE    ");
    if (what_to_count & COUNT_OUT_IFACE) printf("OUT_IFACE   ");
#if defined HAVE_L2
    if (what_to_count & (COUNT_SRC_MAC|COUNT_SUM_MAC)) printf("SRC_MAC            "); 
    if (what_to_count & COUNT_DST_MAC) printf("DST_MAC            "); 
    if (what_to_count & COUNT_VLAN) printf("VLAN   ");
    if (what_to_count & COUNT_COS) printf("COS ");
    if (what_to_count & COUNT_ETHERTYPE) printf("ETYPE  ");
#endif
    if (what_to_count & (COUNT_SRC_AS|COUNT_SUM_AS)) printf("SRC_AS      ");
    if (what_to_count & COUNT_DST_AS) printf("DST_AS      "); 
    if (what_to_count & COUNT_STD_COMM) printf("COMMS                   ");
    if (what_to_count & COUNT_EXT_COMM) printf("ECOMMS                  ");
    if (what_to_count & COUNT_SRC_STD_COMM) printf("SRC_COMMS               ");
    if (what_to_count & COUNT_SRC_EXT_COMM) printf("SRC_ECOMMS              ");
    if (what_to_count_2 & COUNT_LRG_COMM) printf("LCOMMS                  ");
    if (what_to_count_2 & COUNT_SRC_LRG_COMM) printf("SRC_LCOMMS              ");
    if (what_to_count & COUNT_AS_PATH) printf("AS_PATH                  ");
    if (what_to_count & COUNT_SRC_AS_PATH) printf("SRC_AS_PATH              ");
    if (what_to_count & COUNT_LOCAL_PREF) printf("PREF     ");
    if (what_to_count & COUNT_SRC_LOCAL_PREF) printf("SRC_PREF ");
    if (what_to_count & COUNT_MED) printf("MED     ");
    if (what_to_count & COUNT_SRC_MED) printf("SRC_MED ");
    if (what_to_count_2 & COUNT_SRC_ROA) printf("SRC_ROA ");
    if (what_to_count_2 & COUNT_DST_ROA) printf("DST_ROA ");
    if (what_to_count & COUNT_PEER_SRC_AS) printf("PEER_SRC_AS ");
    if (what_to_count & COUNT_PEER_DST_AS) printf("PEER_DST_AS ");
    if (what_to_count & COUNT_PEER_SRC_IP) printf("PEER_SRC_IP                                    ");
    if (what_to_count & COUNT_PEER_DST_IP) printf("PEER_DST_IP                                    ");
    if (what_to_count & COUNT_MPLS_VPN_RD) printf("MPLS_VPN_RD         ");
    if (what_to_count_2 & COUNT_MPLS_PW_ID) printf("MPLS_PW_ID  ");
    if (what_to_count & (COUNT_SRC_HOST|COUNT_SUM_HOST)) printf("SRC_IP                                         ");
    if (what_to_count & (COUNT_SRC_NET|COUNT_SUM_NET)) printf("SRC_NET                                        ");
    if (what_to_count & COUNT_DST_HOST) printf("DST_IP                                         ");
    if (what_to_count & COUNT_DST_NET) printf("DST_NET                                        ");
    if (what_to_count & COUNT_SRC_NMASK) printf("SRC_MASK  ");
    if (what_to_count & COUNT_DST_NMASK) printf("DST_MASK  "); 
    if (what_to_count & (COUNT_SRC_PORT|COUNT_SUM_PORT)) printf("SRC_PORT  ");
    if (what_to_count & COUNT_DST_PORT) printf("DST_PORT  "); 
    if (what_to_count & COUNT_TCPFLAGS) printf("TCP_FLAGS  "); 
    if (what_to_count & COUNT_IP_PROTO) printf("PROTOCOL    ");
    if (what_to_count & COUNT_IP_TOS) printf("TOS    ");

#if defined (WITH_GEOIP) || defined (WITH_GEOIPV2)
    if (what_to_count_2 & COUNT_SRC_HOST_COUNTRY) printf("SH_COUNTRY  ");
    if (what_to_count_2 & COUNT_DST_HOST_COUNTRY) printf("DH_COUNTRY  "); 
#endif
#if defined (WITH_GEOIPV2)
    if (what_to_count_2 & COUNT_SRC_HOST_POCODE) printf("SH_POCODE     ");
    if (what_to_count_2 & COUNT_DST_HOST_POCODE) printf("DH_POCODE     ");
    if (what_to_count_2 & COUNT_SRC_HOST_COORDS) {
      printf("SH_LAT        ");
      printf("SH_LON        ");
    }
    if (what_to_count_2 & COUNT_DST_HOST_COORDS) {
      printf("DH_LAT        ");
      printf("DH_LON        ");
    }
#endif
    if (what_to_count_2 & COUNT_SAMPLING_RATE) printf("SAMPLING_RATE ");
    if (what_to_count_2 & COUNT_SAMPLING_DIRECTION) printf("SAMPLING_DIRECTION ");

    if (what_to_count_2 & COUNT_POST_NAT_SRC_HOST) printf("POST_NAT_SRC_IP                                ");
    if (what_to_count_2 & COUNT_POST_NAT_DST_HOST) printf("POST_NAT_DST_IP                                ");
    if (what_to_count_2 & COUNT_POST_NAT_SRC_PORT) printf("POST_NAT_SRC_PORT  ");
    if (what_to_count_2 & COUNT_POST_NAT_DST_PORT) printf("POST_NAT_DST_PORT  ");
    if (what_to_count_2 & COUNT_NAT_EVENT) printf("NAT_EVENT ");

    if (what_to_count_2 & COUNT_MPLS_LABEL_TOP) printf("MPLS_LABEL_TOP  ");
    if (what_to_count_2 & COUNT_MPLS_LABEL_BOTTOM) printf("MPLS_LABEL_BOTTOM  ");
    if (what_to_count_2 & COUNT_MPLS_STACK_DEPTH) printf("MPLS_STACK_DEPTH  ");

    if (what_to_count_2 & COUNT_TUNNEL_SRC_MAC) printf("TUNNEL_SRC_MAC     ");
    if (what_to_count_2 & COUNT_TUNNEL_DST_MAC) printf("TUNNEL_DST_MAC     ");
    if (what_to_count_2 & COUNT_TUNNEL_SRC_HOST) printf("TUNNEL_SRC_IP                                  ");
    if (what_to_count_2 & COUNT_TUNNEL_DST_HOST) printf("TUNNEL_DST_IP                                  ");
    if (what_to_count_2 & COUNT_TUNNEL_IP_PROTO) printf("TUNNEL_PROTOCOL  ");
    if (what_to_count_2 & COUNT_TUNNEL_IP_TOS) printf("TUNNEL_TOS  ");
    if (what_to_count_2 & COUNT_TUNNEL_SRC_PORT) printf("TUNNEL_SRC_PORT  ");
    if (what_to_count_2 & COUNT_TUNNEL_DST_PORT) printf("TUNNEL_DST_PORT  ");
    if (what_to_count_2 & COUNT_VXLAN) printf("VXLAN     ");

    if (what_to_count_2 & COUNT_TIMESTAMP_START) printf("TIMESTAMP_START                ");
    if (what_to_count_2 & COUNT_TIMESTAMP_END) printf("TIMESTAMP_END                  "); 
    if (what_to_count_2 & COUNT_TIMESTAMP_ARRIVAL) printf("TIMESTAMP_ARRIVAL              "); 
    if (what_to_count_2 & COUNT_EXPORT_PROTO_TIME) printf("TIMESTAMP_EXPORT               "); 
    if (what_to_count_2 & COUNT_EXPORT_PROTO_SEQNO) printf("EXPORT_PROTO_SEQNO  "); 
    if (what_to_count_2 & COUNT_EXPORT_PROTO_VERSION) printf("EXPORT_PROTO_VERSION  "); 
    if (what_to_count_2 & COUNT_EXPORT_PROTO_SYSID) printf("EXPORT_PROTO_SYSID  "); 

    /* all custom primitives printed here */
    {
      char cp_str[SRVBUFLEN];
      int cp_idx;

      for (cp_idx = 0; cp_idx < pmc_custom_primitives_registry.num; cp_idx++) {
        pmc_custom_primitive_header_print(cp_str, SRVBUFLEN, &pmc_custom_primitives_registry.primitive[cp_idx], TRUE);
	printf("%s  ", cp_str);
      }
    }

    if (!is_event) {
      printf("PACKETS               ");
      if (what_to_count & COUNT_FLOWS) printf("FLOWS                 ");
      printf("BYTES\n");
    }
    else printf("\n");
  }
}

void write_stats_header_csv(pm_cfgreg_t what_to_count, pm_cfgreg_t what_to_count_2, u_int8_t have_wtc, char *sep, int is_event)
{
  int count = 0;

  if (!have_wtc) {
    printf("%sTAG", write_sep(sep, &count));
    printf("%sTAG2", write_sep(sep, &count));
    printf("%sLABEL", write_sep(sep, &count));
    printf("%sCLASS", write_sep(sep, &count));
    printf("%sIN_IFACE", write_sep(sep, &count));
    printf("%sOUT_IFACE", write_sep(sep, &count));
#if defined HAVE_L2
    printf("%sSRC_MAC", write_sep(sep, &count));
    printf("%sDST_MAC", write_sep(sep, &count));
    printf("%sVLAN", write_sep(sep, &count));
    printf("%sCOS", write_sep(sep, &count));
    printf("%sETYPE", write_sep(sep, &count));
#endif
    printf("%sSRC_AS", write_sep(sep, &count));
    printf("%sDST_AS", write_sep(sep, &count)); 
    printf("%sCOMMS", write_sep(sep, &count));
    printf("%sSRC_COMMS", write_sep(sep, &count));
    printf("%sAS_PATH", write_sep(sep, &count));
    printf("%sSRC_AS_PATH", write_sep(sep, &count));
    printf("%sPREF", write_sep(sep, &count));
    printf("%sSRC_PREF", write_sep(sep, &count));
    printf("%sMED", write_sep(sep, &count));
    printf("%sSRC_MED", write_sep(sep, &count));
    printf("%sSRC_ROA", write_sep(sep, &count));
    printf("%sDST_ROA", write_sep(sep, &count));
    printf("%sPEER_SRC_AS", write_sep(sep, &count));
    printf("%sPEER_DST_AS", write_sep(sep, &count));
    printf("%sPEER_SRC_IP", write_sep(sep, &count));
    printf("%sPEER_DST_IP", write_sep(sep, &count));
    printf("%sSRC_IP", write_sep(sep, &count));
    printf("%sDST_IP", write_sep(sep, &count));
    printf("%sSRC_MASK", write_sep(sep, &count));
    printf("%sDST_MASK", write_sep(sep, &count));
    printf("%sSRC_PORT", write_sep(sep, &count));
    printf("%sDST_PORT", write_sep(sep, &count));
    printf("%sTCP_FLAGS", write_sep(sep, &count));
    printf("%sPROTOCOL", write_sep(sep, &count));
    printf("%sTOS", write_sep(sep, &count));
#if defined (WITH_GEOIP) || defined (WITH_GEOIPV2)
    printf("%sSH_COUNTRY", write_sep(sep, &count));
    printf("%sDH_COUNTRY", write_sep(sep, &count));
#endif
#if defined (WITH_GEOIPV2)
    printf("%sSH_POCODE", write_sep(sep, &count));
    printf("%sDH_POCODE", write_sep(sep, &count));
    printf("%sSH_LAT", write_sep(sep, &count));
    printf("%sSH_LON", write_sep(sep, &count));
    printf("%sDH_LAT", write_sep(sep, &count));
    printf("%sDH_LON", write_sep(sep, &count));
#endif
    printf("%sSAMPLING_RATE", write_sep(sep, &count));
    printf("%sSAMPLING_DIRECTION", write_sep(sep, &count));
    printf("%sPOST_NAT_SRC_IP", write_sep(sep, &count));
    printf("%sPOST_NAT_DST_IP", write_sep(sep, &count));
    printf("%sPOST_NAT_SRC_PORT", write_sep(sep, &count));
    printf("%sPOST_NAT_DST_PORT", write_sep(sep, &count));
    printf("%sNAT_EVENT", write_sep(sep, &count));
    printf("%sMPLS_LABEL_TOP", write_sep(sep, &count));
    printf("%sMPLS_LABEL_BOTTOM", write_sep(sep, &count));
    printf("%sMPLS_STACK_DEPTH", write_sep(sep, &count));
    printf("%sTUNNEL_SRC_MAC", write_sep(sep, &count));
    printf("%sTUNNEL_DST_MAC", write_sep(sep, &count));
    printf("%sTUNNEL_SRC_IP", write_sep(sep, &count));
    printf("%sTUNNEL_DST_IP", write_sep(sep, &count));
    printf("%sTUNNEL_PROTOCOL", write_sep(sep, &count));
    printf("%sTUNNEL_TOS", write_sep(sep, &count));
    printf("%sTUNNEL_SRC_PORT", write_sep(sep, &count));
    printf("%sTUNNEL_DST_PORT", write_sep(sep, &count));
    printf("%sTIMESTAMP_START", write_sep(sep, &count));
    printf("%sTIMESTAMP_END", write_sep(sep, &count));
    printf("%sTIMESTAMP_ARRIVAL", write_sep(sep, &count));
    printf("%sTIMESTAMP_EXPORT", write_sep(sep, &count));
    printf("%sEXPORT_PROTO_SEQNO", write_sep(sep, &count));
    printf("%sEXPORT_PROTO_VERSION", write_sep(sep, &count));
    printf("%sEXPORT_PROTO_SYSID", write_sep(sep, &count));
    /* all custom primitives printed here */
    {
      char cp_str[SRVBUFLEN];
      int cp_idx;

      for (cp_idx = 0; cp_idx < pmc_custom_primitives_registry.num; cp_idx++) {
        pmc_custom_primitive_header_print(cp_str, SRVBUFLEN, &pmc_custom_primitives_registry.primitive[cp_idx], FALSE);
        printf("%s%s", write_sep(sep, &count), cp_str);
      }
    }
    if (!is_event) {
      printf("%sPACKETS", write_sep(sep, &count));
      printf("%sFLOWS", write_sep(sep, &count));
      printf("%sBYTES\n", write_sep(sep, &count));
    }
    else printf("\n");
  }
  else {
    if (what_to_count & COUNT_TAG) printf("%sTAG", write_sep(sep, &count));
    if (what_to_count & COUNT_TAG2) printf("%sTAG2", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_LABEL) printf("%sLABEL", write_sep(sep, &count));
    if (what_to_count & COUNT_CLASS) printf("%sCLASS", write_sep(sep, &count));
#if defined (WITH_NDPI)
    if (what_to_count_2 & COUNT_NDPI_CLASS) printf("%sCLASS", write_sep(sep, &count)); 
#endif
    if (what_to_count & COUNT_IN_IFACE) printf("%sIN_IFACE", write_sep(sep, &count));
    if (what_to_count & COUNT_OUT_IFACE) printf("%sOUT_IFACE", write_sep(sep, &count));
#if defined HAVE_L2
    if (what_to_count & (COUNT_SRC_MAC|COUNT_SUM_MAC)) printf("%sSRC_MAC", write_sep(sep, &count)); 
    if (what_to_count & COUNT_DST_MAC) printf("%sDST_MAC", write_sep(sep, &count)); 
    if (what_to_count & COUNT_VLAN) printf("%sVLAN", write_sep(sep, &count));
    if (what_to_count & COUNT_COS) printf("%sCOS", write_sep(sep, &count));
    if (what_to_count & COUNT_ETHERTYPE) printf("%sETYPE", write_sep(sep, &count));
#endif
    if (what_to_count & (COUNT_SRC_AS|COUNT_SUM_AS)) printf("%sSRC_AS", write_sep(sep, &count));
    if (what_to_count & COUNT_DST_AS) printf("%sDST_AS", write_sep(sep, &count)); 
    if (what_to_count & COUNT_STD_COMM) printf("%sCOMMS", write_sep(sep, &count));
    if (what_to_count & COUNT_EXT_COMM) printf("%sECOMMS", write_sep(sep, &count));
    if (what_to_count & COUNT_SRC_STD_COMM) printf("%sSRC_COMMS", write_sep(sep, &count));
    if (what_to_count & COUNT_SRC_EXT_COMM) printf("%sSRC_ECOMMS", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_LRG_COMM) printf("%sLCOMMS", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_SRC_LRG_COMM) printf("%sSRC_LCOMMS", write_sep(sep, &count));
    if (what_to_count & COUNT_AS_PATH) printf("%sAS_PATH", write_sep(sep, &count));
    if (what_to_count & COUNT_SRC_AS_PATH) printf("%sSRC_AS_PATH", write_sep(sep, &count));
    if (what_to_count & COUNT_LOCAL_PREF) printf("%sPREF", write_sep(sep, &count));
    if (what_to_count & COUNT_SRC_LOCAL_PREF) printf("%sSRC_PREF", write_sep(sep, &count));
    if (what_to_count & COUNT_MED) printf("%sMED", write_sep(sep, &count));
    if (what_to_count & COUNT_SRC_MED) printf("%sSRC_MED", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_SRC_ROA) printf("%sSRC_ROA", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_DST_ROA) printf("%sDST_ROA", write_sep(sep, &count));
    if (what_to_count & COUNT_PEER_SRC_AS) printf("%sPEER_SRC_AS", write_sep(sep, &count));
    if (what_to_count & COUNT_PEER_DST_AS) printf("%sPEER_DST_AS", write_sep(sep, &count));
    if (what_to_count & COUNT_PEER_SRC_IP) printf("%sPEER_SRC_IP", write_sep(sep, &count));
    if (what_to_count & COUNT_PEER_DST_IP) printf("%sPEER_DST_IP", write_sep(sep, &count));
    if (what_to_count & COUNT_MPLS_VPN_RD) printf("%sMPLS_VPN_RD", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_MPLS_PW_ID) printf("%sMPLS_PW_ID", write_sep(sep, &count));
    if (what_to_count & (COUNT_SRC_HOST|COUNT_SUM_HOST)) printf("%sSRC_IP", write_sep(sep, &count));
    if (what_to_count & (COUNT_SRC_NET|COUNT_SUM_NET)) printf("%sSRC_NET", write_sep(sep, &count));
    if (what_to_count & COUNT_DST_HOST) printf("%sDST_IP", write_sep(sep, &count));
    if (what_to_count & COUNT_DST_NET) printf("%sDST_NET", write_sep(sep, &count));
    if (what_to_count & COUNT_SRC_NMASK) printf("%sSRC_MASK", write_sep(sep, &count));
    if (what_to_count & COUNT_DST_NMASK) printf("%sDST_MASK", write_sep(sep, &count)); 
    if (what_to_count & (COUNT_SRC_PORT|COUNT_SUM_PORT)) printf("%sSRC_PORT", write_sep(sep, &count));
    if (what_to_count & COUNT_DST_PORT) printf("%sDST_PORT", write_sep(sep, &count)); 
    if (what_to_count & COUNT_TCPFLAGS) printf("%sTCP_FLAGS", write_sep(sep, &count)); 
    if (what_to_count & COUNT_IP_PROTO) printf("%sPROTOCOL", write_sep(sep, &count));
    if (what_to_count & COUNT_IP_TOS) printf("%sTOS", write_sep(sep, &count));

#if defined (WITH_GEOIP) || defined (WITH_GEOIPV2)
    if (what_to_count_2 & COUNT_SRC_HOST_COUNTRY) printf("%sSH_COUNTRY", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_DST_HOST_COUNTRY) printf("%sDH_COUNTRY", write_sep(sep, &count));
#endif
#if defined (WITH_GEOIPV2)
    if (what_to_count_2 & COUNT_SRC_HOST_POCODE) printf("%sSH_POCODE", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_DST_HOST_POCODE) printf("%sDH_POCODE", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_SRC_HOST_COORDS) {
      printf("%sSH_LAT", write_sep(sep, &count));
      printf("%sSH_LON", write_sep(sep, &count));
    }
    if (what_to_count_2 & COUNT_DST_HOST_COORDS) {
      printf("%sDH_LAT", write_sep(sep, &count));
      printf("%sDH_LON", write_sep(sep, &count));
    }
#endif
    if (what_to_count_2 & COUNT_SAMPLING_RATE) printf("%sSAMPLING_RATE", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_SAMPLING_DIRECTION) printf("%sSAMPLING_DIRECTION", write_sep(sep, &count));

    if (what_to_count_2 & COUNT_POST_NAT_SRC_HOST) printf("%sPOST_NAT_SRC_IP", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_POST_NAT_DST_HOST) printf("%sPOST_NAT_DST_IP", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_POST_NAT_SRC_PORT) printf("%sPOST_NAT_SRC_PORT", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_POST_NAT_DST_PORT) printf("%sPOST_NAT_DST_PORT", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_NAT_EVENT) printf("%sNAT_EVENT", write_sep(sep, &count));

    if (what_to_count_2 & COUNT_MPLS_LABEL_TOP) printf("%sMPLS_LABEL_TOP", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_MPLS_LABEL_BOTTOM) printf("%sMPLS_LABEL_BOTTOM", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_MPLS_STACK_DEPTH) printf("%sMPLS_STACK_DEPTH", write_sep(sep, &count));

    if (what_to_count_2 & COUNT_TUNNEL_SRC_MAC) printf("%sTUNNEL_SRC_MAC", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_TUNNEL_DST_MAC) printf("%sTUNNEL_DST_MAC", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_TUNNEL_SRC_HOST) printf("%sTUNNEL_SRC_IP", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_TUNNEL_DST_HOST) printf("%sTUNNEL_DST_IP", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_TUNNEL_IP_PROTO) printf("%sTUNNEL_PROTOCOL", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_TUNNEL_IP_TOS) printf("%sTUNNEL_TOS", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_TUNNEL_SRC_PORT) printf("%sTUNNEL_SRC_PORT", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_TUNNEL_DST_PORT) printf("%sTUNNEL_DST_PORT", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_VXLAN) printf("%sVXLAN", write_sep(sep, &count));

    if (what_to_count_2 & COUNT_TIMESTAMP_START) printf("%sTIMESTAMP_START", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_TIMESTAMP_END) printf("%sTIMESTAMP_END", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_TIMESTAMP_ARRIVAL) printf("%sTIMESTAMP_ARRIVAL", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_EXPORT_PROTO_TIME) printf("%sTIMESTAMP_EXPORT", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_EXPORT_PROTO_SEQNO) printf("%sEXPORT_PROTO_SEQNO", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_EXPORT_PROTO_VERSION) printf("%sEXPORT_PROTO_VERSION", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_EXPORT_PROTO_SYSID) printf("%sEXPORT_PROTO_SYSID", write_sep(sep, &count));

    /* all custom primitives printed here */
    {
      char cp_str[SRVBUFLEN];
      int cp_idx;

      for (cp_idx = 0; cp_idx < pmc_custom_primitives_registry.num; cp_idx++) {
        pmc_custom_primitive_header_print(cp_str, SRVBUFLEN, &pmc_custom_primitives_registry.primitive[cp_idx], FALSE);
        printf("%s%s", write_sep(sep, &count), cp_str);
      }
    }

    if (!is_event) {
      printf("%sPACKETS", write_sep(sep, &count));
      if (what_to_count & COUNT_FLOWS) printf("%sFLOWS", write_sep(sep, &count));
      printf("%sBYTES\n", write_sep(sep, &count));
    }
    else printf("\n");
  }
}

void write_status_header()
{
  printf("* = element\n\n"); 
  printf("BUCKET\tCHAIN_STATUS\n");
}

void write_class_table_header()
{
  printf("CLASS_ID\tCLASS_NAME\n");
}

int build_query_client(char *path_ptr)
{
  struct sockaddr_un cAddr;
  int sd, rc, cLen;

  sd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sd < 0) {
    printf("ERROR: Unable to open socket.\n");
    exit(1);
  }

  cAddr.sun_family = AF_UNIX;
  strcpy(cAddr.sun_path, path_ptr);
  cLen = sizeof(cAddr);

  rc = connect(sd, (struct sockaddr *) &cAddr, cLen);
  if (rc < 0) {
    if (errno == ECONNREFUSED) {
      printf("INFO: Connection refused while trying to connect to '%s'\n\n", path_ptr);
      exit(1);
    }
    else {
      printf("ERROR: Unable to connect to '%s'\n\n", path_ptr);
      exit(1);
    }
  }

  return sd;
}

int main(int argc,char **argv)
{
  int clibufsz = (MAX_QUERIES*sizeof(struct query_entry))+sizeof(struct query_header)+2;
  struct pkt_data *acc_elem = NULL;
  struct bucket_desc *bd;
  struct query_header q; 
  struct pkt_primitives empty_addr;
  struct pkt_bgp_primitives empty_pbgp;
  struct pkt_legacy_bgp_primitives empty_plbgp;
  struct pkt_nat_primitives empty_pnat;
  struct pkt_mpls_primitives empty_pmpls;
  struct pkt_tunnel_primitives empty_ptun;
  struct pkt_vlen_hdr_primitives empty_pvlen;
  struct query_entry request;
  struct pkt_bgp_primitives *pbgp = NULL;
  struct pkt_legacy_bgp_primitives *plbgp = NULL;
  struct pkt_nat_primitives *pnat = NULL;
  struct pkt_mpls_primitives *pmpls = NULL;
  struct pkt_tunnel_primitives *ptun = NULL;
  struct pkt_vlen_hdr_primitives *pvlen = NULL;
  u_char *pcust = NULL;
  char *clibuf, *bufptr;
  unsigned char *largebuf, *elem, *ct, *cpt;
  char ethernet_address[18], ip_address[INET6_ADDRSTRLEN];
#if defined (WITH_NDPI)
  char ndpi_class[SUPERSHORTBUFLEN];
#endif
  char path[SRVBUFLEN], file[SRVBUFLEN], password[9], rd_str[SRVBUFLEN], tmpbuf[SRVBUFLEN];
  char *as_path, empty_aspath[] = "^$", empty_string[] = "", *bgp_comm;
  int sd, buflen, unpacked, printed;
  int counter=0, sep_len=0, is_event;
  char *sep_ptr = NULL, sep[10], default_sep[] = ",", spacing_sep[2];
  struct imt_custom_primitives custom_primitives_input;

  /* mrtg stuff */
  char match_string[LARGEBUFLEN], *match_string_token, *match_string_ptr;
  char count[SRVBUFLEN], *count_token[N_PRIMITIVES], *count_ptr;
  int count_index = 0, match_string_index = 0, index = 0;
  pm_cfgreg_t count_token_int[N_PRIMITIVES];
  
  /* getopt() stuff */
  extern char *optarg;
  extern int optind, opterr, optopt;
  int errflag, cp, want_stats, want_erase, want_reset, want_class_table; 
  int want_status, want_mrtg, want_counter, want_match, want_all_fields;
  int want_output, want_custom_primitives_table;
  int want_erase_last_tstamp, want_tstamp_since_epoch, want_tstamp_utc;
  int which_counter, topN_counter, fetch_from_file, sum_counters, num_counters;
  int topN_howmany, topN_printed;
  int datasize;
  pm_cfgreg_t what_to_count, what_to_count_2, have_wtc;
  u_int32_t tmpnum;
  struct extra_primitives extras;
  char *topN_howmany_ptr, *endptr;

  /* Administrativia */
  clibuf = malloc(clibufsz);

  memset(&q, 0, sizeof(struct query_header));
  memset(&empty_addr, 0, sizeof(struct pkt_primitives));
  memset(&empty_pbgp, 0, sizeof(struct pkt_bgp_primitives));
  memset(&empty_plbgp, 0, sizeof(struct pkt_legacy_bgp_primitives));
  memset(&empty_pnat, 0, sizeof(struct pkt_nat_primitives));
  memset(&empty_pmpls, 0, sizeof(struct pkt_mpls_primitives));
  memset(&empty_ptun, 0, sizeof(struct pkt_tunnel_primitives));
  memset(&empty_pvlen, 0, sizeof(struct pkt_vlen_hdr_primitives));
  memset(count, 0, sizeof(count));
  memset(password, 0, sizeof(password)); 
  memset(sep, 0, sizeof(sep));
  memset(&pmc_custom_primitives_registry, 0, sizeof(pmc_custom_primitives_registry));
  memset(&custom_primitives_input, 0, sizeof(custom_primitives_input));

  strcpy(path, "/tmp/collect.pipe");
  unpacked = 0; printed = 0;
  errflag = 0; buflen = 0;
  protocols_number = 0;
  want_stats = FALSE;
  want_erase = FALSE;
  want_erase_last_tstamp = FALSE;
  want_status = FALSE;
  want_counter = FALSE;
  want_mrtg = FALSE;
  want_match = FALSE;
  want_all_fields = FALSE;
  want_reset = FALSE;
  want_class_table = FALSE;
  want_ipproto_num = FALSE;
  want_custom_primitives_table = FALSE;
  which_counter = FALSE;
  topN_counter = FALSE;
  topN_howmany = FALSE;
  sum_counters = FALSE;
  num_counters = FALSE;
  fetch_from_file = FALSE;
  what_to_count = FALSE;
  what_to_count_2 = FALSE;
  have_wtc = FALSE;
  want_output = PRINT_OUTPUT_FORMATTED;
  is_event = FALSE;
  want_tstamp_since_epoch = FALSE;
  want_tstamp_utc = FALSE;

  PvhdrSz = sizeof(struct pkt_vlen_hdr_primitives);
  PmLabelTSz = sizeof(pm_label_t);
  PtLabelTSz = sizeof(pt_label_t);

  while (!errflag && ((cp = getopt(argc, argv, ARGS_PMACCT)) != -1)) {
    switch (cp) {
    case 's':
      if (CHECK_Q_TYPE(q.type)) print_ex_options_error();
      q.type |= WANT_STATS;
      q.num = 1;
      want_stats = TRUE;
      break;
    case 'c':
      strlcpy(count, optarg, sizeof(count));
      pmc_lower_string(count);
      count_ptr = count;

      while ((*count_ptr != '\0') && (count_index <= N_PRIMITIVES-1)) {
        count_token[count_index] = pmc_extract_token(&count_ptr, ',');
	if (!strcmp(count_token[count_index], "src_host")) {
	  count_token_int[count_index] = COUNT_INT_SRC_HOST;
	  what_to_count |= COUNT_SRC_HOST;
	}
        else if (!strcmp(count_token[count_index], "dst_host")) {
	  count_token_int[count_index] = COUNT_INT_DST_HOST;
	  what_to_count |= COUNT_DST_HOST;
	}
        else if (!strcmp(count_token[count_index], "src_net")) {
          count_token_int[count_index] = COUNT_INT_SRC_NET;
          what_to_count |= COUNT_SRC_NET;
        }  
        else if (!strcmp(count_token[count_index], "dst_net")) {
          count_token_int[count_index] = COUNT_INT_DST_NET;
          what_to_count |= COUNT_DST_NET;
	} 
        else if (!strcmp(count_token[count_index], "sum")) {
	  count_token_int[count_index] = COUNT_INT_SUM_HOST;
	  what_to_count |= COUNT_SUM_HOST;
	}
        else if (!strcmp(count_token[count_index], "src_port")) {
	  count_token_int[count_index] = COUNT_INT_SRC_PORT;
	  what_to_count |= COUNT_SRC_PORT;
	}
        else if (!strcmp(count_token[count_index], "dst_port")) {
	  count_token_int[count_index] = COUNT_INT_DST_PORT;
	  what_to_count |= COUNT_DST_PORT;
	}
        else if (!strcmp(count_token[count_index], "proto")) {
	  count_token_int[count_index] = COUNT_INT_IP_PROTO;
	  what_to_count |= COUNT_IP_PROTO;
	}
#if defined HAVE_L2
        else if (!strcmp(count_token[count_index], "src_mac")) {
	  count_token_int[count_index] = COUNT_INT_SRC_MAC;
	  what_to_count |= COUNT_SRC_MAC;
	}
        else if (!strcmp(count_token[count_index], "dst_mac")) {
	  count_token_int[count_index] = COUNT_INT_DST_MAC;
	  what_to_count |= COUNT_DST_MAC;
	}
        else if (!strcmp(count_token[count_index], "vlan")) {
	  count_token_int[count_index] = COUNT_INT_VLAN;
	  what_to_count |= COUNT_VLAN;
	}
        else if (!strcmp(count_token[count_index], "cos")) {
          count_token_int[count_index] = COUNT_INT_COS;
          what_to_count |= COUNT_COS;
        }
        else if (!strcmp(count_token[count_index], "etype")) {
          count_token_int[count_index] = COUNT_INT_ETHERTYPE;
          what_to_count |= COUNT_ETHERTYPE;
        }
	else if (!strcmp(count_token[count_index], "sum_mac")) {
	  count_token_int[count_index] = COUNT_INT_SUM_MAC;
	  what_to_count |= COUNT_SUM_MAC;
	}
#endif 
        else if (!strcmp(count_token[count_index], "in_iface")) {
          count_token_int[count_index] = COUNT_INT_IN_IFACE;
          what_to_count |= COUNT_IN_IFACE;
        }
        else if (!strcmp(count_token[count_index], "out_iface")) {
          count_token_int[count_index] = COUNT_INT_OUT_IFACE;
          what_to_count |= COUNT_OUT_IFACE;
        }
        else if (!strcmp(count_token[count_index], "tos")) {
	  count_token_int[count_index] = COUNT_INT_IP_TOS;
	  what_to_count |= COUNT_IP_TOS;
	}
#if defined (WITH_GEOIP) || defined (WITH_GEOIPV2)
        else if (!strcmp(count_token[count_index], "src_host_country")) {
          count_token_int[count_index] = COUNT_INT_SRC_HOST_COUNTRY;
          what_to_count_2 |= COUNT_SRC_HOST_COUNTRY;
        }
        else if (!strcmp(count_token[count_index], "dst_host_country")) {
          count_token_int[count_index] = COUNT_INT_DST_HOST_COUNTRY;
          what_to_count_2 |= COUNT_DST_HOST_COUNTRY;
        }
#endif
#if defined (WITH_GEOIPV2)
        else if (!strcmp(count_token[count_index], "src_host_pocode")) {
          count_token_int[count_index] = COUNT_INT_SRC_HOST_POCODE;
          what_to_count_2 |= COUNT_SRC_HOST_POCODE;
        }
        else if (!strcmp(count_token[count_index], "dst_host_pocode")) {
          count_token_int[count_index] = COUNT_INT_DST_HOST_POCODE;
          what_to_count_2 |= COUNT_DST_HOST_POCODE;
        }
        else if (!strcmp(count_token[count_index], "src_host_coords")) {
          count_token_int[count_index] = COUNT_INT_SRC_HOST_COORDS;
          what_to_count_2 |= COUNT_SRC_HOST_COORDS;
        }
        else if (!strcmp(count_token[count_index], "dst_host_coords")) {
          count_token_int[count_index] = COUNT_INT_DST_HOST_COORDS;
          what_to_count_2 |= COUNT_DST_HOST_COORDS;
        }
#endif
        else if (!strcmp(count_token[count_index], "sampling_rate")) {
	  count_token_int[count_index] = COUNT_INT_SAMPLING_RATE;
	  what_to_count_2 |= COUNT_SAMPLING_RATE;
	}
        else if (!strcmp(count_token[count_index], "sampling_direction")) {
	  count_token_int[count_index] = COUNT_INT_SAMPLING_DIRECTION;
	  what_to_count_2 |= COUNT_SAMPLING_DIRECTION;
	}
        else if (!strcmp(count_token[count_index], "none")) {
	  count_token_int[count_index] = COUNT_INT_NONE;
	  what_to_count |= COUNT_NONE;
	}
        else if (!strcmp(count_token[count_index], "src_as")) {
	  count_token_int[count_index] = COUNT_INT_SRC_AS;
	  what_to_count |= COUNT_SRC_AS;
	}
        else if (!strcmp(count_token[count_index], "dst_as")) {
	  count_token_int[count_index] = COUNT_INT_DST_AS;
	  what_to_count |= COUNT_DST_AS;
	}
        else if (!strcmp(count_token[count_index], "src_net")) {
	  count_token_int[count_index] = COUNT_INT_SRC_NET;
	  what_to_count |= COUNT_SRC_NET;
	}
        else if (!strcmp(count_token[count_index], "dst_net")) {
	  count_token_int[count_index] = COUNT_INT_DST_NET;
	  what_to_count |= COUNT_DST_NET;
	}
        else if (!strcmp(count_token[count_index], "sum_host")) {
	  count_token_int[count_index] = COUNT_INT_SUM_HOST;
	  what_to_count |= COUNT_SUM_HOST;
	}
        else if (!strcmp(count_token[count_index], "sum_net")) {
	  count_token_int[count_index] = COUNT_INT_SUM_NET;
	  what_to_count |= COUNT_SUM_NET;
	}
        else if (!strcmp(count_token[count_index], "sum_as")) {
	  count_token_int[count_index] = COUNT_INT_SUM_AS;
	  what_to_count |= COUNT_SUM_AS;
	}
        else if (!strcmp(count_token[count_index], "sum_port")) {
	  count_token_int[count_index] = COUNT_INT_SUM_PORT;
	  what_to_count |= COUNT_SUM_PORT;
	}
        else if (!strcmp(count_token[count_index], "src_mask")) {
          count_token_int[count_index] = COUNT_INT_SRC_NMASK;
          what_to_count |= COUNT_SRC_NMASK;
        }
        else if (!strcmp(count_token[count_index], "dst_mask")) {
          count_token_int[count_index] = COUNT_INT_DST_NMASK;
          what_to_count |= COUNT_DST_NMASK;
        }
        else if (!strcmp(count_token[count_index], "tag")) {
	  count_token_int[count_index] = COUNT_INT_TAG;
	  what_to_count |= COUNT_TAG;
	}
        else if (!strcmp(count_token[count_index], "tag2")) {
          count_token_int[count_index] = COUNT_INT_TAG2;
          what_to_count |= COUNT_TAG2;
        }
        else if (!strcmp(count_token[count_index], "class")) {
          count_token_int[count_index] = COUNT_INT_CLASS;
          what_to_count |= COUNT_CLASS;
        }
        else if (!strcmp(count_token[count_index], "std_comm")) {
          count_token_int[count_index] = COUNT_INT_STD_COMM;
          what_to_count |= COUNT_STD_COMM;
        }
        else if (!strcmp(count_token[count_index], "src_std_comm")) {
          count_token_int[count_index] = COUNT_INT_SRC_STD_COMM;
          what_to_count |= COUNT_SRC_STD_COMM;
        }
        else if (!strcmp(count_token[count_index], "ext_comm")) {
          count_token_int[count_index] = COUNT_INT_EXT_COMM;
          what_to_count |= COUNT_EXT_COMM;
        }
        else if (!strcmp(count_token[count_index], "src_ext_comm")) {
          count_token_int[count_index] = COUNT_INT_SRC_EXT_COMM;
          what_to_count |= COUNT_SRC_EXT_COMM;
        }
        else if (!strcmp(count_token[count_index], "lrg_comm")) {
          count_token_int[count_index] = COUNT_INT_LRG_COMM;
          what_to_count_2 |= COUNT_LRG_COMM;
        }
        else if (!strcmp(count_token[count_index], "src_lrg_comm")) {
          count_token_int[count_index] = COUNT_INT_SRC_LRG_COMM;
          what_to_count_2 |= COUNT_SRC_LRG_COMM;
        }
        else if (!strcmp(count_token[count_index], "as_path")) {
          count_token_int[count_index] = COUNT_INT_AS_PATH;
          what_to_count |= COUNT_AS_PATH;
        }
        else if (!strcmp(count_token[count_index], "src_as_path")) {
          count_token_int[count_index] = COUNT_INT_SRC_AS_PATH;
          what_to_count |= COUNT_SRC_AS_PATH;
        }
        else if (!strcmp(count_token[count_index], "local_pref")) {
          count_token_int[count_index] = COUNT_INT_LOCAL_PREF;
          what_to_count |= COUNT_LOCAL_PREF;
        }
        else if (!strcmp(count_token[count_index], "src_local_pref")) {
          count_token_int[count_index] = COUNT_INT_SRC_LOCAL_PREF;
          what_to_count |= COUNT_SRC_LOCAL_PREF;
	}
        else if (!strcmp(count_token[count_index], "med")) {
          count_token_int[count_index] = COUNT_INT_MED;
          what_to_count |= COUNT_MED;
        }
        else if (!strcmp(count_token[count_index], "src_med")) {
          count_token_int[count_index] = COUNT_INT_SRC_MED;
          what_to_count |= COUNT_SRC_MED;
        }
        else if (!strcmp(count_token[count_index], "src_roa")) {
          count_token_int[count_index] = COUNT_INT_SRC_ROA;
          what_to_count_2 |= COUNT_SRC_ROA;
        }
        else if (!strcmp(count_token[count_index], "dst_roa")) {
          count_token_int[count_index] = COUNT_INT_DST_ROA;
          what_to_count_2 |= COUNT_DST_ROA;
        }
        else if (!strcmp(count_token[count_index], "peer_src_as")) {
          count_token_int[count_index] = COUNT_INT_PEER_SRC_AS;
          what_to_count |= COUNT_PEER_SRC_AS;
        }
        else if (!strcmp(count_token[count_index], "peer_dst_as")) {
          count_token_int[count_index] = COUNT_INT_PEER_DST_AS;
          what_to_count |= COUNT_PEER_DST_AS;
        }
        else if (!strcmp(count_token[count_index], "peer_src_ip")) {
          count_token_int[count_index] = COUNT_INT_PEER_SRC_IP;
          what_to_count |= COUNT_PEER_SRC_IP;
        }
        else if (!strcmp(count_token[count_index], "peer_dst_ip")) {
          count_token_int[count_index] = COUNT_INT_PEER_DST_IP;
          what_to_count |= COUNT_PEER_DST_IP;
        }
        else if (!strcmp(count_token[count_index], "mpls_vpn_rd")) {
          count_token_int[count_index] = COUNT_INT_MPLS_VPN_RD;
          what_to_count |= COUNT_MPLS_VPN_RD;
        }
        else if (!strcmp(count_token[count_index], "mpls_pw_id")) {
          count_token_int[count_index] = COUNT_INT_MPLS_PW_ID;
          what_to_count_2 |= COUNT_MPLS_PW_ID;
        }
        else if (!strcmp(count_token[count_index], "post_nat_src_host")) {
          count_token_int[count_index] = COUNT_INT_POST_NAT_SRC_HOST;
          what_to_count_2 |= COUNT_POST_NAT_SRC_HOST;
        }
        else if (!strcmp(count_token[count_index], "post_nat_dst_host")) {
          count_token_int[count_index] = COUNT_INT_POST_NAT_DST_HOST;
          what_to_count_2 |= COUNT_POST_NAT_DST_HOST;
        }
        else if (!strcmp(count_token[count_index], "post_nat_src_port")) {
          count_token_int[count_index] = COUNT_INT_POST_NAT_SRC_PORT;
          what_to_count_2 |= COUNT_POST_NAT_SRC_PORT;
        }
        else if (!strcmp(count_token[count_index], "post_nat_dst_port")) {
          count_token_int[count_index] = COUNT_INT_POST_NAT_DST_PORT;
          what_to_count_2 |= COUNT_POST_NAT_DST_HOST;
        }
        else if (!strcmp(count_token[count_index], "nat_event")) {
          count_token_int[count_index] = COUNT_INT_NAT_EVENT;
          what_to_count_2 |= COUNT_NAT_EVENT;
        }
        else if (!strcmp(count_token[count_index], "mpls_label_top")) {
          count_token_int[count_index] = COUNT_INT_MPLS_LABEL_TOP;
          what_to_count_2 |= COUNT_MPLS_LABEL_TOP;
        }
        else if (!strcmp(count_token[count_index], "mpls_label_bottom")) {
          count_token_int[count_index] = COUNT_INT_MPLS_LABEL_BOTTOM;
          what_to_count_2 |= COUNT_MPLS_LABEL_BOTTOM;
        }
        else if (!strcmp(count_token[count_index], "mpls_stack_depth")) {
          count_token_int[count_index] = COUNT_INT_MPLS_STACK_DEPTH;
          what_to_count_2 |= COUNT_MPLS_STACK_DEPTH;
        }
        else if (!strcmp(count_token[count_index], "timestamp_start")) {
          count_token_int[count_index] = COUNT_INT_TIMESTAMP_START;
          what_to_count_2 |= COUNT_TIMESTAMP_START;
        }
        else if (!strcmp(count_token[count_index], "timestamp_end")) {
          count_token_int[count_index] = COUNT_INT_TIMESTAMP_END;
          what_to_count_2 |= COUNT_TIMESTAMP_END;
        }
        else if (!strcmp(count_token[count_index], "timestamp_arrival")) {
          count_token_int[count_index] = COUNT_INT_TIMESTAMP_ARRIVAL;
          what_to_count_2 |= COUNT_TIMESTAMP_ARRIVAL;
        }
        else if (!strcmp(count_token[count_index], "timestamp_export")) {
          count_token_int[count_index] = COUNT_INT_EXPORT_PROTO_TIME;
          what_to_count_2 |= COUNT_EXPORT_PROTO_TIME;
	}
        else if (!strcmp(count_token[count_index], "export_proto_seqno")) {
          count_token_int[count_index] = COUNT_INT_EXPORT_PROTO_SEQNO;
          what_to_count_2 |= COUNT_EXPORT_PROTO_SEQNO;
        }
        else if (!strcmp(count_token[count_index], "export_proto_version")) {
          count_token_int[count_index] = COUNT_INT_EXPORT_PROTO_VERSION;
          what_to_count_2 |= COUNT_EXPORT_PROTO_VERSION;
        }
        else if (!strcmp(count_token[count_index], "export_proto_sysid")) {
          count_token_int[count_index] = COUNT_INT_EXPORT_PROTO_SYSID;
          what_to_count_2 |= COUNT_EXPORT_PROTO_SYSID;
	}
        else if (!strcmp(count_token[count_index], "label")) {
          count_token_int[count_index] = COUNT_INT_LABEL;
          what_to_count_2 |= COUNT_LABEL;
        }
        else {
	  strlcpy(custom_primitives_input.primitive[custom_primitives_input.num].name,
			count_token[count_index], MAX_CUSTOM_PRIMITIVE_NAMELEN);
	  custom_primitives_input.num++;
	} 
	what_to_count |= COUNT_COUNTERS; /* we always count counters ;-) */
	count_index++;
      }
      break;
    case 'C':
      if (CHECK_Q_TYPE(q.type)) print_ex_options_error();
      q.type |= WANT_CLASS_TABLE;
      q.num = 1;
      want_class_table = TRUE;
      break;
    case 'U':
      if (CHECK_Q_TYPE(q.type)) print_ex_options_error();
      q.type |= WANT_CUSTOM_PRIMITIVES_TABLE;
      q.num = 1;
      want_custom_primitives_table = TRUE;
      break;
    case 'e':
      q.type |= WANT_ERASE; 
      want_erase = TRUE;
      break;
    case 'i':
      q.type |= WANT_ERASE_LAST_TSTAMP;
      want_erase_last_tstamp = TRUE;
      break;
    case 't':
      if (CHECK_Q_TYPE(q.type)) print_ex_options_error();
      q.type |= WANT_STATUS; 
      want_status = TRUE;
      break;
    case 'I':
      want_tstamp_since_epoch = TRUE;
      break;
    case '0':
      want_tstamp_utc = TRUE;
      break;
    case 'l':
      q.type |= WANT_LOCK_OP;
      break;
    case 'm': /* obsoleted */
      want_mrtg = TRUE;
      (void)want_mrtg;
    case 'N':
      if (CHECK_Q_TYPE(q.type)) print_ex_options_error();
      strlcpy(match_string, optarg, sizeof(match_string));
      match_string[LARGEBUFLEN-1] = '\0';
      q.type |= WANT_COUNTER; 
      want_counter = TRUE;
      break;
    case 'n':
      strlcpy(tmpbuf, optarg, sizeof(tmpbuf));
      pmc_lower_string(tmpbuf);
      if (!strcmp(tmpbuf, "bytes")) which_counter = 0;
      else if (!strcmp(tmpbuf, "packets")) which_counter = 1;
      else if (!strcmp(tmpbuf, "flows")) which_counter = 3;
      else if (!strcmp(tmpbuf, "all")) which_counter = 2;
      else printf("WARN: -n, ignoring unknown counter type: %s.\n", tmpbuf);
      break;
    case 'T':
      strlcpy(tmpbuf, optarg, sizeof(tmpbuf));
      pmc_lower_string(tmpbuf);
      topN_howmany_ptr = strchr(tmpbuf, ',');
      if (topN_howmany_ptr) {
	*topN_howmany_ptr = '\0';
	topN_howmany_ptr++;
	topN_howmany = strtoul(topN_howmany_ptr, &endptr, 10);
      }

      if (!strcmp(tmpbuf, "bytes")) topN_counter = 1;
      else if (!strcmp(tmpbuf, "packets")) topN_counter = 2;
      else if (!strcmp(tmpbuf, "flows")) topN_counter = 3;
      else printf("WARN: -T, ignoring unknown counter type: %s.\n", tmpbuf);
      break;
    case 'S':
      sum_counters = TRUE;
      break;
    case 'M':
      if (CHECK_Q_TYPE(q.type)) print_ex_options_error();
      strlcpy(match_string, optarg, sizeof(match_string));
      match_string[LARGEBUFLEN-1] = '\0';
      q.type |= WANT_MATCH;
      want_match = TRUE;
      break;
    case 'p':
      strlcpy(path, optarg, sizeof(path));
      break;
    case 'P':
      strlcpy(password, optarg, sizeof(password));
      break;
    case 'a':
      want_all_fields = TRUE;
      break;
    case 'r':
      q.type |= WANT_RESET;
      want_reset = TRUE;
      break;
    case 'O':
      strlcpy(tmpbuf, optarg, sizeof(tmpbuf));
      pmc_lower_string(tmpbuf);
      if (!strcmp(tmpbuf, "formatted"))
        want_output = PRINT_OUTPUT_FORMATTED;
      else if (!strcmp(tmpbuf, "csv"))
        want_output = PRINT_OUTPUT_CSV;
      else if (!strcmp(tmpbuf, "json")) {
#ifdef WITH_JANSSON
        want_output = PRINT_OUTPUT_JSON;
#else
        want_output = PRINT_OUTPUT_JSON;
        printf("WARN: -O set to json but will produce no output (missing --enable-jansson).\n");
#endif
      }
      else if (!strcmp(tmpbuf, "event_formatted")) {
	want_output = PRINT_OUTPUT_FORMATTED;
        want_output |= PRINT_OUTPUT_EVENT;
      }
      else if (!strcmp(tmpbuf, "event_csv")) {
	want_output = PRINT_OUTPUT_CSV;
        want_output |= PRINT_OUTPUT_EVENT;
      }
      else printf("WARN: -O, ignoring unknown output value: '%s'.\n", tmpbuf);
      break;
    case 'E':
      strlcpy(sep, optarg, sizeof(sep));
      break;
    case 'u':
      want_ipproto_num = TRUE;
      break;
    case 'h':
      usage_client(argv[0]);
      exit(0);
      break;
    case 'V':
      version_client(argv[0]);
      exit(0);
      break;
    default:
      printf("ERROR: parameter %c unknown! \n  Exiting...\n\n", cp);
      usage_client(argv[0]);
      exit(1);
      break;
    }
  }

  /* first off let's fetch the list of custom primitives
     loaded at the server we are connecting to */
  {
    struct query_header qhdr;

    memset(&qhdr, 0, sizeof(struct query_header));
    qhdr.type = WANT_CUSTOM_PRIMITIVES_TABLE;
    qhdr.num = 1;

    memcpy(clibuf, &qhdr, sizeof(struct query_header));
    buflen = sizeof(struct query_header);
    buflen++;
    clibuf[buflen] = '\x4'; /* EOT */
    buflen++;

    // XXX: transfer entry by entry like class tables
    assert(sizeof(struct imt_custom_primitives)+sizeof(struct query_header) < LARGEBUFLEN);
    sd = build_query_client(path);
    send(sd, clibuf, buflen, 0);
    unpacked = Recv(sd, &cpt);

    if (unpacked) {
      memcpy(&pmc_custom_primitives_registry, cpt+sizeof(struct query_header), sizeof(struct imt_custom_primitives));
  
      if (want_custom_primitives_table) {
        int idx;
  
        /* table header */
        printf("NAME                              ");
        printf("LEN    ");
        printf("OFF\n");
  
        for (idx = 0; idx < pmc_custom_primitives_registry.num; idx++) {
  	printf("%-32s  %-5u  %-5u\n", pmc_custom_primitives_registry.primitive[idx].name,
  		pmc_custom_primitives_registry.primitive[idx].len,
  		pmc_custom_primitives_registry.primitive[idx].off);
        }
  
        exit(1);
      }
  
      /* if we were invoked with -c, let's check we do not have unknown primitives */
      if (custom_primitives_input.num) {
        int idx, idx2, found;
  
        for (idx = 0; idx < custom_primitives_input.num; idx++) {
  	  found = FALSE;
  
          for (idx2 = 0; idx2 < pmc_custom_primitives_registry.num; idx2++) {
  	    if (!strcmp(custom_primitives_input.primitive[idx].name, pmc_custom_primitives_registry.primitive[idx2].name)) {
  	      found = TRUE;
  	      break;
  	    }  
  	  }
  
  	  if (!found) {
  	    printf("ERROR: unknown primitive '%s'\n", custom_primitives_input.primitive[idx].name);
  	    exit(1);
  	  }
        }
      }
    }
    else {
      printf("ERROR: missing EOF from server (1)\n");
      exit(1);
    }
  }

  /* some post-getopt-processing task */
  if (want_output & PRINT_OUTPUT_EVENT) is_event = TRUE;

  if (!q.type) {
    printf("ERROR: no options specified. Either -s, -e, -t, -M, -N or -C must be supplied. \n  Exiting...\n\n");
    usage_client(argv[0]);
    exit(1);
  }

  if ((want_counter || want_match) && (!what_to_count && !what_to_count_2)) {
    printf("ERROR: -N or -M selected but -c has not been specified or is invalid.\n  Exiting...\n\n");
    usage_client(argv[0]);
    exit(1);
  }

  if (want_reset && !(want_counter || want_match)) {
    printf("ERROR: -r selected but either -N or -M has not been specified.\n  Exiting...\n\n");
    usage_client(argv[0]);
    exit(1);
  }

  if ((which_counter||sum_counters) && !want_counter) {
    printf("ERROR: -n and -S options apply only to -N\n  Exiting...\n\n");
    usage_client(argv[0]);
    exit(1);
  }

  if (topN_counter && (!want_match && !want_stats)) {
    printf("ERROR: -T option apply only to -M or -s\n  Exiting...\n\n");
    usage_client(argv[0]);
    exit(1);
  }

  if (want_counter || want_match) {
    char *ptr = match_string, prefix[] = "file:";

    while(isspace(*ptr)) ptr++;
    if (!strncmp(ptr, prefix, strlen(prefix))) {
      fetch_from_file = TRUE; 
      ptr += strlen(prefix);
      strlcpy(file, ptr, sizeof(file)); 
    }
  }

  sep_len = strlen(sep);
  if (!sep_len) sep_ptr = default_sep;
  else if (sep_len == 1) sep_ptr = sep;
  else {
    if (!strcmp(sep, "\\t")) {
      spacing_sep[0] = '\t';
      spacing_sep[1] = '\0';
      sep_ptr = spacing_sep;
    }
    else if (!strcmp(sep, "\\s")) {
      spacing_sep[0] = ' ';
      spacing_sep[1] = '\0';
      sep_ptr = spacing_sep;
    }
    else {
      printf("ERROR: -E option expects a single char as separator\n  Exiting...\n\n");
      exit(1);
    }
  }

  memcpy(q.passwd, password, sizeof(password));

  /* setting number of entries in _protocols structure */
  while (_protocols[protocols_number].number != -1) protocols_number++;
  
  if (want_counter || want_match) {
    FILE *f;
    int strnum; 
    char **strings, *tptr1, *tptr2, tmpstr[SRVBUFLEN];
    char *tmpbuf, *tmpbufptr;
    
    /* 1st step: count how many queries we will have */
    if (!fetch_from_file) {
      for (strnum = 0, tptr1 = match_string; tptr1 && (strnum < MAX_QUERIES); strnum++) {
        tptr2 = tptr1;
        tptr1 = strchr(tptr1, ';'); 
        if (tptr1) {
	  if (*tptr2 == *tptr1) strnum--; /* void string */
	  tptr1++;
        }
      } 
    }
    else {
      if ((f = fopen(file, "r")) == NULL) {
        printf("ERROR: file '%s' not found\n", file);
        exit(1);
      }      
      else {
	strnum = 0;
	while (!feof(f) && (strnum < MAX_QUERIES)) {
	  if (fgets(tmpstr, SRVBUFLEN, f)) { 
	    if (!pmc_sanitize_buf(tmpstr)) strnum++;
	  }
	}
      }
    }

    strings = malloc((strnum+1)*sizeof(char *));
    if (!strings) {
      printf("ERROR: Unable to allocate sufficient memory.\n");
      exit(1); 
    }
    memset(strings, 0, (strnum+1)*sizeof(char *));

    if (fetch_from_file) {
      tmpbuf = malloc((strnum+1)*SRVBUFLEN);
      if (!tmpbuf) {
	printf("ERROR: Unable to allocate sufficient memory.\n");
	exit(1);
      }
      memset(tmpbuf, 0, (strnum+1)*SRVBUFLEN);
    }

    /* 2nd step: tokenize the whole string */
    if (!fetch_from_file) {
      for (strnum = 0, tptr1 = match_string; tptr1 && (strnum < MAX_QUERIES); strnum++) {
        tptr2 = tptr1;
        tptr1 = strchr(tptr1, ';');
        if (tptr1) *tptr1 = '\0';
        if (strlen(tptr2)) strings[strnum] = tptr2;
        else strnum--; /* void string */
        if (tptr1) tptr1++;
      }
    }
    else {
      if (!freopen(file, "r", f)) {
	printf("ERROR: freopen() failed: %s\n", strerror(errno));
	exit(1);
      }
      strnum = 0;
      tmpbufptr = tmpbuf;
      while (!feof(f) && (strnum < MAX_QUERIES)) {
        if (fgets(tmpbufptr, SRVBUFLEN, f)) {
	  tmpbufptr[SRVBUFLEN-1] = '\0';
	  if (!pmc_sanitize_buf(tmpbufptr)) {
	    strings[strnum] = tmpbufptr;
	    strnum++;
	    tmpbufptr += SRVBUFLEN;
	  }
        }
      }
      fclose(f);
    }

    bufptr = clibuf;
    bufptr += sizeof(struct query_header);
    
    /* 4th step: build queries */
    for (q.num = 0; (q.num < strnum) && (q.num < MAX_QUERIES); q.num++) {
      match_string_ptr = strings[q.num];
      match_string_index = 0;
      memset(&request, 0, sizeof(struct query_entry));
      request.what_to_count = what_to_count;
      request.what_to_count_2 = what_to_count_2;
      while ((*match_string_ptr != '\0') && (match_string_index < count_index))  {
        match_string_token = pmc_extract_token(&match_string_ptr, ',');

	/* Handling wildcards meaningfully */
	if (!strcmp(match_string_token, "*")) {
	  pm_cfgreg_t index = (count_token_int[match_string_index] >> COUNT_REGISTRY_BITS) & COUNT_INDEX_MASK;

          if (index == 1) request.what_to_count ^= count_token_int[match_string_index];
          else if (index == 2) request.what_to_count_2 ^= count_token_int[match_string_index];

	  match_string_index++;
	  continue;
	}

        if (!strcmp(count_token[match_string_index], "src_host") ||
            !strcmp(count_token[match_string_index], "sum_host")) {
          if (!str_to_addr(match_string_token, &request.data.src_ip)) {
            printf("ERROR: src_host: Invalid IP address: '%s'\n", match_string_token);
            exit(1);
          }
        }
        else if (!strcmp(count_token[match_string_index], "src_net") ||
	    !strcmp(count_token[match_string_index], "sum_net")) {
          if (!str_to_addr(match_string_token, &request.data.src_net)) {
            printf("ERROR: src_host: Invalid IP network: '%s'\n", match_string_token);
            exit(1);
          }
        }
        else if (!strcmp(count_token[match_string_index], "dst_host")) {
          if (!str_to_addr(match_string_token, &request.data.dst_ip)) {
            printf("ERROR: dst_host: Invalid IP address: '%s'\n", match_string_token);
            exit(1);
          }
        }
        else if (!strcmp(count_token[match_string_index], "dst_net")) {
          if (!str_to_addr(match_string_token, &request.data.dst_net)) {
            printf("ERROR: dst_host: Invalid IP network: '%s'\n", match_string_token);
            exit(1);
          }
        }
#if defined (HAVE_L2)
        else if (!strcmp(count_token[match_string_index], "src_mac") ||
		 !strcmp(count_token[match_string_index], "sum_mac")) {
          unsigned char ethaddr[ETH_ADDR_LEN];
	  int res;

          res = string_etheraddr(match_string_token, ethaddr);
	  if (res) {
	    printf("ERROR: src_mac: Invalid MAC address: '%s'\n", match_string_token);
            exit(1);
	  }
	  else memcpy(&request.data.eth_shost, ethaddr, ETH_ADDR_LEN);
        }
        else if (!strcmp(count_token[match_string_index], "dst_mac")) {
          unsigned char ethaddr[ETH_ADDR_LEN];
	  int res;

          res = string_etheraddr(match_string_token, ethaddr);
          if (res) {
            printf("ERROR: dst_mac: Invalid MAC address: '%s'\n", match_string_token);
            exit(1);
          }
          else memcpy(&request.data.eth_dhost, ethaddr, ETH_ADDR_LEN);
        }
        else if (!strcmp(count_token[match_string_index], "vlan")) {
	  request.data.vlan_id = atoi(match_string_token);
        }
        else if (!strcmp(count_token[match_string_index], "cos")) {
          request.data.cos = atoi(match_string_token);
        }
        else if (!strcmp(count_token[match_string_index], "etype")) {
	  sscanf(match_string_token, "%hx", &request.data.etype);
        }
#endif

        else if (!strcmp(count_token[match_string_index], "in_iface")) {
          char *endptr;

          request.data.ifindex_in = strtoul(match_string_token, &endptr, 10);
        }
        else if (!strcmp(count_token[match_string_index], "out_iface")) {
          char *endptr;

          request.data.ifindex_out = strtoul(match_string_token, &endptr, 10);
        }

        else if (!strcmp(count_token[match_string_index], "src_mask")) {
          char *endptr;
	  u_int32_t src_mask;

	  src_mask = strtoul(match_string_token, &endptr, 10);
          request.data.src_nmask = src_mask;
        }
        else if (!strcmp(count_token[match_string_index], "dst_mask")) {
          char *endptr;
	  u_int32_t dst_mask;

          dst_mask = strtoul(match_string_token, &endptr, 10);
	  request.data.dst_nmask = dst_mask;
        }

        else if (!strcmp(count_token[match_string_index], "src_port") ||
		 !strcmp(count_token[match_string_index], "sum_port")) { 
          request.data.src_port = atoi(match_string_token);
        }
        else if (!strcmp(count_token[match_string_index], "dst_port")) {
          request.data.dst_port = atoi(match_string_token);
        }
	else if (!strcmp(count_token[match_string_index], "tos")) {
	  tmpnum = atoi(match_string_token);
	  request.data.tos = (u_int8_t) tmpnum; 
	}
#if defined WITH_GEOIP
        else if (!strcmp(count_token[match_string_index], "src_host_country")) {
          request.data.src_ip_country.id = GeoIP_id_by_code(match_string_token);
        }
        else if (!strcmp(count_token[match_string_index], "dst_host_country")) {
          request.data.dst_ip_country.id = GeoIP_id_by_code(match_string_token);
        }
#endif
#if defined WITH_GEOIPV2
        else if (!strcmp(count_token[match_string_index], "src_host_country")) {
          strlcpy(request.data.src_ip_country.str, match_string_token, PM_COUNTRY_T_STRLEN);
        }
        else if (!strcmp(count_token[match_string_index], "dst_host_country")) {
          strlcpy(request.data.dst_ip_country.str, match_string_token, PM_COUNTRY_T_STRLEN);
        }
        else if (!strcmp(count_token[match_string_index], "src_host_pocode")) {
          strlcpy(request.data.src_ip_pocode.str, match_string_token, PM_POCODE_T_STRLEN);
        }
        else if (!strcmp(count_token[match_string_index], "dst_host_pocode")) {
          strlcpy(request.data.dst_ip_pocode.str, match_string_token, PM_POCODE_T_STRLEN);
        }
        else if (!strcmp(count_token[match_string_index], "src_host_coords")) {
	  char *lat_token, *lon_token, *coord_str = strdup(match_string_token), coord_delim[] = ":";

	  lat_token = strtok(coord_str, coord_delim);
	  lon_token = strtok(NULL, coord_delim);

	  if (!lat_token || !lon_token) {
	    printf("ERROR: src_host_coords: Invalid coordinates: '%s'.\n", match_string_token);
	    printf("ERROR: Expected format: <latitude>:<longitude>\n");
            exit(1);
	  }

	  request.data.src_ip_lat = atof(lat_token);
	  request.data.src_ip_lon = atof(lon_token);

	  free(coord_str);
	}
        else if (!strcmp(count_token[match_string_index], "dst_host_coords")) {
	  char *lat_token, *lon_token, *coord_str = strdup(match_string_token), coord_delim[] = ":";

	  lat_token = strtok(coord_str, coord_delim);
	  lon_token = strtok(NULL, coord_delim);

	  if (!lat_token || !lon_token) {
	    printf("ERROR: dst_host_coords: Invalid coordinates: '%s'.\n", match_string_token);
	    printf("ERROR: Expected format: <latitude>:<longitude>\n");
            exit(1);
	  }

	  request.data.dst_ip_lat = atof(lat_token);
	  request.data.dst_ip_lon = atof(lon_token);

	  free(coord_str);
	}
#endif
	else if (!strcmp(count_token[match_string_index], "sampling_rate")) {
	  request.data.sampling_rate = atoi(match_string_token);
	}
	else if (!strcmp(count_token[match_string_index], "sampling_direction")) {
	  strlcpy(request.data.sampling_direction, match_string_token, sizeof(request.data.sampling_direction));
	}
        else if (!strcmp(count_token[match_string_index], "proto")) {
	  int proto = 0;

	  if (!want_ipproto_num) {
	    for (index = 0; _protocols[index].number != -1; index++) { 
	      if (!strcmp(_protocols[index].name, match_string_token)) {
	        proto = _protocols[index].number;
	        break;
	      }
	    }
	    if (proto <= 0) {
	      proto = atoi(match_string_token);
	      if ((proto <= 0) || (proto > 255)) {
	        printf("ERROR: invalid protocol: '%s'\n", match_string_token);
	        exit(1);
	      }
	    }
	  }
	  else {
	    proto = atoi(match_string_token); 
            if ((proto <= 0) || (proto > 255)) {
              printf("ERROR: invalid protocol: '%s'\n", match_string_token);
              exit(1);
            }
	  }
	  request.data.proto = proto;
        }
	else if (!strcmp(count_token[match_string_index], "none"));
	else if (!strcmp(count_token[match_string_index], "src_as") ||
		 !strcmp(count_token[match_string_index], "sum_as")) {
	  char *endptr;

	  request.data.src_as = strtoul(match_string_token, &endptr, 10);
	}
	else if (!strcmp(count_token[match_string_index], "dst_as")) {
	  char *endptr;

	  request.data.dst_as = strtoul(match_string_token, &endptr, 10);
	}
	else if (!strcmp(count_token[match_string_index], "tag")) {
	  char *endptr = NULL;
	  u_int32_t value;

	  value = strtoull(match_string_token, &endptr, 10);
	  request.data.tag = value; 
	}
        else if (!strcmp(count_token[match_string_index], "tag2")) {
          char *endptr = NULL;
          u_int32_t value;

          value = strtoull(match_string_token, &endptr, 10);
          request.data.tag2 = value;
        }
        else if (!strcmp(count_token[match_string_index], "class")) {
	  struct query_header qhdr;
	  char sclass[MAX_PROTOCOL_LEN];
	  pm_class_t value = 0;

	  memset(sclass, 0, sizeof(sclass));
	  strlcpy(sclass, match_string_token, MAX_PROTOCOL_LEN); 
	  sclass[MAX_PROTOCOL_LEN-1] = '\0';

	  if (!strcmp("unknown", sclass)) request.data.class = 0;
	  else {
	    memset(&qhdr, 0, sizeof(struct query_header));
	    qhdr.type = WANT_CLASS_TABLE;
	    qhdr.num = 1;

	    memcpy(clibuf, &qhdr, sizeof(struct query_header));
	    buflen = sizeof(struct query_header);
	    buflen++;
	    clibuf[buflen] = '\x4'; /* EOT */
	    buflen++;

	    sd = build_query_client(path);
	    send(sd, clibuf, buflen, 0);
	    unpacked = Recv(sd, &ct);

	    if (unpacked) {
  	      ct_num = ((struct query_header *)ct)->num;
  	      elem = ct+sizeof(struct query_header);
  	      class_table = (struct stripped_class *) elem;
  	      ct_idx = 0;
  	      while (ct_idx < ct_num) {
  	        class_table[ct_idx].protocol[MAX_PROTOCOL_LEN-1] = '\0';
  	        if (!strcmp(class_table[ct_idx].protocol, sclass)) {
  	          value = class_table[ct_idx].id;
  		  break;
  	        }
  	        ct_idx++;
  	      }
  
  	      if (!value) {
  	        printf("ERROR: Server has not loaded any classifier for '%s'.\n", sclass);
  	        exit(1); 
  	      }
  	      else request.data.class = value;
            }
	    else {
	      printf("ERROR: missing EOF from server (2)\n");
	      exit(1);
	    }
	  }
        }
        else if (!strcmp(count_token[match_string_index], "std_comm")) {
	  if (!strcmp(match_string_token, "0"))
	    memset(request.plbgp.std_comms, 0, MAX_BGP_STD_COMMS);
	  else {
            strlcpy(request.plbgp.std_comms, match_string_token, MAX_BGP_STD_COMMS);
	    bgp_comm = request.plbgp.std_comms;
	    while (bgp_comm) {
	      bgp_comm = strchr(request.plbgp.std_comms, '_');
	      if (bgp_comm) *bgp_comm = ' ';
	    }
	  }
	}
        else if (!strcmp(count_token[match_string_index], "src_std_comm")) {
          if (!strcmp(match_string_token, "0"))
            memset(request.plbgp.src_std_comms, 0, MAX_BGP_STD_COMMS);
          else {
            strlcpy(request.plbgp.src_std_comms, match_string_token, MAX_BGP_STD_COMMS);
            bgp_comm = request.plbgp.src_std_comms;
            while (bgp_comm) {
              bgp_comm = strchr(request.plbgp.src_std_comms, '_');
              if (bgp_comm) *bgp_comm = ' ';
            }
          }
        }
        else if (!strcmp(count_token[match_string_index], "ext_comm")) {
          if (!strcmp(match_string_token, "0"))
            memset(request.plbgp.ext_comms, 0, MAX_BGP_EXT_COMMS);
          else {
            strlcpy(request.plbgp.ext_comms, match_string_token, MAX_BGP_EXT_COMMS);
            bgp_comm = request.plbgp.ext_comms;
            while (bgp_comm) {
              bgp_comm = strchr(request.plbgp.ext_comms, '_');
              if (bgp_comm) *bgp_comm = ' ';
            }
	  }
	}
        else if (!strcmp(count_token[match_string_index], "src_ext_comm")) {
          if (!strcmp(match_string_token, "0"))
            memset(request.plbgp.src_ext_comms, 0, MAX_BGP_EXT_COMMS);
          else {
            strlcpy(request.plbgp.src_ext_comms, match_string_token, MAX_BGP_EXT_COMMS);
            bgp_comm = request.plbgp.src_ext_comms;
            while (bgp_comm) {
              bgp_comm = strchr(request.plbgp.src_ext_comms, '_');
              if (bgp_comm) *bgp_comm = ' ';
            }
          }
        }
        else if (!strcmp(count_token[match_string_index], "lrg_comm")) {
          if (!strcmp(match_string_token, "0"))
            memset(request.plbgp.lrg_comms, 0, MAX_BGP_LRG_COMMS);
          else {
            strlcpy(request.plbgp.lrg_comms, match_string_token, MAX_BGP_LRG_COMMS);
            bgp_comm = request.plbgp.lrg_comms;
            while (bgp_comm) {
              bgp_comm = strchr(request.plbgp.lrg_comms, '_');
              if (bgp_comm) *bgp_comm = ' ';
            }
          }
        }
        else if (!strcmp(count_token[match_string_index], "src_lrg_comm")) {
          if (!strcmp(match_string_token, "0"))
            memset(request.plbgp.src_lrg_comms, 0, MAX_BGP_LRG_COMMS);
          else {
            strlcpy(request.plbgp.src_lrg_comms, match_string_token, MAX_BGP_LRG_COMMS);
            bgp_comm = request.plbgp.src_lrg_comms;
            while (bgp_comm) {
              bgp_comm = strchr(request.plbgp.src_lrg_comms, '_');
              if (bgp_comm) *bgp_comm = ' ';
            }
          }
        }
        else if (!strcmp(count_token[match_string_index], "as_path")) {
	  if (!strcmp(match_string_token, "^$"))
	    memset(request.plbgp.as_path, 0, MAX_BGP_ASPATH);
	  else {
            strlcpy(request.plbgp.as_path, match_string_token, MAX_BGP_ASPATH);
            as_path = request.plbgp.as_path;
            while (as_path) {
              as_path = strchr(request.plbgp.as_path, '_');
              if (as_path) *as_path = ' ';
            }
	  }
	}
        else if (!strcmp(count_token[match_string_index], "src_as_path")) {
          if (!strcmp(match_string_token, "^$"))
            memset(request.plbgp.src_as_path, 0, MAX_BGP_ASPATH);
          else {
            strlcpy(request.plbgp.src_as_path, match_string_token, MAX_BGP_ASPATH);
            as_path = request.plbgp.src_as_path;
            while (as_path) {
              as_path = strchr(request.plbgp.src_as_path, '_');
              if (as_path) *as_path = ' ';
            }
          }
        }
        else if (!strcmp(count_token[match_string_index], "local_pref")) {
	  char *endptr;

          request.pbgp.local_pref = strtoul(match_string_token, &endptr, 10);
	}
        else if (!strcmp(count_token[match_string_index], "src_local_pref")) {
          char *endptr;

          request.pbgp.src_local_pref = strtoul(match_string_token, &endptr, 10);
        }
        else if (!strcmp(count_token[match_string_index], "med")) {
	  char *endptr;

          request.pbgp.med = strtoul(match_string_token, &endptr, 10);
	}
        else if (!strcmp(count_token[match_string_index], "src_med")) {
          char *endptr;

          request.pbgp.src_med = strtoul(match_string_token, &endptr, 10);
        }
        else if (!strcmp(count_token[match_string_index], "src_roa")) {
          request.pbgp.src_roa = pmc_rpki_str2roa(match_string_token);
        }
        else if (!strcmp(count_token[match_string_index], "dst_roa")) {
          request.pbgp.dst_roa = pmc_rpki_str2roa(match_string_token);
	}
        else if (!strcmp(count_token[match_string_index], "peer_src_as")) {
          char *endptr;

          request.pbgp.peer_src_as = strtoul(match_string_token, &endptr, 10);
        }
        else if (!strcmp(count_token[match_string_index], "peer_dst_as")) {
          char *endptr;

          request.pbgp.peer_dst_as = strtoul(match_string_token, &endptr, 10);
        }
        else if (!strcmp(count_token[match_string_index], "peer_src_ip")) {
          if (!str_to_addr(match_string_token, &request.pbgp.peer_src_ip)) {
            printf("ERROR: peer_src_ip: Invalid IP address: '%s'\n", match_string_token);
            exit(1);
          }
        }
        else if (!strcmp(count_token[match_string_index], "peer_dst_ip")) {
          if (!str_to_addr(match_string_token, &request.pbgp.peer_dst_ip)) {
            printf("ERROR: peer_dst_ip: Invalid IP address: '%s'\n", match_string_token);
            exit(1);
          }
        }
        else if (!strcmp(count_token[match_string_index], "mpls_vpn_rd")) {
	  if (!pmc_bgp_str2rd((rd_t *) &request.pbgp.mpls_vpn_rd, match_string_token)) {
            printf("ERROR: mpls_vpn_rd: Invalid MPLS VPN RD value: '%s'\n", match_string_token);
            exit(1);
          }
        }
        else if (!strcmp(count_token[match_string_index], "mpls_pw_id")) {
          char *endptr;

          request.pbgp.mpls_pw_id = strtoul(match_string_token, &endptr, 10);
        }
        else if (!strcmp(count_token[match_string_index], "post_nat_src_host")) {
          if (!str_to_addr(match_string_token, &request.pnat.post_nat_src_ip)) {
            printf("ERROR: post_nat_src_host: Invalid IP address: '%s'\n", match_string_token);
            exit(1);
          }
        }
        else if (!strcmp(count_token[match_string_index], "post_nat_dst_host")) {
          if (!str_to_addr(match_string_token, &request.pnat.post_nat_dst_ip)) {
            printf("ERROR: post_nat_dst_host: Invalid IP address: '%s'\n", match_string_token);
            exit(1);
          }
        }
        else if (!strcmp(count_token[match_string_index], "post_nat_src_port")) {
          request.pnat.post_nat_src_port = atoi(match_string_token);
        }
        else if (!strcmp(count_token[match_string_index], "post_nat_dst_port")) {
          request.pnat.post_nat_dst_port = atoi(match_string_token);
        }
        else if (!strcmp(count_token[match_string_index], "nat_event")) {
          request.pnat.nat_event = atoi(match_string_token);
        }
        else if (!strcmp(count_token[match_string_index], "mpls_label_top")) {
	  request.pmpls.mpls_label_top = atoi(match_string_token);
        }
        else if (!strcmp(count_token[match_string_index], "mpls_label_bottom")) {
	  request.pmpls.mpls_label_bottom = atoi(match_string_token);
        }
        else if (!strcmp(count_token[match_string_index], "mpls_stack_depth")) {
          request.pmpls.mpls_stack_depth = atoi(match_string_token);
        }
        else if (!strcmp(count_token[match_string_index], "tunnel_src_mac")) {
          unsigned char ethaddr[ETH_ADDR_LEN];
          int res;

          res = string_etheraddr(match_string_token, ethaddr);
          if (res) {
            printf("ERROR: tunnel_src_mac: Invalid MAC address: '%s'\n", match_string_token);
            exit(1);
          }
          else memcpy(&request.ptun.tunnel_eth_shost, ethaddr, ETH_ADDR_LEN);
        }
        else if (!strcmp(count_token[match_string_index], "tunnel_dst_mac")) {
          unsigned char ethaddr[ETH_ADDR_LEN];
          int res;

          res = string_etheraddr(match_string_token, ethaddr);
          if (res) {
            printf("ERROR: tunnel_dst_mac: Invalid MAC address: '%s'\n", match_string_token);
            exit(1);
          }
          else memcpy(&request.ptun.tunnel_eth_dhost, ethaddr, ETH_ADDR_LEN);
        }
        else if (!strcmp(count_token[match_string_index], "tunnel_src_host")) {
          if (!str_to_addr(match_string_token, &request.ptun.tunnel_src_ip)) {
            printf("ERROR: tunnel_src_host: Invalid IP address: '%s'\n", match_string_token);
            exit(1);
          }
        }
        else if (!strcmp(count_token[match_string_index], "tunnel_dst_host")) {
          if (!str_to_addr(match_string_token, &request.ptun.tunnel_dst_ip)) {
            printf("ERROR: tunnel_dst_host: Invalid IP address: '%s'\n", match_string_token);
            exit(1);
          }
        }
        else if (!strcmp(count_token[match_string_index], "tunnel_proto")) {
	  int proto = 0;

	  if (!want_ipproto_num) {
	    for (index = 0; _protocols[index].number != -1; index++) { 
	      if (!strcmp(_protocols[index].name, match_string_token)) {
	        proto = _protocols[index].number;
	        break;
	      }
	    }
	    if (proto <= 0) {
	      proto = atoi(match_string_token);
	      if ((proto <= 0) || (proto > 255)) {
	        printf("ERROR: invalid protocol: '%s'\n", match_string_token);
	        exit(1);
	      }
	    }
	  }
	  else {
	    proto = atoi(match_string_token); 
            if ((proto <= 0) || (proto > 255)) {
              printf("ERROR: invalid protocol: '%s'\n", match_string_token);
              exit(1);
            }
	  }
	  request.ptun.tunnel_proto = proto;
        }
	else if (!strcmp(count_token[match_string_index], "tunnel_tos")) {
	  tmpnum = atoi(match_string_token);
	  request.ptun.tunnel_tos = (u_int8_t) tmpnum; 
	}
        else if (!strcmp(count_token[match_string_index], "tunnel_src_port")) {
          request.ptun.tunnel_src_port = atoi(match_string_token);
        }
        else if (!strcmp(count_token[match_string_index], "tunnel_dst_port")) {
          request.ptun.tunnel_dst_port = atoi(match_string_token);
        }
	else if (!strcmp(count_token[match_string_index], "vxlan")) {
	  tmpnum = atoi(match_string_token);
	  request.ptun.tunnel_id = tmpnum;
	}
        else if (!strcmp(count_token[match_string_index], "timestamp_start")) {
	  struct tm tmp;
	  char *delim = strchr(match_string_token, '.');
	  u_int32_t residual = 0;

	  if (delim) {
	    /* we have residual time after secs */
	    *delim = '\0';
	    delim++;
	    residual = strtol(delim, NULL, 0); 
	  }

	  strptime(match_string_token, "%Y-%m-%dT%H:%M:%S", &tmp);
	  request.pnat.timestamp_start.tv_sec = mktime(&tmp);
	  request.pnat.timestamp_start.tv_usec = residual;
        }
        else if (!strcmp(count_token[match_string_index], "timestamp_end")) {
	  struct tm tmp;
          char *delim = strchr(match_string_token, '.');
          u_int32_t residual = 0;

          if (delim) {
            /* we have residual time after secs */
            *delim = '\0';
            delim++;
            residual = strtol(delim, NULL, 0);
          }

	  strptime(match_string_token, "%Y-%m-%dT%H:%M:%S", &tmp);
	  request.pnat.timestamp_end.tv_sec = mktime(&tmp);
	  request.pnat.timestamp_end.tv_usec = residual;
        }
        else if (!strcmp(count_token[match_string_index], "timestamp_arrival")) {
          struct tm tmp;
          char *delim = strchr(match_string_token, '.');
          u_int32_t residual = 0;

          if (delim) {
            /* we have residual time after secs */
            *delim = '\0';
            delim++;
            residual = strtol(delim, NULL, 0);
          }

          strptime(match_string_token, "%Y-%m-%dT%H:%M:%S", &tmp);
          request.pnat.timestamp_arrival.tv_sec = mktime(&tmp);
          request.pnat.timestamp_arrival.tv_usec = residual;
        }
        else if (!strcmp(count_token[match_string_index], "export_proto_seqno")) {
          char *endptr;

          request.data.export_proto_seqno = strtoul(match_string_token, &endptr, 10);
        }
        else if (!strcmp(count_token[match_string_index], "export_proto_version")) {
          char *endptr;

          request.data.export_proto_version = strtoul(match_string_token, &endptr, 10);
        }
        else if (!strcmp(count_token[match_string_index], "export_proto_sysid")) {
          char *endptr;

          request.data.export_proto_sysid = strtoul(match_string_token, &endptr, 10);
        }
	else if (!strcmp(count_token[match_string_index], "label")) {
	  // XXX: to be supported in future
          printf("ERROR: -M and -N are not supported (yet) against variable-length primitives (ie. label)\n");
          exit(1);
	}
        else {
	  int idx, found;

	  for (idx = 0, found = FALSE; idx < pmc_custom_primitives_registry.num; idx++) {
            if (!strcmp(count_token[match_string_index], pmc_custom_primitives_registry.primitive[idx].name)) {
              found = TRUE;
              break;
            }
          }

          if (!found) {
            printf("ERROR: unknown primitive '%s'\n", count_token[match_string_index]);
            exit(1);
          }
	  else {
	    // XXX: to be supported in future
            printf("ERROR: -M and -N are not supported (yet) against custom primitives\n");
            exit(1);
	  }
        }
        match_string_index++;
      }

      memcpy(bufptr, &request, sizeof(struct query_entry));
      bufptr += sizeof(struct query_entry);
    }
  }

  /* arranging header and size of buffer to send */
  memcpy(clibuf, &q, sizeof(struct query_header)); 
  buflen = sizeof(struct query_header)+(q.num*sizeof(struct query_entry));
  buflen++;
  clibuf[buflen] = '\x4'; /* EOT */
  buflen++;

  sd = build_query_client(path);
  send(sd, clibuf, buflen, 0);

  /* reading results */ 
  if (want_stats || want_match) {
    unpacked = Recv(sd, &largebuf);
 
    if (!unpacked) {
      printf("ERROR: missing EOF from server (4)\n");
      exit(1);
    }

    if (want_all_fields) have_wtc = FALSE; 
    else have_wtc = TRUE; 
    what_to_count = ((struct query_header *)largebuf)->what_to_count;
    what_to_count_2 = ((struct query_header *)largebuf)->what_to_count_2;
    datasize = ((struct query_header *)largebuf)->datasize;
    memcpy(&extras, &((struct query_header *)largebuf)->extras, sizeof(struct extra_primitives));
    if (check_data_sizes((struct query_header *)largebuf, acc_elem)) exit(1);

    /* Before going on with the output, we need to retrieve the class strings
       from the server */
    if (((what_to_count & COUNT_CLASS) || (what_to_count_2 & COUNT_NDPI_CLASS)) && !class_table) {
      struct query_header qhdr;
      int unpacked_class;

      memset(&qhdr, 0, sizeof(struct query_header));
      qhdr.type = WANT_CLASS_TABLE;
      qhdr.num = 1;

      memcpy(clibuf, &qhdr, sizeof(struct query_header));
      buflen = sizeof(struct query_header);
      buflen++;
      clibuf[buflen] = '\x4'; /* EOT */
      buflen++;

      sd = build_query_client(path);
      send(sd, clibuf, buflen, 0);
      unpacked_class = Recv(sd, &ct); 

      if (unpacked_class) {
        ct_num = ((struct query_header *)ct)->num;
        elem = ct+sizeof(struct query_header);
        class_table = (struct stripped_class *) elem;
        while (ct_idx < ct_num) {
	  class_table[ct_idx].protocol[MAX_PROTOCOL_LEN-1] = '\0';
          ct_idx++;
        }
      }
      else {
	printf("ERROR: missing EOF from server (5)\n");
	exit(1);
      }
    }

    if (want_output & PRINT_OUTPUT_FORMATTED)
      write_stats_header_formatted(what_to_count, what_to_count_2, have_wtc, is_event);
    else if (want_output & PRINT_OUTPUT_CSV)
      write_stats_header_csv(what_to_count, what_to_count_2, have_wtc, sep_ptr, is_event);

    elem = largebuf+sizeof(struct query_header);
    unpacked -= sizeof(struct query_header);

    acc_elem = (struct pkt_data *) elem;

    topN_printed = 0;
    if (topN_counter) {
      int num = unpacked/datasize;

      client_counters_merge_sort((void *)acc_elem, 0, num, datasize, topN_counter);
    }

    while (printed < unpacked && (!topN_howmany || topN_printed < topN_howmany)) {
      int count = 0;

      topN_printed++;
      acc_elem = (struct pkt_data *) elem;

      if (extras.off_pkt_bgp_primitives) pbgp = (struct pkt_bgp_primitives *) ((u_char *)elem + extras.off_pkt_bgp_primitives);
      else pbgp = &empty_pbgp;

      if (extras.off_pkt_lbgp_primitives) plbgp = (struct pkt_legacy_bgp_primitives *) ((u_char *)elem + extras.off_pkt_lbgp_primitives);
      else plbgp = &empty_plbgp;

      if (extras.off_pkt_nat_primitives) pnat = (struct pkt_nat_primitives *) ((u_char *)elem + extras.off_pkt_nat_primitives);
      else pnat = &empty_pnat;

      if (extras.off_pkt_mpls_primitives) pmpls = (struct pkt_mpls_primitives *) ((u_char *)elem + extras.off_pkt_mpls_primitives);
      else pmpls = &empty_pmpls;

      if (extras.off_pkt_tun_primitives) ptun = (struct pkt_tunnel_primitives *) ((u_char *)elem + extras.off_pkt_tun_primitives);
      else ptun = &empty_ptun;

      if (extras.off_custom_primitives) pcust = ((u_char *)elem + extras.off_custom_primitives);
      else pcust = NULL;

      if (extras.off_pkt_vlen_hdr_primitives) pvlen = (struct pkt_vlen_hdr_primitives *) ((u_char *)elem + extras.off_pkt_vlen_hdr_primitives);
      else pvlen = &empty_pvlen;

      if (memcmp(acc_elem, &empty_addr, sizeof(struct pkt_primitives)) != 0 || 
	  memcmp(pbgp, &empty_pbgp, sizeof(struct pkt_bgp_primitives)) != 0 ||
	  memcmp(plbgp, &empty_plbgp, sizeof(struct pkt_legacy_bgp_primitives)) != 0 ||
	  memcmp(pnat, &empty_pnat, sizeof(struct pkt_nat_primitives)) != 0 ||
	  memcmp(pmpls, &empty_pmpls, sizeof(struct pkt_mpls_primitives)) != 0 ||
	  memcmp(ptun, &empty_ptun, sizeof(struct pkt_tunnel_primitives)) != 0 ||
	  pmc_custom_primitives_registry.len ||
	  memcmp(pvlen, &empty_pvlen, sizeof(struct pkt_vlen_hdr_primitives)) != 0) {
        if (!have_wtc || (what_to_count & COUNT_TAG)) {
	  if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-10" PRIu64 "  ", acc_elem->primitives.tag);
	  else if (want_output & PRINT_OUTPUT_CSV) printf("%s%" PRIu64 "", write_sep(sep_ptr, &count), acc_elem->primitives.tag);
	}

        if (!have_wtc || (what_to_count & COUNT_TAG2)) {
	  if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-10" PRIu64 "  ", acc_elem->primitives.tag2);
	  else if (want_output & PRINT_OUTPUT_CSV) printf("%s%" PRIu64 "", write_sep(sep_ptr, &count), acc_elem->primitives.tag2);
	}

        if (!have_wtc || (what_to_count & COUNT_CLASS)) {
          if (want_output & PRINT_OUTPUT_FORMATTED)
	    printf("%-16s  ", (acc_elem->primitives.class == 0 || acc_elem->primitives.class > ct_idx ||
				!class_table[acc_elem->primitives.class-1].id) ? "unknown" : class_table[acc_elem->primitives.class-1].protocol);
          else if (want_output & PRINT_OUTPUT_CSV)
	    printf("%s%s", write_sep(sep_ptr, &count),
				(acc_elem->primitives.class == 0 || acc_elem->primitives.class > ct_idx ||
				!class_table[acc_elem->primitives.class-1].id) ? "unknown" : class_table[acc_elem->primitives.class-1].protocol);
	}

#if defined (WITH_NDPI)
	if (!have_wtc || (what_to_count_2 & COUNT_NDPI_CLASS)) {
	  snprintf(ndpi_class, SUPERSHORTBUFLEN, "%s/%s",
		pmc_ndpi_get_proto_name(acc_elem->primitives.ndpi_class.master_protocol),
		pmc_ndpi_get_proto_name(acc_elem->primitives.ndpi_class.app_protocol));

	  if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-16s  ", ndpi_class); 
	  else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), ndpi_class);
	}
#endif

        if (!have_wtc || (what_to_count_2 & COUNT_LABEL)) {
          if (want_output & PRINT_OUTPUT_FORMATTED); /* case not supported */
          else if (want_output & PRINT_OUTPUT_CSV) pmc_printf_csv_label(pvlen, COUNT_INT_LABEL, write_sep(sep_ptr, &count), empty_string);
        }

        if (!have_wtc || (what_to_count & COUNT_IN_IFACE)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-10u  ", acc_elem->primitives.ifindex_in);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), acc_elem->primitives.ifindex_in);
        }
        if (!have_wtc || (what_to_count & COUNT_OUT_IFACE)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-10u  ", acc_elem->primitives.ifindex_out);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), acc_elem->primitives.ifindex_out);
        }

#if defined (HAVE_L2)
	if (!have_wtc || (what_to_count & (COUNT_SRC_MAC|COUNT_SUM_MAC))) {
	  etheraddr_string(acc_elem->primitives.eth_shost, ethernet_address);
	  if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-17s  ", ethernet_address);
	  else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), ethernet_address);
	}

	if (!have_wtc || (what_to_count & COUNT_DST_MAC)) {
	  etheraddr_string(acc_elem->primitives.eth_dhost, ethernet_address);
	  if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-17s  ", ethernet_address);
	  else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), ethernet_address);
	} 

	if (!have_wtc || (what_to_count & COUNT_VLAN)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-5u  ", acc_elem->primitives.vlan_id);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), acc_elem->primitives.vlan_id);
        }

        if (!have_wtc || (what_to_count & COUNT_COS)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-2u  ", acc_elem->primitives.cos);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), acc_elem->primitives.cos);
        }
        if (!have_wtc || (what_to_count & COUNT_ETHERTYPE)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-5x  ", acc_elem->primitives.etype);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%x", write_sep(sep_ptr, &count), acc_elem->primitives.etype);
        }
#endif
	if (!have_wtc || (what_to_count & (COUNT_SRC_AS|COUNT_SUM_AS))) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-10u  ", acc_elem->primitives.src_as);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), acc_elem->primitives.src_as);
        }

	if (!have_wtc || (what_to_count & COUNT_DST_AS)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-10u  ", acc_elem->primitives.dst_as);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), acc_elem->primitives.dst_as);
        }

	if (!have_wtc || (what_to_count & COUNT_STD_COMM)) {
	  bgp_comm = plbgp->std_comms;
	  while (bgp_comm) {
	    bgp_comm = strchr(plbgp->std_comms, ' ');
	    if (bgp_comm) *bgp_comm = '_';
	  }
          if (strlen(plbgp->std_comms)) {
	    if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-22s   ", plbgp->std_comms);
	    else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), plbgp->std_comms);
	  }
	  else {
	    if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-22u   ", 0);
	    else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), empty_string);
	  }
        }

	if (!have_wtc || (what_to_count & COUNT_SRC_STD_COMM)) {
	  bgp_comm = plbgp->src_std_comms;
	  while (bgp_comm) {
	    bgp_comm = strchr(plbgp->src_std_comms, ' ');
	    if (bgp_comm) *bgp_comm = '_';
	  }
          if (strlen(plbgp->src_std_comms)) {
	    if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-22s   ", plbgp->src_std_comms);
	    else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), plbgp->src_std_comms);
	  }
	  else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-22u   ", 0);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), empty_string);
	  }
        }

        if (what_to_count & COUNT_EXT_COMM) {
          bgp_comm = plbgp->ext_comms;
          while (bgp_comm) {
            bgp_comm = strchr(plbgp->ext_comms, ' ');
            if (bgp_comm) *bgp_comm = '_';
          }
          if (strlen(plbgp->ext_comms)) {
	    if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-22s   ", plbgp->ext_comms);
	    else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), plbgp->ext_comms);
	  }
	  else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-22u   ", 0);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), empty_string);
	  }
        }

        if (what_to_count & COUNT_SRC_EXT_COMM) {
          bgp_comm = plbgp->src_ext_comms;
          while (bgp_comm) {
            bgp_comm = strchr(plbgp->src_ext_comms, ' ');
            if (bgp_comm) *bgp_comm = '_';
          }
          if (strlen(plbgp->src_ext_comms)) {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-22s   ", plbgp->src_ext_comms);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), plbgp->src_ext_comms);
	  }
          else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-22u   ", 0);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), empty_string);
          }
        }

        if (what_to_count_2 & COUNT_LRG_COMM) {
          bgp_comm = plbgp->lrg_comms;
          while (bgp_comm) {
            bgp_comm = strchr(plbgp->lrg_comms, ' ');
            if (bgp_comm) *bgp_comm = '_';
          }
          if (strlen(plbgp->lrg_comms)) {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-22s   ", plbgp->lrg_comms);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), plbgp->lrg_comms);
          }
          else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-22u   ", 0);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), empty_string);
          }
        }

        if (what_to_count_2 & COUNT_SRC_LRG_COMM) {
          bgp_comm = plbgp->src_lrg_comms;
          while (bgp_comm) {
            bgp_comm = strchr(plbgp->src_lrg_comms, ' ');
            if (bgp_comm) *bgp_comm = '_';
          }
          if (strlen(plbgp->src_lrg_comms)) {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-22s   ", plbgp->src_lrg_comms);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), plbgp->src_lrg_comms);
          }
          else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-22u   ", 0);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), empty_string);
          }
        }

        if (!have_wtc || (what_to_count & COUNT_AS_PATH)) {
	  as_path = plbgp->as_path;
	  while (as_path) {
	    as_path = strchr(plbgp->as_path, ' ');
	    if (as_path) *as_path = '_';
	  }
          if (strlen(plbgp->as_path)) {
	    if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-22s   ", plbgp->as_path);
	    else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), plbgp->as_path);
	  }
	  else {
	    if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-22s   ", empty_aspath); 
	    else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), plbgp->as_path); 
	  }
        }

        if (!have_wtc || (what_to_count & COUNT_SRC_AS_PATH)) {
	  as_path = plbgp->src_as_path;
	  while (as_path) {
	    as_path = strchr(plbgp->src_as_path, ' ');
	    if (as_path) *as_path = '_';
	  }
          if (strlen(plbgp->src_as_path)) {
	    if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-22s   ", plbgp->src_as_path);
	    else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), plbgp->src_as_path);
	  }
          else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-22s   ", empty_aspath);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), plbgp->src_as_path);
          }
        }

        if (!have_wtc || (what_to_count & COUNT_LOCAL_PREF)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-7u  ", pbgp->local_pref);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), pbgp->local_pref);
        }

        if (!have_wtc || (what_to_count & COUNT_SRC_LOCAL_PREF)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-7u  ", pbgp->src_local_pref);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), pbgp->src_local_pref);
        }

        if (!have_wtc || (what_to_count & COUNT_MED)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-6u  ", pbgp->med);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), pbgp->med);
        }

        if (!have_wtc || (what_to_count & COUNT_SRC_MED)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-6u  ", pbgp->src_med);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), pbgp->src_med);
        }

        if (!have_wtc || (what_to_count_2 & COUNT_SRC_ROA)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-6s  ", pmc_rpki_roa_print(pbgp->src_roa));
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), pmc_rpki_roa_print(pbgp->src_roa));
        }

        if (!have_wtc || (what_to_count_2 & COUNT_DST_ROA)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-6s  ", pmc_rpki_roa_print(pbgp->dst_roa));
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), pmc_rpki_roa_print(pbgp->dst_roa));
        }

        if (!have_wtc || (what_to_count & COUNT_PEER_SRC_AS)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-10u  ", pbgp->peer_src_as);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), pbgp->peer_src_as);
        }

        if (!have_wtc || (what_to_count & COUNT_PEER_DST_AS)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-10u  ", pbgp->peer_dst_as);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), pbgp->peer_dst_as);
        }

        if (!have_wtc || (what_to_count & COUNT_PEER_SRC_IP)) {
          addr_to_str(ip_address, &pbgp->peer_src_ip);

          if (strlen(ip_address)) {
	    if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45s  ", ip_address);
	    else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), ip_address);
	  }
          else {
	    if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45u  ", 0);
	    else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), empty_string);
	  }
        }

        if (!have_wtc || (what_to_count & COUNT_PEER_DST_IP)) {
          addr_to_str2(ip_address, &pbgp->peer_dst_ip, ft2af(acc_elem->flow_type));

          if (strlen(ip_address)) {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45s  ", ip_address);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), ip_address);
          }
          else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45u  ", 0);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), empty_string);
          }
        }

        if (!have_wtc || (what_to_count & COUNT_MPLS_VPN_RD)) {
          pmc_bgp_rd2str(rd_str, (rd_t *) &pbgp->mpls_vpn_rd);

          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-18s  ", rd_str);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), rd_str);
	}

        if (!have_wtc || (what_to_count_2 & COUNT_MPLS_PW_ID)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-10u  ", pbgp->mpls_pw_id);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), pbgp->mpls_pw_id);
        }

	if (!have_wtc || (what_to_count & (COUNT_SRC_HOST|COUNT_SUM_HOST))) {
	  addr_to_str(ip_address, &acc_elem->primitives.src_ip);

          if (strlen(ip_address)) {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45s  ", ip_address);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), ip_address);
          }
          else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45u  ", 0);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), empty_string);
          }
	}

        if (!have_wtc || (what_to_count & (COUNT_SRC_NET|COUNT_SUM_NET))) {
          addr_to_str(ip_address, &acc_elem->primitives.src_net);

          if (strlen(ip_address)) {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45s  ", ip_address);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), ip_address);
          }
          else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45u  ", 0);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), empty_string);
          }
        }

	if (!have_wtc || (what_to_count & COUNT_DST_HOST)) {
	  addr_to_str(ip_address, &acc_elem->primitives.dst_ip);

          if (strlen(ip_address)) {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45s  ", ip_address);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), ip_address);
          }
          else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45u  ", 0);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), empty_string);
          }
	}

        if (!have_wtc || (what_to_count & COUNT_DST_NET)) {
          addr_to_str(ip_address, &acc_elem->primitives.dst_net);

          if (strlen(ip_address)) {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45s  ", ip_address);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), ip_address);
          }
          else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45u  ", 0);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), empty_string);
          }
        }

        if (!have_wtc || (what_to_count & COUNT_SRC_NMASK)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-3u       ", acc_elem->primitives.src_nmask);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), acc_elem->primitives.src_nmask);
	}

        if (!have_wtc || (what_to_count & COUNT_DST_NMASK)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-3u       ", acc_elem->primitives.dst_nmask);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), acc_elem->primitives.dst_nmask);
	}

	if (!have_wtc || (what_to_count & (COUNT_SRC_PORT|COUNT_SUM_PORT))) {
	  if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-5u     ", acc_elem->primitives.src_port);
	  else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), acc_elem->primitives.src_port);
	}

	if (!have_wtc || (what_to_count & COUNT_DST_PORT)) {
	  if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-5u     ", acc_elem->primitives.dst_port);
	  else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), acc_elem->primitives.dst_port);
	}

	if (!have_wtc || (what_to_count & COUNT_TCPFLAGS)) {
	  if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-6u     ", acc_elem->tcp_flags);
	  else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), acc_elem->tcp_flags);
	}

	if (!have_wtc || (what_to_count & COUNT_IP_PROTO)) {
	  if (acc_elem->primitives.proto < protocols_number && !want_ipproto_num) {
	    if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-10s  ", _protocols[acc_elem->primitives.proto].name);
	    else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), _protocols[acc_elem->primitives.proto].name);
	  }
	  else {
	    if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-10u  ", acc_elem->primitives.proto);
	    else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), acc_elem->primitives.proto);
	  }
	}

	if (!have_wtc || (what_to_count & COUNT_IP_TOS)) {
	  if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-3u    ", acc_elem->primitives.tos); 
	  else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), acc_elem->primitives.tos); 
	}

#if defined WITH_GEOIP
        if (!have_wtc || (what_to_count_2 & COUNT_SRC_HOST_COUNTRY)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-5s       ", GeoIP_code_by_id(acc_elem->primitives.src_ip_country.id));
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), GeoIP_code_by_id(acc_elem->primitives.src_ip_country.id));
        }

        if (!have_wtc || (what_to_count_2 & COUNT_DST_HOST_COUNTRY)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-5s       ", GeoIP_code_by_id(acc_elem->primitives.dst_ip_country.id));
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), GeoIP_code_by_id(acc_elem->primitives.dst_ip_country.id));
        }
#endif
#if defined WITH_GEOIPV2
        if (!have_wtc || (what_to_count_2 & COUNT_SRC_HOST_COUNTRY)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-5s       ", acc_elem->primitives.src_ip_country.str);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), acc_elem->primitives.src_ip_country.str); 
        }

        if (!have_wtc || (what_to_count_2 & COUNT_DST_HOST_COUNTRY)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-5s       ", acc_elem->primitives.dst_ip_country.str);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), acc_elem->primitives.dst_ip_country.str);
        }

        if (!have_wtc || (what_to_count_2 & COUNT_SRC_HOST_POCODE)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-12s  ", acc_elem->primitives.src_ip_pocode.str);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), acc_elem->primitives.src_ip_pocode.str);
        }

        if (!have_wtc || (what_to_count_2 & COUNT_DST_HOST_POCODE)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-12s  ", acc_elem->primitives.dst_ip_pocode.str);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), acc_elem->primitives.dst_ip_pocode.str);
        }

        if (!have_wtc || (what_to_count_2 & COUNT_SRC_HOST_COORDS)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) {
            printf("%-12f  ", acc_elem->primitives.src_ip_lat);
            printf("%-12f  ", acc_elem->primitives.src_ip_lon);
          }
          else if (want_output & PRINT_OUTPUT_CSV) {
            printf("%s%f", write_sep(sep_ptr, &count), acc_elem->primitives.src_ip_lat);
            printf("%s%f", write_sep(sep_ptr, &count), acc_elem->primitives.src_ip_lon);
          }
        }

        if (!have_wtc || (what_to_count_2 & COUNT_DST_HOST_COORDS)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) {
            printf("%-12f  ", acc_elem->primitives.dst_ip_lat);
            printf("%-12f  ", acc_elem->primitives.dst_ip_lon);
          }
          else if (want_output & PRINT_OUTPUT_CSV) {
            printf("%s%f", write_sep(sep_ptr, &count), acc_elem->primitives.dst_ip_lat);
            printf("%s%f", write_sep(sep_ptr, &count), acc_elem->primitives.dst_ip_lon);
          }
        }
#endif

	if (!have_wtc || (what_to_count_2 & COUNT_SAMPLING_RATE)) {
	  if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-7u       ", acc_elem->primitives.sampling_rate); 
	  else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), acc_elem->primitives.sampling_rate); 
	}

	if (!have_wtc || (what_to_count_2 & COUNT_SAMPLING_DIRECTION)) {
	  if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-1s                  ", acc_elem->primitives.sampling_direction); 
	  else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), acc_elem->primitives.sampling_direction); 
	}

        if (!have_wtc || (what_to_count_2 & COUNT_POST_NAT_SRC_HOST)) {
          addr_to_str(ip_address, &pnat->post_nat_src_ip);

          if (strlen(ip_address)) {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45s  ", ip_address);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), ip_address);
          }
          else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45u  ", 0);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), empty_string);
          }
        }

        if (!have_wtc || (what_to_count_2 & COUNT_POST_NAT_DST_HOST)) {
          addr_to_str(ip_address, &pnat->post_nat_dst_ip);

          if (strlen(ip_address)) {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45s  ", ip_address);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), ip_address);
          }
          else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45u  ", 0);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), empty_string);
          }
        }

        if (!have_wtc || (what_to_count_2 & COUNT_POST_NAT_SRC_PORT)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-5u              ", pnat->post_nat_src_port);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), pnat->post_nat_src_port);
        }

        if (!have_wtc || (what_to_count_2 & COUNT_POST_NAT_DST_PORT)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-5u              ", pnat->post_nat_dst_port);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), pnat->post_nat_dst_port);
        }

        if (!have_wtc || (what_to_count_2 & COUNT_NAT_EVENT)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-3u       ", pnat->nat_event);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), pnat->nat_event);
        }

        if (!have_wtc || (what_to_count_2 & COUNT_MPLS_LABEL_TOP)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-7u         ", pmpls->mpls_label_top);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), pmpls->mpls_label_top);
        }

        if (!have_wtc || (what_to_count_2 & COUNT_MPLS_LABEL_BOTTOM)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-7u            ", pmpls->mpls_label_bottom);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), pmpls->mpls_label_bottom);
        }

        if (!have_wtc || (what_to_count_2 & COUNT_MPLS_STACK_DEPTH)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-2u                ", pmpls->mpls_stack_depth);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), pmpls->mpls_stack_depth);
        }

        if (!have_wtc || (what_to_count_2 & COUNT_TUNNEL_SRC_MAC)) {
          etheraddr_string(ptun->tunnel_eth_shost, ethernet_address);
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-17s  ", ethernet_address);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), ethernet_address);
        }

        if (!have_wtc || (what_to_count_2 & COUNT_TUNNEL_DST_MAC)) {
          etheraddr_string(ptun->tunnel_eth_dhost, ethernet_address);
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-17s  ", ethernet_address);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), ethernet_address);
        }

        if (!have_wtc || (what_to_count_2 & COUNT_TUNNEL_SRC_HOST)) {
          addr_to_str(ip_address, &ptun->tunnel_src_ip);

          if (strlen(ip_address)) {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45s  ", ip_address);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), ip_address);
          }
          else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45u  ", 0);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), empty_string);
          }
        }

        if (!have_wtc || (what_to_count_2 & COUNT_TUNNEL_DST_HOST)) {
          addr_to_str(ip_address, &ptun->tunnel_dst_ip);

          if (strlen(ip_address)) {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45s  ", ip_address);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), ip_address);
          }
          else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45u  ", 0);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), empty_string);
          }
        }

	if (!have_wtc || (what_to_count_2 & COUNT_TUNNEL_IP_PROTO)) {
	  if (ptun->tunnel_proto < protocols_number && !want_ipproto_num) {
	    if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-10s       ", _protocols[ptun->tunnel_proto].name);
	    else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), _protocols[ptun->tunnel_proto].name);
	  }
	  else {
	    if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-10u  ", ptun->tunnel_proto);
	    else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), ptun->tunnel_proto);
	  }
	}

	if (!have_wtc || (what_to_count_2 & COUNT_TUNNEL_IP_TOS)) {
	  if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-3u         ", ptun->tunnel_tos);
	  else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), ptun->tunnel_tos);
	}

        if (!have_wtc || (what_to_count_2 & COUNT_TUNNEL_SRC_PORT)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-5u            ", ptun->tunnel_src_port);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), ptun->tunnel_src_port);
        }

        if (!have_wtc || (what_to_count_2 & COUNT_TUNNEL_DST_PORT)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-5u            ", ptun->tunnel_dst_port);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), ptun->tunnel_dst_port);
        }

	if (!have_wtc || (what_to_count_2 & COUNT_VXLAN)) {
	  if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-8u  ", ptun->tunnel_id);
	  else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), ptun->tunnel_id);
	}

        if (!have_wtc || (what_to_count_2 & COUNT_TIMESTAMP_START)) {
	  char tstamp_str[SRVBUFLEN];

	  pmc_compose_timestamp(tstamp_str, SRVBUFLEN, &pnat->timestamp_start, TRUE, want_tstamp_since_epoch, want_tstamp_utc);
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-30s ", tstamp_str);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), tstamp_str);
        }

        if (!have_wtc || (what_to_count_2 & COUNT_TIMESTAMP_END)) {
          char tstamp_str[SRVBUFLEN];

	  pmc_compose_timestamp(tstamp_str, SRVBUFLEN, &pnat->timestamp_end, TRUE, want_tstamp_since_epoch, want_tstamp_utc);
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-30s ", tstamp_str);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), tstamp_str);
        }

        if (!have_wtc || (what_to_count_2 & COUNT_TIMESTAMP_ARRIVAL)) {
          char tstamp_str[SRVBUFLEN];

          pmc_compose_timestamp(tstamp_str, SRVBUFLEN, &pnat->timestamp_arrival, TRUE, want_tstamp_since_epoch, want_tstamp_utc);
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-30s ", tstamp_str);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), tstamp_str);
        }

        if (!have_wtc || (what_to_count_2 & COUNT_EXPORT_PROTO_TIME)) {
          char tstamp_str[SRVBUFLEN];

          pmc_compose_timestamp(tstamp_str, SRVBUFLEN, &pnat->timestamp_export, TRUE, want_tstamp_since_epoch, want_tstamp_utc);
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-30s ", tstamp_str);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), tstamp_str);
        }

        if (!have_wtc || (what_to_count_2 & COUNT_EXPORT_PROTO_SEQNO)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-18u  ", acc_elem->primitives.export_proto_seqno);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), acc_elem->primitives.export_proto_seqno);
        }

        if (!have_wtc || (what_to_count_2 & COUNT_EXPORT_PROTO_VERSION)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-20u  ", acc_elem->primitives.export_proto_version);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), acc_elem->primitives.export_proto_version);
        }

        if (!have_wtc || (what_to_count_2 & COUNT_EXPORT_PROTO_SYSID)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-18u  ", acc_elem->primitives.export_proto_sysid);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), acc_elem->primitives.export_proto_sysid);
        }

        /* all custom primitives printed here */
        {
          char cp_str[SRVBUFLEN];
          int cp_idx;

          for (cp_idx = 0; cp_idx < pmc_custom_primitives_registry.num; cp_idx++) {
            pmc_custom_primitive_value_print(cp_str, SRVBUFLEN, pcust, &pmc_custom_primitives_registry.primitive[cp_idx],
						want_output & PRINT_OUTPUT_FORMATTED ? 1 : 0);
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%s  ", cp_str);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), cp_str);
          }
        }

	if (!(want_output & PRINT_OUTPUT_EVENT)) {
	  if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-20" PRIu64 "  ", acc_elem->pkt_num);
	  else if (want_output & PRINT_OUTPUT_CSV) printf("%s%" PRIu64 "", write_sep(sep_ptr, &count), acc_elem->pkt_num);

	  if (!have_wtc || (what_to_count & COUNT_FLOWS)) {
	    if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-20" PRIu64 "  ", acc_elem->flo_num);
	    else if (want_output & PRINT_OUTPUT_CSV) printf("%s%" PRIu64 "", write_sep(sep_ptr, &count), acc_elem->flo_num);
	  }

	  if (want_output & (PRINT_OUTPUT_FORMATTED|PRINT_OUTPUT_CSV))
	    printf("%s%" PRIu64 "\n", write_sep(sep_ptr, &count), acc_elem->pkt_len);
        }
	else printf("\n");

	if (want_output & PRINT_OUTPUT_JSON) {
	  char *json_str;

	  json_str = pmc_compose_json(what_to_count, what_to_count_2, acc_elem->flow_type,
				      &acc_elem->primitives, pbgp, plbgp, pnat, pmpls, ptun, pcust, pvlen,
				      acc_elem->pkt_len, acc_elem->pkt_num, acc_elem->flo_num,
				      acc_elem->tcp_flags, NULL, want_tstamp_since_epoch, want_tstamp_utc);

	  if (json_str) {
	    printf("%s\n", json_str);
	    free(json_str);
	  }
	}

        counter++;
      }
      elem += datasize;
      printed += datasize;
    }
    if (want_output & PRINT_OUTPUT_FORMATTED) printf("\nFor a total of: %d entries\n", counter);
  }
  else if (want_erase) printf("OK: Clearing stats.\n");
  else if (want_erase_last_tstamp) {
    struct timeval cycle_stamp, table_reset_stamp;

    gettimeofday(&cycle_stamp, NULL);
    unpacked = Recv(sd, &largebuf);

    if (unpacked == (sizeof(struct query_header) + sizeof(struct timeval))) {
      memcpy(&table_reset_stamp, (largebuf + sizeof(struct query_header)), sizeof(struct timeval));
      if (table_reset_stamp.tv_sec) printf("%ld\n", (long)(cycle_stamp.tv_sec - table_reset_stamp.tv_sec));
      else printf("never\n");
    }
  }
  else if (want_status) {
    unpacked = Recv(sd, &largebuf);

    if (unpacked) {
      write_status_header();
      elem = largebuf+sizeof(struct query_header);
      unpacked -= sizeof(struct query_header);
      while (printed < unpacked) {
        bd = (struct bucket_desc *) elem;
        printf("%u\t", bd->num);
        while (bd->howmany > 0) {
          printf("*");
	  bd->howmany--;
        }
        printf("\n");

        elem += sizeof(struct bucket_desc);
        printed += sizeof(struct bucket_desc);
      }
    }
    else {
      printf("ERROR: missing EOF from server (7)\n");
      exit(1);
    }
  }
  else if (want_counter) {
    unsigned char *base;
    u_int64_t bcnt = 0, pcnt = 0, fcnt = 0;
    int printed;

    unpacked = Recv(sd, &largebuf);

    if (!unpacked) {
      printf("ERROR: missing EOF from server (8)\n");
      exit(1);
    }

    base = largebuf+sizeof(struct query_header);
    if (check_data_sizes((struct query_header *)largebuf, acc_elem)) exit(1);
    acc_elem = (struct pkt_data *) base;
    for (printed = sizeof(struct query_header); printed < unpacked; printed += sizeof(struct pkt_data), acc_elem++) {
      if (sum_counters) {
	pcnt += acc_elem->pkt_num;
	fcnt += acc_elem->flo_num;
	bcnt += acc_elem->pkt_len;
	num_counters += acc_elem->time_start.tv_sec; /* XXX: this field is used here to count how much entries we are accumulating */
      }
      else {
	/* print bytes */
        if (which_counter == 0) printf("%" PRIu64 "\n", acc_elem->pkt_len); 
	/* print packets */
	else if (which_counter == 1) printf("%" PRIu64 "\n", acc_elem->pkt_num); 
	/* print packets+bytes+flows+num */
	else if (which_counter == 2) printf("%" PRIu64 " %" PRIu64 " %" PRIu64 " %lu\n", acc_elem->pkt_num, acc_elem->pkt_len, acc_elem->flo_num, acc_elem->time_start.tv_sec);
	/* print flows */
	else if (which_counter == 3) printf("%" PRIu64 "\n", acc_elem->flo_num);
      }
    }
      
    if (sum_counters) {
      if (which_counter == 0) printf("%" PRIu64 "\n", bcnt); /* print bytes */
      else if (which_counter == 1) printf("%" PRIu64 "\n", pcnt); /* print packets */
      else if (which_counter == 2) printf("%" PRIu64 " %" PRIu64 " %" PRIu64 " %u\n", pcnt, bcnt, fcnt, num_counters); /* print packets+bytes+flows+num */
      else if (which_counter == 3) printf("%" PRIu64 "\n", fcnt); /* print flows */
    }
  }
  else if (want_class_table) { 
    int ct_eff=0;

    unpacked = Recv(sd, &ct);

    if (unpacked) {
      write_class_table_header();
      ct_num = ((struct query_header *)ct)->num;
      elem = ct+sizeof(struct query_header);
      class_table = (struct stripped_class *) elem;
      while (ct_idx < ct_num) {
        class_table[ct_idx].protocol[MAX_PROTOCOL_LEN-1] = '\0';
        if (class_table[ct_idx].id) {
	  printf("%u\t\t%s\n", class_table[ct_idx].id, class_table[ct_idx].protocol);
	  ct_eff++;
        }
        ct_idx++;
      }
      printf("\nFor a total of: %d classifiers\n", ct_eff);
    }
    else {
      printf("ERROR: missing EOF from server (9)\n");
      exit(1);
    }
  }
  else {
    usage_client(argv[0]);
    exit(1);
  }

  close(sd);

  return 0;
}

char *pmc_extract_token(char **string, int delim)
{
  char *token, *delim_ptr;

  if ((delim_ptr = strchr(*string, delim))) {
    *delim_ptr = '\0';
    token = *string;
    *string = delim_ptr+1;
  }
  else {
    token = *string;
    *string += strlen(*string);
  }

  return token;
}

int Recv(int sd, unsigned char **buf) 
{
  int num, unpacked = 0, round = 0, eof_received = 0; 
  unsigned char rxbuf[LARGEBUFLEN], emptybuf[LARGEBUFLEN], *elem = NULL;

  *buf = (unsigned char *) malloc(LARGEBUFLEN);
  if (!(*buf)) {
    printf("ERROR: malloc() out of memory (Recv)\n");
    exit(1);
  }
  memset(*buf, 0, LARGEBUFLEN);
  memset(rxbuf, 0, LARGEBUFLEN);
  memset(emptybuf, 0, LARGEBUFLEN);

  do {
    num = recv(sd, rxbuf, LARGEBUFLEN, 0);
    if (num > 0) {
      if (!memcmp(rxbuf, emptybuf, LARGEBUFLEN)) {
	eof_received = TRUE;
      }
      else {
	/* check: enough space in allocated buffer */
	if (unpacked+num >= round*LARGEBUFLEN) {
          round++;
          *buf = realloc((unsigned char *) *buf, round*LARGEBUFLEN);
          if (!(*buf)) {
            printf("ERROR: realloc() out of memory (Recv)\n");
            exit(1);
          }
          /* ensuring realloc() didn't move somewhere else our memory area */
          elem = *buf;
          elem += unpacked;
	}

	memcpy(elem, rxbuf, num);
	unpacked += num;
	elem += num;
      }
    }
  } while (num > 0);

  if (eof_received) return unpacked;
  else return 0;
}

int check_data_sizes(struct query_header *qh, struct pkt_data *acc_elem)
{
  if (!acc_elem) return FALSE;

  if (qh->cnt_sz != sizeof(acc_elem->pkt_len)) {
    printf("ERROR: Counter sizes mismatch: daemon: %d  client: %d\n", qh->cnt_sz*8, (int)sizeof(acc_elem->pkt_len)*8);
    printf("ERROR: It's very likely that a 64bit package has been mixed with a 32bit one.\n\n");
    printf("ERROR: Please fix the issue before trying again.\n");
    return (qh->cnt_sz-sizeof(acc_elem->pkt_len));
  }

  if (qh->ip_sz != sizeof(acc_elem->primitives.src_ip)) {
    printf("ERROR: IP address sizes mismatch. daemon: %d  client: %d\n", qh->ip_sz, (int)sizeof(acc_elem->primitives.src_ip));
    printf("ERROR: It's very likely that an IPv6-enabled package has been mixed with a IPv4-only one.\n\n");
    printf("ERROR: Please fix the issue before trying again.\n");
    return (qh->ip_sz-sizeof(acc_elem->primitives.src_ip));
  } 

  return FALSE;
}

/* sort the (sub)array v from start to end */
void client_counters_merge_sort(void *table, int start, int end, int size, int order)
{
  int middle;

  /* no elements to sort */
  if ((start == end) || (start == end-1)) return;

  /* find the middle of the array, splitting it into two subarrays */
  middle = (start+end)/2;

  /* sort the subarray from start..middle */
  client_counters_merge_sort(table, start, middle, size, order);

  /* sort the subarray from middle..end */
  client_counters_merge_sort(table, middle, end, size, order);

  /* merge the two sorted halves */
  client_counters_merge(table, start, middle, end, size, order);
}

/*
   merge the subarray v[start..middle] with v[middle..end], placing the
   result back into v.
*/
void client_counters_merge(void *table, int start, int middle, int end, int size, int order)
{
  void *v1, *v2;
  int  v1_n, v2_n, v1_index, v2_index, i, s = size;
  struct pkt_data data1, data2;

  v1_n = middle-start;
  v2_n = end-middle;

  v1 = malloc(v1_n*s);
  v2 = malloc(v2_n*s);

  if ((!v1) || (!v2)) {
    printf("ERROR: Memory sold out while sorting statistics.\n");
    exit(1);
  }

  for (i=0; i<v1_n; i++) {
    memcpy(v1+(i*s), table+((start+i)*s), s);
  }
  for (i=0; i<v2_n; i++) {
    memcpy(v2+(i*s), table+((middle+i)*s), s);
  }

  v1_index = 0;
  v2_index = 0;

  /* as we pick elements from one or the other to place back into the table */
  if (order == 1) { /* bytes */ 
    for (i=0; (v1_index < v1_n) && (v2_index < v2_n); i++) {
      /* current v1 element less than current v2 element? */
      memcpy(&data1, v1+(v1_index*s), sizeof(data1));
      memcpy(&data2, v2+(v2_index*s), sizeof(data2));
      if (data1.pkt_len < data2.pkt_len) {
	memcpy(table+((start+i)*s), v2+(v2_index*s), s);
	v2_index++;
      }
      else if (data1.pkt_len == data2.pkt_len) {
	memcpy(table+((start+i)*s), v2+(v2_index*s), s);
	v2_index++;
      }
      else {
	memcpy(table+((start+i)*s), v1+(v1_index*s), s);
	v1_index++;
      }
    }
  }
  else if (order == 2) { /* packets */
    for (i=0; (v1_index < v1_n) && (v2_index < v2_n); i++) {
      /* current v1 element less than current v2 element? */
      memcpy(&data1, v1+(v1_index*s), sizeof(data1));
      memcpy(&data2, v2+(v2_index*s), sizeof(data2));
      if (data1.pkt_num < data2.pkt_num) {
	memcpy(table+((start+i)*s), v2+(v2_index*s), s); 
	v2_index++;
      }
      else if (data1.pkt_num == data2.pkt_num) {
        memcpy(table+((start+i)*s), v2+(v2_index*s), s);
        v2_index++;
      }
      else {
	memcpy(table+((start+i)*s), v1+(v1_index*s), s);
        v1_index++;
      }
    }
  }
  else if (order == 3) { /* flows */
    for (i=0; (v1_index < v1_n) && (v2_index < v2_n); i++) {
      /* current v1 element less than current v2 element? */
      memcpy(&data1, v1+(v1_index*s), sizeof(data1));
      memcpy(&data2, v2+(v2_index*s), sizeof(data2));
      if (data1.flo_num < data2.flo_num) {
        memcpy(table+((start+i)*s), v2+(v2_index*s), s);
        v2_index++;
      }
      else if (data1.flo_num == data2.flo_num) {
        memcpy(table+((start+i)*s), v2+(v2_index*s), s);
        v2_index++;
      }
      else {
        memcpy(table+((start+i)*s), v1+(v1_index*s), s);
        v1_index++;
      }
    }
  }

  /* clean up; either v1 or v2 may have stuff left in it */
  for (; v1_index < v1_n; i++) {
    memcpy(table+((start+i)*s), v1+(v1_index*s), s);
    v1_index++;
  }
  for (; v2_index < v2_n; i++) {
    memcpy(table+((start+i)*s), v2+(v2_index*s), s);
    v2_index++;
  }

  free(v1);
  free(v2);
}

u_int16_t pmc_bgp_rd_type_get(u_int16_t type)
{
  return (type & RD_TYPE_MASK);
}

int pmc_bgp_rd2str(char *str, rd_t *rd)
{
  struct rd_ip  *rdi;
  struct rd_as  *rda;
  struct rd_as4 *rda4;
  struct host_addr a;
  char ip_address[INET6_ADDRSTRLEN];
  u_int16_t type = pmc_bgp_rd_type_get(rd->type);

  switch (type) {
  case RD_TYPE_AS:
    rda = (struct rd_as *) rd;
    sprintf(str, "%u:%u:%u", type, rda->as, rda->val);
    break;
  case RD_TYPE_IP:
    rdi = (struct rd_ip *) rd;
    a.family = AF_INET;
    a.address.ipv4.s_addr = rdi->ip.s_addr;
    addr_to_str(ip_address, &a);
    sprintf(str, "%u:%s:%u", type, ip_address, rdi->val);
    break;
  case RD_TYPE_AS4:
    rda4 = (struct rd_as4 *) rd;
    sprintf(str, "%u:%u:%u", type, rda4->as, rda4->val);
    break;
  case RD_TYPE_VRFID:
    rda = (struct rd_as *) rd;
    sprintf(str, "vrfid:%u", rda->val);
    break;
  default:
    sprintf(str, "unknown");
    break;
  }

  return TRUE;
}

int pmc_bgp_str2rd(rd_t *output, char *value)
{
  struct host_addr a;
  char *endptr, *token;
  u_int32_t tmp32;
  struct rd_ip  *rdi;
  struct rd_as  *rda;
  struct rd_as4 *rda4;
  int idx = 0;
  rd_t rd;

  memset(&a, 0, sizeof(a));
  memset(&rd, 0, sizeof(rd));

  /* type:RD_subfield1:RD_subfield2 */
  while ( (token = pmc_extract_token(&value, ':')) && idx < 3) {
    if (idx == 0) {
      tmp32 = strtoul(token, &endptr, 10);
      rd.type = tmp32;
      switch (rd.type) {
      case RD_TYPE_AS:
        rda = (struct rd_as *) &rd;
        break;
      case RD_TYPE_IP:
        rdi = (struct rd_ip *) &rd;
        break;
      case RD_TYPE_AS4:
        rda4 = (struct rd_as4 *) &rd;
        break;
      default:
        printf("ERROR: Invalid RD type specified\n");
        return FALSE;
      }
    }
    if (idx == 1) {
      switch (rd.type) {
      case RD_TYPE_AS:
        tmp32 = strtoul(token, &endptr, 10);
        rda->as = tmp32;
        break;
      case RD_TYPE_IP:
        memset(&a, 0, sizeof(a));
        str_to_addr(token, &a);
        if (a.family == AF_INET) rdi->ip.s_addr = a.address.ipv4.s_addr;
        break;
      case RD_TYPE_AS4:
        tmp32 = strtoul(token, &endptr, 10);
        rda4->as = tmp32;
        break;
      }
    }
    if (idx == 2) {
      switch (rd.type) {
      case RD_TYPE_AS:
        tmp32 = strtoul(token, &endptr, 10);
        rda->val = tmp32;
        break;
      case RD_TYPE_IP:
        tmp32 = strtoul(token, &endptr, 10);
        rdi->val = tmp32;
        break;
      case RD_TYPE_AS4:
        tmp32 = strtoul(token, &endptr, 10);
        rda4->val = tmp32;
        break;
      }
    }

    idx++;
  }

  memcpy(output, &rd, sizeof(rd));

  return TRUE;
}

#ifdef WITH_JANSSON 
char *pmc_compose_json(u_int64_t wtc, u_int64_t wtc_2, u_int8_t flow_type, struct pkt_primitives *pbase,
		  struct pkt_bgp_primitives *pbgp, struct pkt_legacy_bgp_primitives *plbgp,
		  struct pkt_nat_primitives *pnat, struct pkt_mpls_primitives *pmpls,
		  struct pkt_tunnel_primitives *ptun, u_char *pcust, struct pkt_vlen_hdr_primitives *pvlen,
		  pm_counter_t bytes_counter, pm_counter_t packet_counter, pm_counter_t flow_counter,
		  u_int32_t tcp_flags, struct timeval *basetime, int tstamp_since_epoch, int tstamp_utc)
{
  char src_mac[18], dst_mac[18], src_host[INET6_ADDRSTRLEN], dst_host[INET6_ADDRSTRLEN], ip_address[INET6_ADDRSTRLEN];
  char rd_str[SRVBUFLEN], misc_str[SRVBUFLEN], *as_path, *bgp_comm, empty_string[] = "", *tmpbuf;
  char tstamp_str[SRVBUFLEN], *label_ptr;
  json_t *obj = json_object();
  
  if (wtc & COUNT_TAG) json_object_set_new_nocheck(obj, "tag", json_integer((json_int_t)pbase->tag));

  if (wtc & COUNT_TAG2) json_object_set_new_nocheck(obj, "tag2", json_integer((json_int_t)pbase->tag2));

  if (wtc_2 & COUNT_LABEL) {
    pmc_vlen_prims_get(pvlen, COUNT_INT_LABEL, &label_ptr);
    if (!label_ptr) label_ptr = empty_string;

    json_object_set_new_nocheck(obj, "label", json_string(label_ptr));
  }

  if (wtc & COUNT_CLASS)
    json_object_set_new_nocheck(obj, "class", json_string((pbase->class && class_table[(pbase->class)-1].id) ? class_table[(pbase->class)-1].protocol : "unknown"));

#if defined (WITH_NDPI)
  char ndpi_class[SUPERSHORTBUFLEN];
  if (wtc_2 & COUNT_NDPI_CLASS) {
    snprintf(ndpi_class, SUPERSHORTBUFLEN, "%s/%s",
		pmc_ndpi_get_proto_name(pbase->ndpi_class.master_protocol),
		pmc_ndpi_get_proto_name(pbase->ndpi_class.app_protocol));

    json_object_set_new_nocheck(obj, "class", json_string(ndpi_class));
  }
#endif

#if defined (HAVE_L2)
  if (wtc & COUNT_SRC_MAC) {
    etheraddr_string(pbase->eth_shost, src_mac);
    json_object_set_new_nocheck(obj, "mac_src", json_string(src_mac));
  }

  if (wtc & COUNT_DST_MAC) {
    etheraddr_string(pbase->eth_dhost, dst_mac);
    json_object_set_new_nocheck(obj, "mac_dst", json_string(dst_mac));
  }

  if (wtc & COUNT_VLAN) json_object_set_new_nocheck(obj, "vlan", json_integer((json_int_t)pbase->vlan_id));

  if (wtc & COUNT_COS) json_object_set_new_nocheck(obj, "cos", json_integer((json_int_t)pbase->cos));

  if (wtc & COUNT_ETHERTYPE) {
    sprintf(misc_str, "%x", pbase->etype);
    json_object_set_new_nocheck(obj, "etype", json_string(misc_str));
  }
#endif

  if (wtc & COUNT_SRC_AS) json_object_set_new_nocheck(obj, "as_src", json_integer((json_int_t)pbase->src_as));

  if (wtc & COUNT_DST_AS) json_object_set_new_nocheck(obj, "as_dst", json_integer((json_int_t)pbase->dst_as));

  if (wtc & COUNT_STD_COMM) {
    bgp_comm = plbgp->std_comms;
    while (bgp_comm) {
      bgp_comm = strchr(plbgp->std_comms, ' ');
      if (bgp_comm) *bgp_comm = '_';
    }

    if (strlen(plbgp->std_comms))
      json_object_set_new_nocheck(obj, "comms", json_string(plbgp->std_comms));
    else
      json_object_set_new_nocheck(obj, "comms", json_string(empty_string));
  }

  if (wtc & COUNT_EXT_COMM) {
    bgp_comm = plbgp->ext_comms;
    while (bgp_comm) {
      bgp_comm = strchr(plbgp->ext_comms, ' ');
      if (bgp_comm) *bgp_comm = '_';
    }

    if (strlen(plbgp->ext_comms))
      json_object_set_new_nocheck(obj, "ecomms", json_string(plbgp->ext_comms));
    else
      json_object_set_new_nocheck(obj, "ecomms", json_string(empty_string));
  }

  if (wtc_2 & COUNT_LRG_COMM) {
    bgp_comm = plbgp->lrg_comms;
    while (bgp_comm) {
      bgp_comm = strchr(plbgp->lrg_comms, ' ');
      if (bgp_comm) *bgp_comm = '_';
    }

    if (strlen(plbgp->lrg_comms))
      json_object_set_new_nocheck(obj, "lcomms", json_string(plbgp->lrg_comms));
    else
      json_object_set_new_nocheck(obj, "lcomms", json_string(empty_string));
  }

  if (wtc & COUNT_AS_PATH) {
    as_path = plbgp->as_path;
    while (as_path) {
      as_path = strchr(plbgp->as_path, ' ');
      if (as_path) *as_path = '_';
    }
    if (strlen(plbgp->as_path))
      json_object_set_new_nocheck(obj, "as_path", json_string(plbgp->as_path));
    else
      json_object_set_new_nocheck(obj, "as_path", json_string(empty_string));
  }

  if (wtc & COUNT_LOCAL_PREF) json_object_set_new_nocheck(obj, "local_pref", json_integer((json_int_t)pbgp->local_pref));

  if (wtc & COUNT_MED) json_object_set_new_nocheck(obj, "med", json_integer((json_int_t)pbgp->med));

  if (wtc_2 & COUNT_DST_ROA) json_object_set_new_nocheck(obj, "roa_dst", json_string(pmc_rpki_roa_print(pbgp->dst_roa)));

  if (wtc & COUNT_PEER_SRC_AS) json_object_set_new_nocheck(obj, "peer_as_src", json_integer((json_int_t)pbgp->peer_src_as));

  if (wtc & COUNT_PEER_DST_AS) json_object_set_new_nocheck(obj, "peer_as_dst", json_integer((json_int_t)pbgp->peer_dst_as));

  if (wtc & COUNT_PEER_SRC_IP) {
    addr_to_str(ip_address, &pbgp->peer_src_ip);
    json_object_set_new_nocheck(obj, "peer_ip_src", json_string(ip_address));
  }

  if (wtc & COUNT_PEER_DST_IP) {
    addr_to_str2(ip_address, &pbgp->peer_dst_ip, ft2af(flow_type));
    json_object_set_new_nocheck(obj, "peer_ip_dst", json_string(ip_address));
  }

  if (wtc & COUNT_SRC_STD_COMM) {
    bgp_comm = plbgp->src_std_comms;
    while (bgp_comm) {
      bgp_comm = strchr(plbgp->src_std_comms, ' ');
      if (bgp_comm) *bgp_comm = '_';
    }

    if (strlen(plbgp->src_std_comms))
      json_object_set_new_nocheck(obj, "src_comms", json_string(plbgp->src_std_comms));
    else
      json_object_set_new_nocheck(obj, "src_comms", json_string(empty_string));
  }

  if (wtc & COUNT_SRC_EXT_COMM) {
    bgp_comm = plbgp->src_ext_comms;
    while (bgp_comm) {
      bgp_comm = strchr(plbgp->src_ext_comms, ' ');
      if (bgp_comm) *bgp_comm = '_';
    }

    if (strlen(plbgp->src_ext_comms))
      json_object_set_new_nocheck(obj, "src_ecomms", json_string(plbgp->src_ext_comms));
    else
      json_object_set_new_nocheck(obj, "src_ecomms", json_string(empty_string));
  }

  if (wtc_2 & COUNT_SRC_LRG_COMM) {
    bgp_comm = plbgp->src_lrg_comms;
    while (bgp_comm) {
      bgp_comm = strchr(plbgp->src_lrg_comms, ' ');
      if (bgp_comm) *bgp_comm = '_';
    }

    if (strlen(plbgp->src_lrg_comms))
      json_object_set_new_nocheck(obj, "src_lcomms", json_string(plbgp->src_lrg_comms));
    else
      json_object_set_new_nocheck(obj, "src_lcomms", json_string(empty_string));
  }

  if (wtc & COUNT_SRC_AS_PATH) {
    as_path = plbgp->src_as_path;
    while (as_path) {
      as_path = strchr(plbgp->src_as_path, ' ');
      if (as_path) *as_path = '_';
    }
    if (strlen(plbgp->src_as_path))
      json_object_set_new_nocheck(obj, "src_as_path", json_string(plbgp->src_as_path));
    else
      json_object_set_new_nocheck(obj, "src_as_path", json_string(empty_string));
  }

  if (wtc & COUNT_SRC_LOCAL_PREF) json_object_set_new_nocheck(obj, "src_local_pref", json_integer((json_int_t)pbgp->src_local_pref));

  if (wtc & COUNT_SRC_MED) json_object_set_new_nocheck(obj, "src_med", json_integer((json_int_t)pbgp->src_med));

  if (wtc_2 & COUNT_SRC_ROA) json_object_set_new_nocheck(obj, "roa_src", json_string(pmc_rpki_roa_print(pbgp->src_roa)));

  if (wtc & COUNT_IN_IFACE) json_object_set_new_nocheck(obj, "iface_in", json_integer((json_int_t)pbase->ifindex_in));

  if (wtc & COUNT_OUT_IFACE) json_object_set_new_nocheck(obj, "iface_out", json_integer((json_int_t)pbase->ifindex_out));

  if (wtc & COUNT_MPLS_VPN_RD) {
    pmc_bgp_rd2str(rd_str, &pbgp->mpls_vpn_rd);
    json_object_set_new_nocheck(obj, "mpls_vpn_rd", json_string(rd_str));
  }

  if (wtc_2 & COUNT_MPLS_PW_ID) json_object_set_new_nocheck(obj, "mpls_pw_id", json_integer((json_int_t)pbgp->mpls_pw_id));

  if (wtc & COUNT_SRC_HOST) {
    addr_to_str(src_host, &pbase->src_ip);
    json_object_set_new_nocheck(obj, "ip_src", json_string(src_host));
  }

  if (wtc & COUNT_SRC_NET) {
    addr_to_str(src_host, &pbase->src_net);
    json_object_set_new_nocheck(obj, "net_src", json_string(src_host));
  }

  if (wtc & COUNT_DST_HOST) {
    addr_to_str(dst_host, &pbase->dst_ip);
    json_object_set_new_nocheck(obj, "ip_dst", json_string(dst_host));
  }

  if (wtc & COUNT_DST_NET) {
    addr_to_str(dst_host, &pbase->dst_net);
    json_object_set_new_nocheck(obj, "net_dst", json_string(dst_host));
  }

  if (wtc & COUNT_SRC_NMASK) json_object_set_new_nocheck(obj, "mask_src", json_integer((json_int_t)pbase->src_nmask));

  if (wtc & COUNT_DST_NMASK) json_object_set_new_nocheck(obj, "mask_dst", json_integer((json_int_t)pbase->dst_nmask));

  if (wtc & COUNT_SRC_PORT) json_object_set_new_nocheck(obj, "port_src", json_integer((json_int_t)pbase->src_port));

  if (wtc & COUNT_DST_PORT) json_object_set_new_nocheck(obj, "port_dst", json_integer((json_int_t)pbase->dst_port));

#if defined (WITH_GEOIP)
  if (wtc_2 & COUNT_SRC_HOST_COUNTRY) {
    if (pbase->src_ip_country.id > 0)
      json_object_set_new_nocheck(obj, "country_ip_src", json_string(GeoIP_code_by_id(pbase->src_ip_country.id)));
    else
      json_object_set_new_nocheck(obj, "country_ip_src", json_string(empty_string));
  }

  if (wtc_2 & COUNT_DST_HOST_COUNTRY) {
    if (pbase->dst_ip_country.id > 0)
      json_object_set_new_nocheck(obj, "country_ip_dst", json_string(GeoIP_code_by_id(pbase->dst_ip_country.id)));
    else
      json_object_set_new_nocheck(obj, "country_ip_dst", json_string(empty_string));
  }
#endif
#if defined (WITH_GEOIPV2)
  if (wtc_2 & COUNT_SRC_HOST_COUNTRY) {
    if (strlen(pbase->src_ip_country.str))
      json_object_set_new_nocheck(obj, "country_ip_src", json_string(pbase->src_ip_country.str));
    else
      json_object_set_new_nocheck(obj, "country_ip_src", json_string(empty_string));
  }

  if (wtc_2 & COUNT_DST_HOST_COUNTRY) {
    if (strlen(pbase->dst_ip_country.str))
      json_object_set_new_nocheck(obj, "country_ip_dst", json_string(pbase->dst_ip_country.str));
    else
      json_object_set_new_nocheck(obj, "country_ip_dst", json_string(empty_string));
  }

  if (wtc_2 & COUNT_SRC_HOST_POCODE) {
    if (strlen(pbase->src_ip_pocode.str))
      json_object_set_new_nocheck(obj, "pocode_ip_src", json_string(pbase->src_ip_pocode.str));
    else
      json_object_set_new_nocheck(obj, "pocode_ip_src", json_string(empty_string));
  }

  if (wtc_2 & COUNT_DST_HOST_POCODE) {
    if (strlen(pbase->dst_ip_pocode.str))
      json_object_set_new_nocheck(obj, "pocode_ip_dst", json_string(pbase->dst_ip_pocode.str));
    else
      json_object_set_new_nocheck(obj, "pocode_ip_dst", json_string(empty_string));
  }

  if (wtc_2 & COUNT_SRC_HOST_COORDS) {
    json_object_set_new_nocheck(obj, "lat_ip_src", json_real(pbase->src_ip_lat));
    json_object_set_new_nocheck(obj, "lat_ip_src", json_real(pbase->src_ip_lon));
  }

  if (wtc_2 & COUNT_DST_HOST_COORDS) {
    json_object_set_new_nocheck(obj, "lat_ip_dst", json_real(pbase->dst_ip_lat));
    json_object_set_new_nocheck(obj, "lat_ip_dst", json_real(pbase->dst_ip_lon));
  }
#endif

  if (wtc & COUNT_TCPFLAGS) {
    sprintf(misc_str, "%u", tcp_flags);
    json_object_set_new_nocheck(obj, "tcp_flags", json_string(misc_str));
  }

  if (wtc & COUNT_IP_PROTO) {
    char proto[PROTO_NUM_STRLEN];

    if (!want_ipproto_num) json_object_set_new_nocheck(obj, "ip_proto", json_string(_protocols[pbase->proto].name));
    else {
      snprintf(proto, PROTO_NUM_STRLEN, "%u", pbase->proto);
      json_object_set_new_nocheck(obj, "ip_proto", json_string(proto));
    }
  }

  if (wtc & COUNT_IP_TOS) json_object_set_new_nocheck(obj, "tos", json_integer((json_int_t)pbase->tos));

  if (wtc_2 & COUNT_SAMPLING_RATE) json_object_set_new_nocheck(obj, "sampling_rate", json_integer((json_int_t)pbase->sampling_rate));
  if (wtc_2 & COUNT_SAMPLING_DIRECTION) json_object_set_new_nocheck(obj, "sampling_direction", json_string(pbase->sampling_direction));

  if (wtc_2 & COUNT_POST_NAT_SRC_HOST) {
    addr_to_str(src_host, &pnat->post_nat_src_ip);
    json_object_set_new_nocheck(obj, "post_nat_ip_src", json_string(src_host));
  }

  if (wtc_2 & COUNT_POST_NAT_DST_HOST) {
    addr_to_str(dst_host, &pnat->post_nat_dst_ip);
    json_object_set_new_nocheck(obj, "post_nat_ip_dst", json_string(dst_host));
  }

  if (wtc_2 & COUNT_POST_NAT_SRC_PORT) json_object_set_new_nocheck(obj, "post_nat_port_src", json_integer((json_int_t)pnat->post_nat_src_port));

  if (wtc_2 & COUNT_POST_NAT_DST_PORT) json_object_set_new_nocheck(obj, "post_nat_port_dst", json_integer((json_int_t)pnat->post_nat_dst_port));

  if (wtc_2 & COUNT_NAT_EVENT) json_object_set_new_nocheck(obj, "nat_event", json_integer((json_int_t)pnat->nat_event));

  if (wtc_2 & COUNT_MPLS_LABEL_TOP) json_object_set_new_nocheck(obj, "mpls_label_top", json_integer((json_int_t)pmpls->mpls_label_top));

  if (wtc_2 & COUNT_MPLS_LABEL_BOTTOM) json_object_set_new_nocheck(obj, "mpls_label_bottom", json_integer((json_int_t)pmpls->mpls_label_bottom));

  if (wtc_2 & COUNT_MPLS_STACK_DEPTH) json_object_set_new_nocheck(obj, "mpls_stack_depth", json_integer((json_int_t)pmpls->mpls_stack_depth));

  if (wtc_2 & COUNT_TUNNEL_SRC_MAC) {
    etheraddr_string(ptun->tunnel_eth_shost, src_mac);
    json_object_set_new_nocheck(obj, "tunnel_mac_src", json_string(src_mac));
  }

  if (wtc_2 & COUNT_TUNNEL_DST_MAC) {
    etheraddr_string(ptun->tunnel_eth_dhost, dst_mac);
    json_object_set_new_nocheck(obj, "tunnel_mac_dst", json_string(dst_mac));
  }

  if (wtc_2 & COUNT_TUNNEL_SRC_HOST) {
    addr_to_str(src_host, &ptun->tunnel_src_ip);
    json_object_set_new_nocheck(obj, "tunnel_ip_src", json_string(src_host));
  }

  if (wtc_2 & COUNT_TUNNEL_DST_HOST) {
    addr_to_str(dst_host, &ptun->tunnel_dst_ip);
    json_object_set_new_nocheck(obj, "tunnel_ip_dst", json_string(dst_host));
  }

  if (wtc_2 & COUNT_TUNNEL_IP_PROTO) {
    char proto[PROTO_NUM_STRLEN];

    if (!want_ipproto_num) json_object_set_new_nocheck(obj, "tunnel_ip_proto", json_string(_protocols[ptun->tunnel_proto].name));
    else {
      snprintf(proto, PROTO_NUM_STRLEN, "%u", ptun->tunnel_proto);
      json_object_set_new_nocheck(obj, "tunnel_ip_proto", json_string(proto));
    }
  }

  if (wtc_2 & COUNT_TUNNEL_IP_TOS) json_object_set_new_nocheck(obj, "tunnel_tos", json_integer((json_int_t)ptun->tunnel_tos));
  if (wtc_2 & COUNT_TUNNEL_SRC_PORT) json_object_set_new_nocheck(obj, "tunnel_port_src", json_integer((json_int_t)ptun->tunnel_src_port));
  if (wtc_2 & COUNT_TUNNEL_DST_PORT) json_object_set_new_nocheck(obj, "tunnel_port_dst", json_integer((json_int_t)ptun->tunnel_dst_port));
  if (wtc_2 & COUNT_VXLAN) json_object_set_new_nocheck(obj, "vxlan", json_integer((json_int_t)ptun->tunnel_id));

  if (wtc_2 & COUNT_TIMESTAMP_START) {
    pmc_compose_timestamp(tstamp_str, SRVBUFLEN, &pnat->timestamp_start, TRUE, tstamp_since_epoch, tstamp_utc);
    json_object_set_new_nocheck(obj, "timestamp_start", json_string(tstamp_str));
  }

  if (wtc_2 & COUNT_TIMESTAMP_END) {
    pmc_compose_timestamp(tstamp_str, SRVBUFLEN, &pnat->timestamp_end, TRUE, tstamp_since_epoch, tstamp_utc);
    json_object_set_new_nocheck(obj, "timestamp_end", json_string(tstamp_str));
  }

  if (wtc_2 & COUNT_TIMESTAMP_ARRIVAL) {
    pmc_compose_timestamp(tstamp_str, SRVBUFLEN, &pnat->timestamp_arrival, TRUE, tstamp_since_epoch, tstamp_utc);
    json_object_set_new_nocheck(obj, "timestamp_arrival", json_string(tstamp_str));
  }

  if (wtc_2 & COUNT_EXPORT_PROTO_TIME) {
    pmc_compose_timestamp(tstamp_str, SRVBUFLEN, &pnat->timestamp_export, TRUE, tstamp_since_epoch, tstamp_utc);
    json_object_set_new_nocheck(obj, "timestamp_export", json_string(tstamp_str));
  }

  if (wtc_2 & COUNT_EXPORT_PROTO_SEQNO) json_object_set_new_nocheck(obj, "export_proto_seqno", json_integer((json_int_t)pbase->export_proto_seqno));

  if (wtc_2 & COUNT_EXPORT_PROTO_VERSION) json_object_set_new_nocheck(obj, "export_proto_version", json_integer((json_int_t)pbase->export_proto_version));

  if (wtc_2 & COUNT_EXPORT_PROTO_SYSID) json_object_set_new_nocheck(obj, "export_proto_sysid", json_integer((json_int_t)pbase->export_proto_sysid));

  /* all custom primitives printed here */
  {
    int cp_idx;

    for (cp_idx = 0; cp_idx < pmc_custom_primitives_registry.num; cp_idx++) {
      if (pmc_custom_primitives_registry.primitive[cp_idx].len != PM_VARIABLE_LENGTH) {
        char cp_str[SRVBUFLEN];

        pmc_custom_primitive_value_print(cp_str, SRVBUFLEN, pcust, &pmc_custom_primitives_registry.primitive[cp_idx], FALSE);
	json_object_set_new_nocheck(obj, pmc_custom_primitives_registry.primitive[cp_idx].name, json_string(cp_str));
      }
      else {
        char *label_ptr = NULL;

        pmc_vlen_prims_get(pvlen, pmc_custom_primitives_registry.primitive[cp_idx].type, &label_ptr);
        if (!label_ptr) label_ptr = empty_string;
	json_object_set_new_nocheck(obj, pmc_custom_primitives_registry.primitive[cp_idx].name, json_string(label_ptr));
      }
    }
  }

  if (flow_type != NF9_FTYPE_EVENT && flow_type != NF9_FTYPE_OPTION) {
    json_object_set_new_nocheck(obj, "packets", json_integer((json_int_t)packet_counter));

    if (wtc & COUNT_FLOWS) json_object_set_new_nocheck(obj, "flows", json_integer((json_int_t)flow_counter));

    json_object_set_new_nocheck(obj, "bytes", json_integer((json_int_t)bytes_counter));
  }

  tmpbuf = json_dumps(obj, JSON_PRESERVE_ORDER);
  json_decref(obj);

  return tmpbuf;
}
#else
char *pmc_compose_json(u_int64_t wtc, u_int64_t wtc_2, u_int8_t flow_type, struct pkt_primitives *pbase,
                  struct pkt_bgp_primitives *pbgp, struct pkt_legacy_bgp_primitives *plbgp,
		  struct pkt_nat_primitives *pnat, struct pkt_mpls_primitives *pmpls,
		  struct pkt_tunnel_primitives *ptun, u_char *pcust, struct pkt_vlen_hdr_primitives *pvlen,
		  pm_counter_t bytes_counter, pm_counter_t packet_counter, pm_counter_t flow_counter,
		  u_int32_t tcp_flags, struct timeval *basetime, int tstamp_since_epoch, int tstamp_utc)
{
  return NULL;
}
#endif

void pmc_append_rfc3339_timezone(char *s, int slen, const struct tm *nowtm)
{
  int len = strlen(s), max = (slen - len);
  char buf[8], zulu[] = "Z";

  strftime(buf, 8, "%z", nowtm);

  if (!strcmp(buf, "+0000")) {
    if (max) strcat(s, zulu);
  }
  else {
    if (max >= 7) {
      s[len] = buf[0]; len++;
      s[len] = buf[1]; len++;
      s[len] = buf[2]; len++;
      s[len] = ':'; len++;
      s[len] = buf[3]; len++;
      s[len] = buf[4]; len++;
      s[len] = '\0';
    }
  }
}

void pmc_compose_timestamp(char *buf, int buflen, struct timeval *tv, int usec, int tstamp_since_epoch, int tstamp_utc)
{
  int slen;
  time_t time1;
  struct tm *time2;

  if (tstamp_since_epoch) {
    if (usec) snprintf(buf, buflen, "%ld.%.6ld", tv->tv_sec, (long)tv->tv_usec);
    else snprintf(buf, buflen, "%ld", tv->tv_sec);
  }
  else {
    time1 = tv->tv_sec;
    if (!tstamp_utc) time2 = localtime(&time1);
    else time2 = gmtime(&time1);

    slen = strftime(buf, buflen, "%Y-%m-%dT%H:%M:%S", time2);

    if (usec) snprintf((buf + slen), (buflen - slen), ".%.6ld", (long)tv->tv_usec);
    pmc_append_rfc3339_timezone(buf, buflen, time2);
  }
}

void pmc_custom_primitive_header_print(char *out, int outlen, struct imt_custom_primitive_entry *cp_entry, int formatted)
{
  char format[SRVBUFLEN];

  if (out && cp_entry) {
    memset(out, 0, outlen);

    if (cp_entry->semantics == CUSTOM_PRIMITIVE_TYPE_UINT ||
        cp_entry->semantics == CUSTOM_PRIMITIVE_TYPE_HEX) {
      if (formatted) {
	snprintf(format, SRVBUFLEN, "%%-%d", cps_flen[cp_entry->len] > strlen(cp_entry->name) ? cps_flen[cp_entry->len] : (int)strlen(cp_entry->name));
	strncat(format, "s", SRVBUFLEN - 1);
      }
      else snprintf(format, SRVBUFLEN, "%s", "%s");
    }
    else if (cp_entry->semantics == CUSTOM_PRIMITIVE_TYPE_STRING ||
	     cp_entry->semantics == CUSTOM_PRIMITIVE_TYPE_RAW) {
      if (formatted) {
	snprintf(format, SRVBUFLEN, "%%-%d", cp_entry->len > strlen(cp_entry->name) ? cp_entry->len : (int)strlen(cp_entry->name));
	strncat(format, "s", SRVBUFLEN - 1);
      }
      else snprintf(format, SRVBUFLEN, "%s", "%s");
    }
    else if (cp_entry->semantics == CUSTOM_PRIMITIVE_TYPE_IP) {
      int len = 0;

      len = INET6_ADDRSTRLEN;
      	
      if (formatted) {
        snprintf(format, SRVBUFLEN, "%%-%d", len > strlen(cp_entry->name) ? len : (int)strlen(cp_entry->name));
        strncat(format, "s", SRVBUFLEN - 1);
      }
      else snprintf(format, SRVBUFLEN, "%s", "%s");
    }
    else if (cp_entry->semantics == CUSTOM_PRIMITIVE_TYPE_MAC) {
      int len = ETHER_ADDRSTRLEN;

      if (formatted) {
        snprintf(format, SRVBUFLEN, "%%-%d", len > strlen(cp_entry->name) ? len : (int)strlen(cp_entry->name));
        strncat(format, "s", SRVBUFLEN - 1);
      }
      else snprintf(format, SRVBUFLEN, "%s", "%s");
    }

    snprintf(out, outlen, format, cp_entry->name);
  }
}

void pmc_custom_primitive_value_print(char *out, int outlen, u_char *in, struct imt_custom_primitive_entry *cp_entry, int formatted)
{
  char format[SRVBUFLEN];

  if (in && out && cp_entry) {
    memset(out, 0, outlen); 

    if (cp_entry->semantics == CUSTOM_PRIMITIVE_TYPE_UINT ||
	cp_entry->semantics == CUSTOM_PRIMITIVE_TYPE_HEX) {
      if (formatted)
        snprintf(format, SRVBUFLEN, "%%-%d%s", cps_flen[cp_entry->len] > strlen(cp_entry->name) ? cps_flen[cp_entry->len] : (int)strlen(cp_entry->name), 
			cps_type[cp_entry->semantics]); 
      else
        snprintf(format, SRVBUFLEN, "%%%s", cps_type[cp_entry->semantics]); 

      if (cp_entry->len == 1) {
        u_int8_t t8;

        memcpy(&t8, (in+cp_entry->off), 1);
	snprintf(out, outlen, format, t8);
      }
      else if (cp_entry->len == 2) {
        u_int16_t t16, st16;

        memcpy(&t16, (in+cp_entry->off), 2);
	st16 = ntohs(t16);
	snprintf(out, outlen, format, st16);
      }
      else if (cp_entry->len == 4) {
        u_int32_t t32, st32;

        memcpy(&t32, (in+cp_entry->off), 4);
        st32 = ntohl(t32);
	snprintf(out, outlen, format, st32);
      }
      else if (cp_entry->len == 8) {
        u_int64_t t64, st64;

        memcpy(&t64, (in+cp_entry->off), 8);
        st64 = pm_ntohll(t64);
	snprintf(out, outlen, format, st64);
      }
    }
    else if (cp_entry->semantics == CUSTOM_PRIMITIVE_TYPE_STRING ||
	     cp_entry->semantics == CUSTOM_PRIMITIVE_TYPE_RAW) {
      if (formatted)
	snprintf(format, SRVBUFLEN, "%%-%d%s", cp_entry->len > strlen(cp_entry->name) ? cp_entry->len : (int)strlen(cp_entry->name),
			cps_type[cp_entry->semantics]); 
      else
	snprintf(format, SRVBUFLEN, "%%%s", cps_type[cp_entry->semantics]); 

      snprintf(out, outlen, format, (in+cp_entry->off));
    }
    else if (cp_entry->semantics == CUSTOM_PRIMITIVE_TYPE_IP) {
      struct host_addr ip_addr;
      char ip_str[INET6_ADDRSTRLEN];
      int len = 0;

      memset(&ip_addr, 0, sizeof(ip_addr));
      memset(ip_str, 0, sizeof(ip_str));

      len = INET6_ADDRSTRLEN;

      if (cp_entry->len == 4) { 
	ip_addr.family = AF_INET;
	memcpy(&ip_addr.address.ipv4, in+cp_entry->off, 4); 
      }
      else if (cp_entry->len == 16) {
	ip_addr.family = AF_INET6;
	memcpy(&ip_addr.address.ipv6, in+cp_entry->off, 16); 
      }

      addr_to_str(ip_str, &ip_addr);
      if (formatted)
        snprintf(format, SRVBUFLEN, "%%-%d%s", len > strlen(cp_entry->name) ? len : (int)strlen(cp_entry->name),
                        cps_type[cp_entry->semantics]);
      else
        snprintf(format, SRVBUFLEN, "%%%s", cps_type[cp_entry->semantics]);

      snprintf(out, outlen, format, ip_str);
    }
    else if (cp_entry->semantics == CUSTOM_PRIMITIVE_TYPE_MAC) {
      char eth_str[ETHER_ADDRSTRLEN];
      int len = ETHER_ADDRSTRLEN;

      memset(eth_str, 0, sizeof(eth_str));
      etheraddr_string(in+cp_entry->off, eth_str);

      if (formatted)
        snprintf(format, SRVBUFLEN, "%%-%d%s", len > strlen(cp_entry->name) ? len : (int)strlen(cp_entry->name),
                        cps_type[cp_entry->semantics]);
      else
        snprintf(format, SRVBUFLEN, "%%%s", cps_type[cp_entry->semantics]);

      snprintf(out, outlen, format, eth_str);
    }
  }
}

void pmc_vlen_prims_get(struct pkt_vlen_hdr_primitives *hdr, pm_cfgreg_t wtc, char **res)
{
  pm_label_t *label_ptr;
  char *ptr = (char *) hdr;
  int x, rlen;

  if (res) *res = NULL;

  if (!hdr || !wtc || !res) return;

  ptr += PvhdrSz;
  label_ptr = (pm_label_t *) ptr;

  for (x = 0, rlen = 0; x < hdr->num && rlen < hdr->tot_len; x++) {
    if (label_ptr->type == wtc) {
      if (label_ptr->len) {
        ptr += PmLabelTSz;
        *res = ptr;
      }

      return;
    }
    else {
      ptr += (PmLabelTSz + label_ptr->len);
      rlen += (PmLabelTSz + label_ptr->len);
      label_ptr = (pm_label_t *) ptr;
    }
  }
}

void pmc_printf_csv_label(struct pkt_vlen_hdr_primitives *pvlen, pm_cfgreg_t wtc, char *sep, char *empty_string)
{
  char *label_ptr = NULL;

  pmc_vlen_prims_get(pvlen, wtc, &label_ptr);
  if (!label_ptr) label_ptr = empty_string;
  printf("%s%s", sep, label_ptr);
}

void pmc_lower_string(char *string)
{
  int i = 0;

  while (string[i] != '\0') {
    string[i] = tolower(string[i]);
    i++;
  }
}

char *pmc_ndpi_get_proto_name(u_int16_t proto_id)
{
  if (!proto_id || proto_id > ct_idx || !class_table[proto_id].id) return class_table[0].protocol;
  else return class_table[proto_id].protocol;
}

const char *pmc_rpki_roa_print(u_int8_t roa)
{
  if (roa <= ROA_STATUS_MAX) return rpki_roa[roa];
  else return rpki_roa[ROA_STATUS_UNKNOWN];
}

u_int8_t pmc_rpki_str2roa(char *roa_str)
{
  if (!strcmp(roa_str, "u")) return ROA_STATUS_UNKNOWN;
  else if (!strcmp(roa_str, "i")) return ROA_STATUS_INVALID;
  else if (!strcmp(roa_str, "v")) return ROA_STATUS_VALID;

  return ROA_STATUS_UNKNOWN;
}

/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2013 by Paolo Lucente
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

#define __PMACCT_CLIENT_C

/* include */
#include "pmacct.h"
#include "pmacct-data.h"
#include "imt_plugin.h"
#include "bgp/bgp_packet.h"
#include "bgp/bgp.h"

/* prototypes */
int Recv(int, unsigned char **);
void print_ex_options_error();
void write_status_header_formatted();
void write_status_header_csv();
void write_class_table_header();
void write_pkt_len_distrib_table_header();
char *write_sep(char *, int *);
int CHECK_Q_TYPE(int);
int check_data_sizes(struct query_header *, struct pkt_data *);
void client_counters_merge_sort(void *, int, int, int, int);
void client_counters_merge(void *, int, int, int, int, int);
int pmc_sanitize_buf(char *);
void pmc_trim_all_spaces(char *);
char *pmc_extract_token(char **, int);
int pmc_bgp_rd2str(char *, rd_t *);
int pmc_bgp_str2rd(rd_t *, char *);

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
  printf("%s (%s)\n", PMACCT_USAGE_HEADER, PMACCT_BUILD);
  printf("Usage: %s [query]\n\n", prog);
  printf("Queries:\n");
  printf("  -s\tShow statistics\n"); 
  printf("  -N\t[matching data[';' ... ]] | ['file:'[filename]] \n\tMatch primitives; print counters only (requires -c)\n");
  printf("  -n\t[bytes|packets|flows|all] \n\tSelect the counters to print (applies to -N)\n");
  printf("  -S\tSum counters instead of returning a single counter for each request (applies to -N)\n");
  printf("  -M\t[matching data[';' ... ]] | ['file:'[filename]] \n\tMatch primitives; print formatted table (requires -c)\n");
  printf("  -a\tDisplay all table fields (even those currently unused)\n");
  printf("  -c\t[ src_mac | dst_mac | vlan | cos | src_host | dst_host | src_net | dst_net | src_mask | dst_mask | \n\t src_port | dst_port | tos | proto | src_as | dst_as | sum_mac | sum_host | sum_net | sum_as | \n\t sum_port | in_iface | out_iface | tag | tag2 | flows | class | std_comm | ext_comm | as_path | \n\t peer_src_ip | peer_dst_ip | peer_src_as | peer_dst_as | src_as_path | src_std_comm | src_med | \n\t src_ext_comm | src_local_pref | mpls_vpn_rd | etype | sampling_rate | pkt_len_distrib |\n\t post_nat_src_host | post_nat_dst_host | post_nat_src_port | post_nat_dst_port | nat_event |\n\t timestamp_start | timestamp_end ] \n\tSelect primitives to match (required by -N and -M)\n");
  printf("  -T\t[bytes|packets|flows] \n\tOutput top N statistics (applies to -M and -s)\n");
  printf("  -e\tClear statistics\n");
  printf("  -r\tReset counters (applies to -N and -M)\n");
  printf("  -l\tPerform locking of the table\n");
  printf("  -t\tShow memory table status\n");
  printf("  -C\tShow classifiers table\n");
  printf("  -D\tShow packet length distribution table\n");
  printf("  -p\t[file] \n\tSocket for client-server communication (DEFAULT: /tmp/collect.pipe)\n");
  printf("  -O\tSet output [ csv | event_formatted | event_csv ] (applies to -M and -s)\n");
  printf("  -E\tSet sparator for CSV format\n");
  printf("  -u\tLeave IP protocols in numerical format\n");
  printf("\n");
  printf("  See QUICKSTART file in the distribution for examples\n");
  printf("\n");
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

void write_stats_header_formatted(u_int64_t what_to_count, u_int64_t what_to_count_2, u_int8_t have_wtc, int is_event)
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
    printf("BGP_COMMS                ");
    printf("SRC_BGP_COMMS            ");
    printf("AS_PATH                  ");
    printf("SRC_AS_PATH              ");
    printf("PREF     ");
    printf("SRC_PREF ");
    printf("MED     ");
    printf("SRC_MED ");
    printf("SYM  ");
    printf("PEER_SRC_AS ");
    printf("PEER_DST_AS ");
#if defined ENABLE_IPV6
    printf("PEER_SRC_IP                                    ");
    printf("PEER_DST_IP                                    ");
#else
    printf("PEER_SRC_IP      ");
    printf("PEER_DST_IP      ");
#endif
#if defined ENABLE_IPV6
    printf("SRC_IP                                         ");
    printf("DST_IP                                         ");
#else
    printf("SRC_IP           ");
    printf("DST_IP           ");
#endif
    printf("SRC_MASK  ");
    printf("DST_MASK  ");
    printf("SRC_PORT  ");
    printf("DST_PORT  ");
    printf("TCP_FLAGS  ");
    printf("PROTOCOL    ");
    printf("TOS    ");
#if defined (WITH_GEOIP)
    printf("SH_COUNTRY  ");
    printf("DH_COUNTRY  "); 
#endif
    printf("SAMPLING_RATE ");
    printf("PKT_LEN_DISTRIB ");

#if defined ENABLE_IPV6
    printf("POST_NAT_SRC_IP                                ");
    printf("POST_NAT_DST_IP                                ");
#else
    printf("POST_NAT_SRC_IP  ");
    printf("POST_NAT_DST_IP  ");
#endif
    printf("POST_NAT_SRC_PORT  ");
    printf("POST_NAT_DST_PORT  ");
    printf("NAT_EVENT ");

    printf("TIMESTAMP_START                ");
    printf("TIMESTAMP_END                  ");

    if (!is_event) {
#if defined HAVE_64BIT_COUNTERS
      printf("PACKETS               ");
      printf("FLOWS                 ");
      printf("BYTES\n");
#else
      printf("PACKETS     ");
      printf("FLOWS       ");
      printf("BYTES\n");
#endif
    }
    else printf("\n");
  }
  else {
    if (what_to_count & COUNT_ID) printf("TAG         ");
    if (what_to_count & COUNT_ID2) printf("TAG2        ");
    if (what_to_count & COUNT_CLASS) printf("CLASS             ");
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
    if (what_to_count & (COUNT_STD_COMM|COUNT_EXT_COMM))
      printf("BGP_COMMS                ");
    if (what_to_count & (COUNT_SRC_STD_COMM|COUNT_SRC_EXT_COMM))
      printf("SRC_BGP_COMMS            ");
    if (what_to_count & COUNT_AS_PATH) printf("AS_PATH                  ");
    if (what_to_count & COUNT_SRC_AS_PATH) printf("SRC_AS_PATH              ");
    if (what_to_count & COUNT_LOCAL_PREF) printf("PREF     ");
    if (what_to_count & COUNT_SRC_LOCAL_PREF) printf("SRC_PREF ");
    if (what_to_count & COUNT_MED) printf("MED     ");
    if (what_to_count & COUNT_SRC_MED) printf("SRC_MED ");
    if (what_to_count & COUNT_PEER_SRC_AS) printf("PEER_SRC_AS ");
    if (what_to_count & COUNT_PEER_DST_AS) printf("PEER_DST_AS ");
#if defined ENABLE_IPV6
    if (what_to_count & COUNT_PEER_SRC_IP) printf("PEER_SRC_IP                                    ");
    if (what_to_count & COUNT_PEER_DST_IP) printf("PEER_DST_IP                                    ");
#else
    if (what_to_count & COUNT_PEER_SRC_IP) printf("PEER_SRC_IP      ");
    if (what_to_count & COUNT_PEER_DST_IP) printf("PEER_DST_IP      ");
#endif
    if (what_to_count & COUNT_MPLS_VPN_RD) printf("MPLS_VPN_RD         ");
#if defined ENABLE_IPV6
    if (what_to_count & (COUNT_SRC_HOST|COUNT_SRC_NET)) printf("SRC_IP                                         "); 
    if (what_to_count & (COUNT_SUM_HOST|COUNT_SUM_NET)) printf("SRC_IP                                         ");
    if (what_to_count & (COUNT_DST_HOST|COUNT_DST_NET)) printf("DST_IP                                         ");
#else
    if (what_to_count & (COUNT_SRC_HOST|COUNT_SRC_NET)) printf("SRC_IP           ");
    if (what_to_count & (COUNT_SUM_HOST|COUNT_SUM_NET)) printf("SRC_IP           ");
    if (what_to_count & (COUNT_DST_HOST|COUNT_DST_NET)) printf("DST_IP           ");
#endif
    if (what_to_count & COUNT_SRC_NMASK) printf("SRC_MASK  ");
    if (what_to_count & COUNT_DST_NMASK) printf("DST_MASK  "); 
    if (what_to_count & (COUNT_SRC_PORT|COUNT_SUM_PORT)) printf("SRC_PORT  ");
    if (what_to_count & COUNT_DST_PORT) printf("DST_PORT  "); 
    if (what_to_count & COUNT_TCPFLAGS) printf("TCP_FLAGS  "); 
    if (what_to_count & COUNT_IP_PROTO) printf("PROTOCOL    ");
    if (what_to_count & COUNT_IP_TOS) printf("TOS    ");

#ifdef WITH_GEOIP
    if (what_to_count_2 & COUNT_SRC_HOST_COUNTRY) printf("SH_COUNTRY  ");
    if (what_to_count_2 & COUNT_DST_HOST_COUNTRY) printf("DH_COUNTRY  "); 
#endif
    if (what_to_count_2 & COUNT_SAMPLING_RATE) printf("SAMPLING_RATE ");
    if (what_to_count_2 & COUNT_PKT_LEN_DISTRIB) printf("PKT_LEN_DISTRIB ");

#if defined ENABLE_IPV6
    if (what_to_count_2 & COUNT_POST_NAT_SRC_HOST) printf("POST_NAT_SRC_IP                                ");
    if (what_to_count_2 & COUNT_POST_NAT_DST_HOST) printf("POST_NAT_DST_IP                                ");
#else
    if (what_to_count_2 & COUNT_POST_NAT_SRC_HOST) printf("POST_NAT_SRC_IP  ");
    if (what_to_count_2 & COUNT_POST_NAT_DST_HOST) printf("POST_NAT_DST_IP  ");
#endif
    if (what_to_count_2 & COUNT_POST_NAT_SRC_PORT) printf("POST_NAT_SRC_PORT  ");
    if (what_to_count_2 & COUNT_POST_NAT_DST_PORT) printf("POST_NAT_DST_PORT  ");
    if (what_to_count_2 & COUNT_NAT_EVENT) printf("NAT_EVENT ");

    if (what_to_count_2 & COUNT_TIMESTAMP_START) printf("TIMESTAMP_START                ");
    if (what_to_count_2 & COUNT_TIMESTAMP_END) printf("TIMESTAMP_END                  "); 

    if (!is_event) {
#if defined HAVE_64BIT_COUNTERS
      printf("PACKETS               ");
      if (what_to_count & COUNT_FLOWS) printf("FLOWS                 ");
      printf("BYTES\n");
#else
      printf("PACKETS     ");
      if (what_to_count & COUNT_FLOWS) printf("FLOWS       ");
      printf("BYTES\n");
#endif
    }
    else printf("\n");
  }
}

char *write_sep(char *sep, int *count)
{
  static char empty_sep[] = "";

  if (*count) return sep;
  else {
    (*count)++;
    return empty_sep;
  }
}

void write_stats_header_csv(u_int64_t what_to_count, u_int64_t what_to_count_2, u_int8_t have_wtc, char *sep, int is_event)
{
  int count = 0;

  if (!have_wtc) {
    printf("%sTAG", write_sep(sep, &count));
    printf("%sTAG2", write_sep(sep, &count));
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
    printf("%sBGP_COMMS", write_sep(sep, &count));
    printf("%sSRC_BGP_COMMS", write_sep(sep, &count));
    printf("%sAS_PATH", write_sep(sep, &count));
    printf("%sSRC_AS_PATH", write_sep(sep, &count));
    printf("%sPREF", write_sep(sep, &count));
    printf("%sSRC_PREF", write_sep(sep, &count));
    printf("%sMED", write_sep(sep, &count));
    printf("%sSRC_MED", write_sep(sep, &count));
    printf("%sSYM", write_sep(sep, &count));
    printf("%sPEER_SRC_AS", write_sep(sep, &count));
    printf("%sPEER_DST_AS", write_sep(sep, &count));
#if defined ENABLE_IPV6
    printf("%sPEER_SRC_IP", write_sep(sep, &count));
    printf("%sPEER_DST_IP", write_sep(sep, &count));
#else
    printf("%sPEER_SRC_IP", write_sep(sep, &count));
    printf("%sPEER_DST_IP", write_sep(sep, &count));
#endif
#if defined ENABLE_IPV6
    printf("%sSRC_IP", write_sep(sep, &count));
    printf("%sDST_IP", write_sep(sep, &count));
#else
    printf("%sSRC_IP", write_sep(sep, &count));
    printf("%sDST_IP", write_sep(sep, &count));
#endif
    printf("%sSRC_MASK", write_sep(sep, &count));
    printf("%sDST_MASK", write_sep(sep, &count));
    printf("%sSRC_PORT", write_sep(sep, &count));
    printf("%sDST_PORT", write_sep(sep, &count));
    printf("%sTCP_FLAGS", write_sep(sep, &count));
    printf("%sPROTOCOL", write_sep(sep, &count));
    printf("%sTOS", write_sep(sep, &count));
#if defined WITH_GEOIP
    printf("%sSH_COUNTRY", write_sep(sep, &count));
    printf("%sDH_COUNTRY", write_sep(sep, &count));
#endif
    printf("%sSAMPLING_RATE", write_sep(sep, &count));
    printf("%sPKT_LEN_DISTRIB", write_sep(sep, &count));
    printf("%sPOST_NAT_SRC_IP", write_sep(sep, &count));
    printf("%sPOST_NAT_DST_IP", write_sep(sep, &count));
    printf("%sPOST_NAT_SRC_PORT", write_sep(sep, &count));
    printf("%sPOST_NAT_DST_PORT", write_sep(sep, &count));
    printf("%sNAT_EVENT", write_sep(sep, &count));
    printf("%sTIMESTAMP_START", write_sep(sep, &count));
    printf("%sTIMESTAMP_END", write_sep(sep, &count));
    if (!is_event) {
#if defined HAVE_64BIT_COUNTERS
      printf("%sPACKETS", write_sep(sep, &count));
      printf("%sFLOWS", write_sep(sep, &count));
      printf("%sBYTES\n", write_sep(sep, &count));
#else
      printf("%sPACKETS", write_sep(sep, &count));
      printf("%sFLOWS", write_sep(sep, &count));
      printf("%sBYTES\n", write_sep(sep, &count));
#endif
    }
    else printf("\n");
  }
  else {
    if (what_to_count & COUNT_ID) printf("%sTAG", write_sep(sep, &count));
    if (what_to_count & COUNT_ID2) printf("%sTAG2", write_sep(sep, &count));
    if (what_to_count & COUNT_CLASS) printf("%sCLASS", write_sep(sep, &count));
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
    if (what_to_count & (COUNT_STD_COMM|COUNT_EXT_COMM))
      printf("%sBGP_COMMS", write_sep(sep, &count));
    if (what_to_count & (COUNT_SRC_STD_COMM|COUNT_SRC_EXT_COMM))
      printf("%sSRC_BGP_COMMS", write_sep(sep, &count));
    if (what_to_count & COUNT_AS_PATH) printf("%sAS_PATH", write_sep(sep, &count));
    if (what_to_count & COUNT_SRC_AS_PATH) printf("%sSRC_AS_PATH", write_sep(sep, &count));
    if (what_to_count & COUNT_LOCAL_PREF) printf("%sPREF", write_sep(sep, &count));
    if (what_to_count & COUNT_SRC_LOCAL_PREF) printf("%sSRC_PREF", write_sep(sep, &count));
    if (what_to_count & COUNT_MED) printf("%sMED", write_sep(sep, &count));
    if (what_to_count & COUNT_SRC_MED) printf("%sSRC_MED", write_sep(sep, &count));
    if (what_to_count & COUNT_PEER_SRC_AS) printf("%sPEER_SRC_AS", write_sep(sep, &count));
    if (what_to_count & COUNT_PEER_DST_AS) printf("%sPEER_DST_AS", write_sep(sep, &count));
#if defined ENABLE_IPV6
    if (what_to_count & COUNT_PEER_SRC_IP) printf("%sPEER_SRC_IP", write_sep(sep, &count));
    if (what_to_count & COUNT_PEER_DST_IP) printf("%sPEER_DST_IP", write_sep(sep, &count));
#else
    if (what_to_count & COUNT_PEER_SRC_IP) printf("%sPEER_SRC_IP", write_sep(sep, &count));
    if (what_to_count & COUNT_PEER_DST_IP) printf("%sPEER_DST_IP", write_sep(sep, &count));
#endif
    if (what_to_count & COUNT_MPLS_VPN_RD) printf("%sMPLS_VPN_RD", write_sep(sep, &count));
#if defined ENABLE_IPV6
    if (what_to_count & (COUNT_SRC_HOST|COUNT_SRC_NET)) printf("%sSRC_IP", write_sep(sep, &count)); 
    if (what_to_count & (COUNT_SUM_HOST|COUNT_SUM_NET)) printf("%sSRC_IP", write_sep(sep, &count));
    if (what_to_count & (COUNT_DST_HOST|COUNT_DST_NET)) printf("%sDST_IP", write_sep(sep, &count));
#else
    if (what_to_count & (COUNT_SRC_HOST|COUNT_SRC_NET)) printf("%sSRC_IP", write_sep(sep, &count));
    if (what_to_count & (COUNT_SUM_HOST|COUNT_SUM_NET)) printf("%sSRC_IP", write_sep(sep, &count));
    if (what_to_count & (COUNT_DST_HOST|COUNT_DST_NET)) printf("%sDST_IP", write_sep(sep, &count));
#endif
    if (what_to_count & COUNT_SRC_NMASK) printf("%sSRC_MASK", write_sep(sep, &count));
    if (what_to_count & COUNT_DST_NMASK) printf("%sDST_MASK", write_sep(sep, &count)); 
    if (what_to_count & (COUNT_SRC_PORT|COUNT_SUM_PORT)) printf("%sSRC_PORT", write_sep(sep, &count));
    if (what_to_count & COUNT_DST_PORT) printf("%sDST_PORT", write_sep(sep, &count)); 
    if (what_to_count & COUNT_TCPFLAGS) printf("%sTCP_FLAGS", write_sep(sep, &count)); 
    if (what_to_count & COUNT_IP_PROTO) printf("%sPROTOCOL", write_sep(sep, &count));
    if (what_to_count & COUNT_IP_TOS) printf("%sTOS", write_sep(sep, &count));

#if defined WITH_GEOIP
    if (what_to_count_2 & COUNT_SRC_HOST_COUNTRY) printf("%sSH_COUNTRY", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_DST_HOST_COUNTRY) printf("%sDH_COUNTRY", write_sep(sep, &count));
#endif
    if (what_to_count_2 & COUNT_SAMPLING_RATE) printf("%sSAMPLING_RATE", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_PKT_LEN_DISTRIB) printf("%sPKT_LEN_DISTRIB", write_sep(sep, &count));

    if (what_to_count_2 & COUNT_POST_NAT_SRC_HOST) printf("%sPOST_NAT_SRC_IP", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_POST_NAT_DST_HOST) printf("%sPOST_NAT_DST_IP", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_POST_NAT_SRC_PORT) printf("%sPOST_NAT_SRC_PORT", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_POST_NAT_DST_PORT) printf("%sPOST_NAT_DST_PORT", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_NAT_EVENT) printf("%sNAT_EVENT", write_sep(sep, &count));

    if (what_to_count_2 & COUNT_TIMESTAMP_START) printf("%sTIMESTAMP_START", write_sep(sep, &count));
    if (what_to_count_2 & COUNT_TIMESTAMP_END) printf("%sTIMESTAMP_END", write_sep(sep, &count));

    if (!is_event) {
#if defined HAVE_64BIT_COUNTERS
      printf("%sPACKETS", write_sep(sep, &count));
      if (what_to_count & COUNT_FLOWS) printf("%sFLOWS", write_sep(sep, &count));
      printf("%sBYTES\n", write_sep(sep, &count));
#else
      printf("%sPACKETS", write_sep(sep, &count));
      if (what_to_count & COUNT_FLOWS) printf("%sFLOWS", write_sep(sep, &count));
      printf("%sBYTES\n", write_sep(sep, &count));
#endif
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

void write_pkt_len_distrib_table_header()
{
  printf("ID\tPKT_LEN_DISTRIB\n");
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
  struct pkt_data *acc_elem;
  struct bucket_desc *bd;
  struct query_header q; 
  struct pkt_primitives empty_addr;
  struct pkt_bgp_primitives empty_pbgp;
  struct pkt_nat_primitives empty_pnat;
  struct query_entry request;
  struct stripped_class *class_table = NULL;
  struct pkt_bgp_primitives *pbgp = NULL;
  struct pkt_nat_primitives *pnat= NULL;
  char clibuf[clibufsz], *bufptr;
  char *pkt_len_distrib_table[MAX_PKT_LEN_DISTRIB_BINS];
  unsigned char *largebuf, *elem, *ct, *pldt;
  char ethernet_address[18], ip_address[INET6_ADDRSTRLEN];
  char path[128], file[128], password[9], rd_str[SRVBUFLEN];
  char *as_path, empty_aspath[] = "^$", *bgp_comm, unknown_pkt_len_distrib[] = "not_recv";
  int sd, buflen, unpacked, printed;
  int counter=0, ct_idx=0, ct_num=0, sep_len=0;
  int pldt_idx=0, pldt_num=0, is_event;
  char *sep_ptr = NULL, sep[10], default_sep[] = ",";

  /* mrtg stuff */
  char match_string[LARGEBUFLEN], *match_string_token, *match_string_ptr;
  char count[128], *count_token[N_PRIMITIVES], *count_ptr;
  int count_index = 0, match_string_index = 0, index = 0;
  u_int64_t count_token_int[N_PRIMITIVES];
  
  /* getopt() stuff */
  extern char *optarg;
  extern int optind, opterr, optopt;
  int errflag, cp, want_stats, want_erase, want_reset, want_class_table; 
  int want_status, want_mrtg, want_counter, want_match, want_all_fields;
  int want_output, want_ipproto_num, want_pkt_len_distrib_table;
  int which_counter, topN_counter, fetch_from_file, sum_counters, num_counters;
  int datasize;
  u_int64_t what_to_count, what_to_count_2, have_wtc;
  u_int32_t tmpnum;
  struct extra_primitives extras;

  /* Administrativia */
  memset(&q, 0, sizeof(struct query_header));
  memset(&empty_addr, 0, sizeof(struct pkt_primitives));
  memset(&empty_pbgp, 0, sizeof(struct pkt_bgp_primitives));
  memset(&empty_pnat, 0, sizeof(struct pkt_nat_primitives));
  memset(count, 0, sizeof(count));
  memset(password, 0, sizeof(password)); 
  memset(sep, 0, sizeof(sep));
  memset(pkt_len_distrib_table, 0, sizeof(pkt_len_distrib_table));

  strcpy(path, "/tmp/collect.pipe");
  unpacked = 0; printed = 0;
  errflag = 0; buflen = 0;
  protocols_number = 0;
  want_stats = FALSE;
  want_erase = FALSE;
  want_status = FALSE;
  want_counter = FALSE;
  want_mrtg = FALSE;
  want_match = FALSE;
  want_all_fields = FALSE;
  want_reset = FALSE;
  want_class_table = FALSE;
  want_ipproto_num = FALSE;
  want_pkt_len_distrib_table = FALSE;
  which_counter = FALSE;
  topN_counter = FALSE;
  sum_counters = FALSE;
  num_counters = FALSE;
  fetch_from_file = FALSE;
  what_to_count = FALSE;
  what_to_count_2 = FALSE;
  have_wtc = FALSE;
  want_output = PRINT_OUTPUT_FORMATTED;
  is_event = FALSE;

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
      count_ptr = count;
      while ((*count_ptr != '\0') && (count_index <= N_PRIMITIVES-1)) {
        count_token[count_index] = pmc_extract_token(&count_ptr, ',');
	if (!strcmp(count_token[count_index], "src_host")) {
	  count_token_int[count_index] = COUNT_SRC_HOST;
	  what_to_count |= COUNT_SRC_HOST;
	}
        else if (!strcmp(count_token[count_index], "dst_host")) {
	  count_token_int[count_index] = COUNT_DST_HOST;
	  what_to_count |= COUNT_DST_HOST;
	}
        else if (!strcmp(count_token[count_index], "sum")) {
	  count_token_int[count_index] = COUNT_SUM_HOST;
	  what_to_count |= COUNT_SUM_HOST;
	}
        else if (!strcmp(count_token[count_index], "src_port")) {
	  count_token_int[count_index] = COUNT_SRC_PORT;
	  what_to_count |= COUNT_SRC_PORT;
	}
        else if (!strcmp(count_token[count_index], "dst_port")) {
	  count_token_int[count_index] = COUNT_DST_PORT;
	  what_to_count |= COUNT_DST_PORT;
	}
        else if (!strcmp(count_token[count_index], "proto")) {
	  count_token_int[count_index] = COUNT_IP_PROTO;
	  what_to_count |= COUNT_IP_PROTO;
	}
#if defined HAVE_L2
        else if (!strcmp(count_token[count_index], "src_mac")) {
	  count_token_int[count_index] = COUNT_SRC_MAC;
	  what_to_count |= COUNT_SRC_MAC;
	}
        else if (!strcmp(count_token[count_index], "dst_mac")) {
	  count_token_int[count_index] = COUNT_DST_MAC;
	  what_to_count |= COUNT_DST_MAC;
	}
        else if (!strcmp(count_token[count_index], "vlan")) {
	  count_token_int[count_index] = COUNT_VLAN;
	  what_to_count |= COUNT_VLAN;
	}
        else if (!strcmp(count_token[count_index], "cos")) {
          count_token_int[count_index] = COUNT_COS;
          what_to_count |= COUNT_COS;
        }
        else if (!strcmp(count_token[count_index], "etype")) {
          count_token_int[count_index] = COUNT_ETHERTYPE;
          what_to_count |= COUNT_ETHERTYPE;
        }
	else if (!strcmp(count_token[count_index], "sum_mac")) {
	  count_token_int[count_index] = COUNT_SUM_MAC;
	  what_to_count |= COUNT_SUM_MAC;
	}
#endif 
        else if (!strcmp(count_token[count_index], "in_iface")) {
          count_token_int[count_index] = COUNT_IN_IFACE;
          what_to_count |= COUNT_IN_IFACE;
        }
        else if (!strcmp(count_token[count_index], "out_iface")) {
          count_token_int[count_index] = COUNT_OUT_IFACE;
          what_to_count |= COUNT_OUT_IFACE;
        }
        else if (!strcmp(count_token[count_index], "tos")) {
	  count_token_int[count_index] = COUNT_IP_TOS;
	  what_to_count |= COUNT_IP_TOS;
	}
#if defined WITH_GEOIP
        else if (!strcmp(count_token[count_index], "src_host_country")) {
          count_token_int[count_index] = COUNT_SRC_HOST_COUNTRY;
          what_to_count_2 |= COUNT_SRC_HOST_COUNTRY;
        }
        else if (!strcmp(count_token[count_index], "dst_host_country")) {
          count_token_int[count_index] = COUNT_DST_HOST_COUNTRY;
          what_to_count_2 |= COUNT_DST_HOST_COUNTRY;
        }
#endif
        else if (!strcmp(count_token[count_index], "sampling_rate")) {
	  count_token_int[count_index] = COUNT_SAMPLING_RATE;
	  what_to_count_2 |= COUNT_SAMPLING_RATE;
	}
        else if (!strcmp(count_token[count_index], "none")) {
	  count_token_int[count_index] = COUNT_NONE;
	  what_to_count |= COUNT_NONE;
	}
        else if (!strcmp(count_token[count_index], "src_as")) {
	  count_token_int[count_index] = COUNT_SRC_AS;
	  what_to_count |= COUNT_SRC_AS;
	}
        else if (!strcmp(count_token[count_index], "dst_as")) {
	  count_token_int[count_index] = COUNT_DST_AS;
	  what_to_count |= COUNT_DST_AS;
	}
        else if (!strcmp(count_token[count_index], "src_net")) {
	  count_token_int[count_index] = COUNT_SRC_NET;
	  what_to_count |= COUNT_SRC_NET;
	}
        else if (!strcmp(count_token[count_index], "dst_net")) {
	  count_token_int[count_index] = COUNT_DST_NET;
	  what_to_count |= COUNT_DST_NET;
	}
        else if (!strcmp(count_token[count_index], "sum_host")) {
	  count_token_int[count_index] = COUNT_SUM_HOST;
	  what_to_count |= COUNT_SUM_HOST;
	}
        else if (!strcmp(count_token[count_index], "sum_net")) {
	  count_token_int[count_index] = COUNT_SUM_NET;
	  what_to_count |= COUNT_SUM_NET;
	}
        else if (!strcmp(count_token[count_index], "sum_as")) {
	  count_token_int[count_index] = COUNT_SUM_AS;
	  what_to_count |= COUNT_SUM_AS;
	}
        else if (!strcmp(count_token[count_index], "sum_port")) {
	  count_token_int[count_index] = COUNT_SUM_PORT;
	  what_to_count |= COUNT_SUM_PORT;
	}
        else if (!strcmp(count_token[count_index], "src_mask")) {
          count_token_int[count_index] = COUNT_SRC_NMASK;
          what_to_count |= COUNT_SRC_NMASK;
        }
        else if (!strcmp(count_token[count_index], "dst_mask")) {
          count_token_int[count_index] = COUNT_DST_NMASK;
          what_to_count |= COUNT_DST_NMASK;
        }
        else if (!strcmp(count_token[count_index], "tag")) {
	  count_token_int[count_index] = COUNT_ID;
	  what_to_count |= COUNT_ID;
	}
        else if (!strcmp(count_token[count_index], "tag2")) {
          count_token_int[count_index] = COUNT_ID2;
          what_to_count |= COUNT_ID2;
        }
        else if (!strcmp(count_token[count_index], "class")) {
          count_token_int[count_index] = COUNT_CLASS;
          what_to_count |= COUNT_CLASS;
        }
        else if (!strcmp(count_token[count_index], "pkt_len_distrib")) {
          count_token_int[count_index] = COUNT_PKT_LEN_DISTRIB;
          what_to_count_2 |= COUNT_PKT_LEN_DISTRIB;
        }
        else if (!strcmp(count_token[count_index], "std_comm")) {
          count_token_int[count_index] = COUNT_STD_COMM;
          what_to_count |= COUNT_STD_COMM;
        }
        else if (!strcmp(count_token[count_index], "src_std_comm")) {
          count_token_int[count_index] = COUNT_SRC_STD_COMM;
          what_to_count |= COUNT_SRC_STD_COMM;
        }
        else if (!strcmp(count_token[count_index], "ext_comm")) {
          count_token_int[count_index] = COUNT_EXT_COMM;
          what_to_count |= COUNT_EXT_COMM;
        }
        else if (!strcmp(count_token[count_index], "src_ext_comm")) {
          count_token_int[count_index] = COUNT_SRC_EXT_COMM;
          what_to_count |= COUNT_SRC_EXT_COMM;
        }
        else if (!strcmp(count_token[count_index], "as_path")) {
          count_token_int[count_index] = COUNT_AS_PATH;
          what_to_count |= COUNT_AS_PATH;
        }
        else if (!strcmp(count_token[count_index], "src_as_path")) {
          count_token_int[count_index] = COUNT_SRC_AS_PATH;
          what_to_count |= COUNT_SRC_AS_PATH;
        }
        else if (!strcmp(count_token[count_index], "local_pref")) {
          count_token_int[count_index] = COUNT_LOCAL_PREF;
          what_to_count |= COUNT_LOCAL_PREF;
        }
        else if (!strcmp(count_token[count_index], "src_local_pref")) {
          count_token_int[count_index] = COUNT_SRC_LOCAL_PREF;
          what_to_count |= COUNT_SRC_LOCAL_PREF;
	}
        else if (!strcmp(count_token[count_index], "med")) {
          count_token_int[count_index] = COUNT_MED;
          what_to_count |= COUNT_MED;
        }
        else if (!strcmp(count_token[count_index], "src_med")) {
          count_token_int[count_index] = COUNT_SRC_MED;
          what_to_count |= COUNT_SRC_MED;
        }
        else if (!strcmp(count_token[count_index], "peer_src_as")) {
          count_token_int[count_index] = COUNT_PEER_SRC_AS;
          what_to_count |= COUNT_PEER_SRC_AS;
        }
        else if (!strcmp(count_token[count_index], "peer_dst_as")) {
          count_token_int[count_index] = COUNT_PEER_DST_AS;
          what_to_count |= COUNT_PEER_DST_AS;
        }
        else if (!strcmp(count_token[count_index], "peer_src_ip")) {
          count_token_int[count_index] = COUNT_PEER_SRC_IP;
          what_to_count |= COUNT_PEER_SRC_IP;
        }
        else if (!strcmp(count_token[count_index], "peer_dst_ip")) {
          count_token_int[count_index] = COUNT_PEER_DST_IP;
          what_to_count |= COUNT_PEER_DST_IP;
        }
        else if (!strcmp(count_token[count_index], "mpls_vpn_rd")) {
          count_token_int[count_index] = COUNT_MPLS_VPN_RD;
          what_to_count |= COUNT_MPLS_VPN_RD;
        }
        else if (!strcmp(count_token[count_index], "post_nat_src_host")) {
          count_token_int[count_index] = COUNT_POST_NAT_SRC_HOST;
          what_to_count_2 |= COUNT_POST_NAT_SRC_HOST;
        }
        else if (!strcmp(count_token[count_index], "post_nat_dst_host")) {
          count_token_int[count_index] = COUNT_POST_NAT_DST_HOST;
          what_to_count_2 |= COUNT_POST_NAT_DST_HOST;
        }
        else if (!strcmp(count_token[count_index], "post_nat_src_port")) {
          count_token_int[count_index] = COUNT_POST_NAT_SRC_PORT;
          what_to_count_2 |= COUNT_POST_NAT_SRC_PORT;
        }
        else if (!strcmp(count_token[count_index], "post_nat_dst_port")) {
          count_token_int[count_index] = COUNT_POST_NAT_DST_PORT;
          what_to_count_2 |= COUNT_POST_NAT_DST_HOST;
        }
        else if (!strcmp(count_token[count_index], "nat_event")) {
          count_token_int[count_index] = COUNT_NAT_EVENT;
          what_to_count_2 |= COUNT_NAT_EVENT;
        }
        else if (!strcmp(count_token[count_index], "timestamp_start")) {
          count_token_int[count_index] = COUNT_TIMESTAMP_START;
          what_to_count_2 |= COUNT_TIMESTAMP_START;
        }
        else if (!strcmp(count_token[count_index], "timestamp_end")) {
          count_token_int[count_index] = COUNT_TIMESTAMP_END;
          what_to_count_2 |= COUNT_TIMESTAMP_END;
        }
        else printf("WARN: ignoring unknown aggregation method: %s.\n", count_token[count_index]);
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
    case 'D':
      if (CHECK_Q_TYPE(q.type)) print_ex_options_error();
      q.type |= WANT_PKT_LEN_DISTRIB_TABLE;
      q.num = 1;
      want_pkt_len_distrib_table = TRUE;
      break;
    case 'e':
      q.type |= WANT_ERASE; 
      want_erase = TRUE;
      break;
    case 't':
      if (CHECK_Q_TYPE(q.type)) print_ex_options_error();
      q.type |= WANT_STATUS; 
      want_status = TRUE;
      break;
    case 'l':
      q.type |= WANT_LOCK_OP;
      break;
    case 'm': /* obsoleted */
      want_mrtg = TRUE;
    case 'N':
      if (CHECK_Q_TYPE(q.type)) print_ex_options_error();
      strlcpy(match_string, optarg, sizeof(match_string));
      match_string[LARGEBUFLEN-1] = '\0';
      q.type |= WANT_COUNTER; 
      want_counter = TRUE;
      break;
    case 'n':
      if (!strcmp(optarg, "bytes")) which_counter = 0;
      else if (!strcmp(optarg, "packets")) which_counter = 1;
      else if (!strcmp(optarg, "flows")) which_counter = 3;
      else if (!strcmp(optarg, "all")) which_counter = 2;
      else printf("WARN: -n, ignoring unknown counter type: %s.\n", optarg);
      break;
    case 'T':
      if (!strcmp(optarg, "bytes")) topN_counter = 1;
      else if (!strcmp(optarg, "packets")) topN_counter = 2;
      else if (!strcmp(optarg, "flows")) topN_counter = 3;
      else printf("WARN: -T, ignoring unknown counter type: %s.\n", optarg);
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
      if (!strcmp(optarg, "formatted"))
        want_output = PRINT_OUTPUT_FORMATTED;
      else if (!strcmp(optarg, "csv"))
        want_output = PRINT_OUTPUT_CSV;
      else if (!strcmp(optarg, "event_formatted")) {
	want_output = PRINT_OUTPUT_FORMATTED;
        want_output |= PRINT_OUTPUT_EVENT;
      }
      else if (!strcmp(optarg, "event_csv")) {
	want_output = PRINT_OUTPUT_CSV;
        want_output |= PRINT_OUTPUT_EVENT;
      }
      else printf("WARN: -O, ignoring unknown output value: '%s'.\n", optarg);
      break;
    case 'E':
      strlcpy(sep, optarg, sizeof(sep));
      break;
    case 'u':
      want_ipproto_num = TRUE;
      break;
    default:
      printf("ERROR: parameter %c unknown! \n  Exiting...\n\n", cp);
      usage_client(argv[0]);
      exit(1);
      break;
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
    printf("ERROR: -E option expects a single char as separator\n  Exiting...\n\n");
    exit(1);
  }

  /* Sanitizing the aggregation method */ 
  if (what_to_count || what_to_count_2) {
    if (what_to_count & COUNT_STD_COMM && what_to_count & COUNT_EXT_COMM) {
      printf("ERROR: The use of STANDARD and EXTENDED BGP communitities is mutual exclusive.\n");
      exit(1);
    }
    if (what_to_count & COUNT_SRC_STD_COMM && what_to_count & COUNT_SRC_EXT_COMM) {
      printf("ERROR: The use of STANDARD and EXTENDED BGP communitities is mutual exclusive.\n");
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
          request.what_to_count ^= count_token_int[match_string_index];	  
	  match_string_index++;
	  continue;
	}

        if (!strcmp(count_token[match_string_index], "src_host") ||
	    !strcmp(count_token[match_string_index], "src_net") ||
	    !strcmp(count_token[match_string_index], "sum_host") ||
	    !strcmp(count_token[match_string_index], "sum_net")) {
	  if (!str_to_addr(match_string_token, &request.data.src_ip)) {
	    printf("ERROR: src_host: Invalid IP address: '%s'\n", match_string_token);
	    exit(1);
	  }
        }
        else if (!strcmp(count_token[match_string_index], "dst_host") ||
		 !strcmp(count_token[match_string_index], "dst_net")) {
          if (!str_to_addr(match_string_token, &request.data.dst_ip)) {
            printf("ERROR: dst_host: Invalid IP address: '%s'\n", match_string_token);
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
            printf("ERROR: src_mac: Invalid MAC address: '%s'\n", match_string_token);
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
	  sscanf(match_string_token, "%x", &request.data.etype);
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
          request.data.src_ip_country = GeoIP_id_by_code(match_string_token);
        }
        else if (!strcmp(count_token[match_string_index], "dst_host_country")) {
          request.data.dst_ip_country = GeoIP_id_by_code(match_string_token);
        }
#endif
	else if (!strcmp(count_token[match_string_index], "sampling_rate")) {
	  request.data.sampling_rate = atoi(match_string_token);
	}
        else if (!strcmp(count_token[match_string_index], "proto")) {
	  int proto;

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
	  request.data.id = value; 
	}
        else if (!strcmp(count_token[match_string_index], "tag2")) {
          char *endptr = NULL;
          u_int32_t value;

          value = strtoull(match_string_token, &endptr, 10);
          request.data.id2 = value;
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
	    Recv(sd, &ct);
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
        }
	else if (!strcmp(count_token[match_string_index], "pkt_len_distrib")) {
          struct stripped_pkt_len_distrib *pldt_elem, req_elem;
          struct query_header qhdr;
          u_int16_t req_value = 0;

          memset(&req_elem, 0, sizeof(req_elem));
          strlcpy(req_elem.str, match_string_token, MAX_PKT_LEN_DISTRIB_LEN);
          req_elem.str[MAX_PKT_LEN_DISTRIB_LEN-1] = '\0';

	  memset(&qhdr, 0, sizeof(struct query_header));
	  qhdr.type = WANT_PKT_LEN_DISTRIB_TABLE;
	  qhdr.num = 1;

	  memcpy(clibuf, &qhdr, sizeof(struct query_header));
	  buflen = sizeof(struct query_header);
	  buflen++;
	  clibuf[buflen] = '\x4'; /* EOT */
	  buflen++;

	  sd = build_query_client(path);
	  send(sd, clibuf, buflen, 0);
	  Recv(sd, &pldt);

	  pldt_num = ((struct query_header *)pldt)->num;
	  elem = pldt+sizeof(struct query_header);
	  pldt_elem = (struct stripped_pkt_len_distrib *) elem;
	  while (pldt_idx < pldt_num) {
	    pkt_len_distrib_table[pldt_idx] = pldt_elem->str;
	    if (!strcmp(req_elem.str, pkt_len_distrib_table[pldt_idx])) req_value = pldt_idx;
	    pldt_idx++; pldt_elem++;
	  }

          if (!pldt_num) {
            printf("ERROR: Server has not loaded any packet length distributions.\n");
            exit(1);
          }
	  else request.data.pkt_len_distrib = req_value;
	}
        else if (!strcmp(count_token[match_string_index], "std_comm")) {
	  if (!strcmp(match_string_token, "0"))
	    memset(request.pbgp.std_comms, 0, MAX_BGP_STD_COMMS);
	  else {
            strlcpy(request.pbgp.std_comms, match_string_token, MAX_BGP_STD_COMMS);
	    bgp_comm = request.pbgp.std_comms;
	    while (bgp_comm) {
	      bgp_comm = strchr(request.pbgp.std_comms, '_');
	      if (bgp_comm) *bgp_comm = ' ';
	    }
	  }
	}
        else if (!strcmp(count_token[match_string_index], "src_std_comm")) {
          if (!strcmp(match_string_token, "0"))
            memset(request.pbgp.src_std_comms, 0, MAX_BGP_STD_COMMS);
          else {
            strlcpy(request.pbgp.src_std_comms, match_string_token, MAX_BGP_STD_COMMS);
            bgp_comm = request.pbgp.src_std_comms;
            while (bgp_comm) {
              bgp_comm = strchr(request.pbgp.src_std_comms, '_');
              if (bgp_comm) *bgp_comm = ' ';
            }
          }
        }
        else if (!strcmp(count_token[match_string_index], "ext_comm")) {
          if (!strcmp(match_string_token, "0"))
            memset(request.pbgp.ext_comms, 0, MAX_BGP_EXT_COMMS);
          else {
            strlcpy(request.pbgp.ext_comms, match_string_token, MAX_BGP_EXT_COMMS);
            bgp_comm = request.pbgp.ext_comms;
            while (bgp_comm) {
              bgp_comm = strchr(request.pbgp.ext_comms, '_');
              if (bgp_comm) *bgp_comm = ' ';
            }
	  }
	}
        else if (!strcmp(count_token[match_string_index], "src_ext_comm")) {
          if (!strcmp(match_string_token, "0"))
            memset(request.pbgp.src_ext_comms, 0, MAX_BGP_EXT_COMMS);
          else {
            strlcpy(request.pbgp.src_ext_comms, match_string_token, MAX_BGP_EXT_COMMS);
            bgp_comm = request.pbgp.src_ext_comms;
            while (bgp_comm) {
              bgp_comm = strchr(request.pbgp.src_ext_comms, '_');
              if (bgp_comm) *bgp_comm = ' ';
            }
          }
        }
        else if (!strcmp(count_token[match_string_index], "as_path")) {
	  if (!strcmp(match_string_token, "^$"))
	    memset(request.pbgp.as_path, 0, MAX_BGP_ASPATH);
	  else {
            strlcpy(request.pbgp.as_path, match_string_token, MAX_BGP_ASPATH);
            as_path = request.pbgp.as_path;
            while (as_path) {
              as_path = strchr(request.pbgp.as_path, '_');
              if (as_path) *as_path = ' ';
            }
	  }
	}
        else if (!strcmp(count_token[match_string_index], "src_as_path")) {
          if (!strcmp(match_string_token, "^$"))
            memset(request.pbgp.src_as_path, 0, MAX_BGP_ASPATH);
          else {
            strlcpy(request.pbgp.src_as_path, match_string_token, MAX_BGP_ASPATH);
            as_path = request.pbgp.src_as_path;
            while (as_path) {
              as_path = strchr(request.pbgp.src_as_path, '_');
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
        else if (!strcmp(count_token[match_string_index], "post_nat_src_host")) {
          if (!str_to_addr(match_string_token, &request.pnat.post_nat_src_ip)) {
            printf("ERROR: src_host: Invalid IP address: '%s'\n", match_string_token);
            exit(1);
          }
        }
        else if (!strcmp(count_token[match_string_index], "post_nat_dst_host")) {
          if (!str_to_addr(match_string_token, &request.pnat.post_nat_dst_ip)) {
            printf("ERROR: dst_host: Invalid IP address: '%s'\n", match_string_token);
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
        else if (!strcmp(count_token[match_string_index], "timestamp_start")) {
	  // XXX
        }
        else if (!strcmp(count_token[match_string_index], "timestamp_end")) {
	  // XXX
        }
        else printf("WARN: ignoring unknown aggregation method: '%s'.\n", *count_token);
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
    if (want_all_fields) have_wtc = FALSE; 
    else have_wtc = TRUE; 
    what_to_count = ((struct query_header *)largebuf)->what_to_count;
    what_to_count_2 = ((struct query_header *)largebuf)->what_to_count_2;
    datasize = ((struct query_header *)largebuf)->datasize;
    memcpy(&extras, &((struct query_header *)largebuf)->extras, sizeof(struct extra_primitives));
    if (check_data_sizes((struct query_header *)largebuf, acc_elem)) exit(1);

    /* Before going on with the output, we need to retrieve the class strings
       from the server */
    if (what_to_count & COUNT_CLASS && !class_table) {
      struct query_header qhdr;

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
      Recv(sd, &ct); 
      ct_num = ((struct query_header *)ct)->num;
      elem = ct+sizeof(struct query_header);
      class_table = (struct stripped_class *) elem;
      while (ct_idx < ct_num) {
	class_table[ct_idx].protocol[MAX_PROTOCOL_LEN-1] = '\0';
        ct_idx++;
      }
    }

    if (what_to_count_2 & COUNT_PKT_LEN_DISTRIB && !pkt_len_distrib_table[0]) {
      struct stripped_pkt_len_distrib *pldt_elem;
      struct query_header qhdr;

      memset(&qhdr, 0, sizeof(struct query_header));
      qhdr.type = WANT_PKT_LEN_DISTRIB_TABLE;
      qhdr.num = 1;

      memcpy(clibuf, &qhdr, sizeof(struct query_header));
      buflen = sizeof(struct query_header);
      buflen++;
      clibuf[buflen] = '\x4'; /* EOT */
      buflen++;

      sd = build_query_client(path);
      send(sd, clibuf, buflen, 0);
      Recv(sd, &pldt);

      pldt_num = ((struct query_header *)pldt)->num;
      elem = pldt+sizeof(struct query_header);
      pldt_elem = (struct stripped_pkt_len_distrib *) elem;
      while (pldt_idx < pldt_num) {
        pkt_len_distrib_table[pldt_idx] = pldt_elem->str;
        pldt_idx++; pldt_elem++;
      }
    }

    if (want_output & PRINT_OUTPUT_FORMATTED)
      write_stats_header_formatted(what_to_count, what_to_count_2, have_wtc, is_event);
    else if (want_output & PRINT_OUTPUT_CSV)
      write_stats_header_csv(what_to_count, what_to_count_2, have_wtc, sep_ptr, is_event);

    elem = largebuf+sizeof(struct query_header);
    unpacked -= sizeof(struct query_header);

    acc_elem = (struct pkt_data *) elem;
    if (topN_counter) {
      int num = unpacked/datasize;

      client_counters_merge_sort((void *)acc_elem, 0, num, datasize, topN_counter);
    }

    while (printed < unpacked) {
      int count = 0;

      acc_elem = (struct pkt_data *) elem;

      if (extras.off_pkt_bgp_primitives) pbgp = (struct pkt_bgp_primitives *) ((u_char *)elem + extras.off_pkt_bgp_primitives);
      else pbgp = &empty_pbgp;

      if (extras.off_pkt_nat_primitives) pnat = (struct pkt_nat_primitives *) ((u_char *)elem + extras.off_pkt_nat_primitives);
      else pnat = &empty_pnat;

      if (memcmp(&acc_elem, &empty_addr, sizeof(struct pkt_primitives)) != 0 || 
	  memcmp(pbgp, &empty_pbgp, sizeof(struct pkt_bgp_primitives)) != 0 ||
	  memcmp(pnat, &empty_pnat, sizeof(struct pkt_nat_primitives)) != 0) {
        if (!have_wtc || (what_to_count & COUNT_ID)) {
	  if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-10llu  ", acc_elem->primitives.id);
	  else if (want_output & PRINT_OUTPUT_CSV) printf("%s%llu", write_sep(sep_ptr, &count), acc_elem->primitives.id);
	}

        if (!have_wtc || (what_to_count & COUNT_ID2)) {
	  if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-10llu  ", acc_elem->primitives.id2);
	  else if (want_output & PRINT_OUTPUT_CSV) printf("%s%llu", write_sep(sep_ptr, &count), acc_elem->primitives.id2);
	}

        if (!have_wtc || (what_to_count & COUNT_CLASS)) {
           if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-16s  ", (acc_elem->primitives.class == 0 || acc_elem->primitives.class > ct_idx ||
							!class_table[acc_elem->primitives.class-1].id) ? "unknown" : class_table[acc_elem->primitives.class-1].protocol);
           else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count),
				(acc_elem->primitives.class == 0 || acc_elem->primitives.class > ct_idx ||
				!class_table[acc_elem->primitives.class-1].id) ? "unknown" : class_table[acc_elem->primitives.class-1].protocol);
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

	/* Slightly special "!have_wtc" handling due to standard and
	   extended BGP communities being mutual exclusive */
	if ((!have_wtc && !(what_to_count & COUNT_EXT_COMM)) || (what_to_count & COUNT_STD_COMM)) {
	  bgp_comm = pbgp->std_comms;
	  while (bgp_comm) {
	    bgp_comm = strchr(pbgp->std_comms, ' ');
	    if (bgp_comm) *bgp_comm = '_';
	  }
          if (strlen(pbgp->std_comms)) {
	    if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-22s   ", pbgp->std_comms);
	    else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), pbgp->std_comms);
	  }
	  else {
	    if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-22u   ", 0);
	    else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), 0);
	  }
        }

	if ((!have_wtc && !(what_to_count & COUNT_SRC_EXT_COMM)) || (what_to_count & COUNT_SRC_STD_COMM)) {
	  bgp_comm = pbgp->src_std_comms;
	  while (bgp_comm) {
	    bgp_comm = strchr(pbgp->src_std_comms, ' ');
	    if (bgp_comm) *bgp_comm = '_';
	  }
          if (strlen(pbgp->src_std_comms)) {
	    if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-22s   ", pbgp->src_std_comms);
	    else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), pbgp->src_std_comms);
	  }
	  else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-22u   ", 0);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), 0);
	  }
        }

        if (what_to_count & COUNT_EXT_COMM) {
          bgp_comm = pbgp->ext_comms;
          while (bgp_comm) {
            bgp_comm = strchr(pbgp->ext_comms, ' ');
            if (bgp_comm) *bgp_comm = '_';
          }
          if (strlen(pbgp->ext_comms)) {
	    if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-22s   ", pbgp->ext_comms);
	    else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), pbgp->ext_comms);
	  }
	  else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-22u   ", 0);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), 0);
	  }
        }

        if (what_to_count & COUNT_SRC_EXT_COMM) {
          bgp_comm = pbgp->src_ext_comms;
          while (bgp_comm) {
            bgp_comm = strchr(pbgp->src_ext_comms, ' ');
            if (bgp_comm) *bgp_comm = '_';
          }
          if (strlen(pbgp->src_ext_comms)) {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-22s   ", pbgp->src_ext_comms);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), pbgp->src_ext_comms);
	  }
          else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-22u   ", 0);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), 0);
          }
        }

        if (!have_wtc || (what_to_count & COUNT_AS_PATH)) {
	  as_path = pbgp->as_path;
	  while (as_path) {
	    as_path = strchr(pbgp->as_path, ' ');
	    if (as_path) *as_path = '_';
	  }
          if (strlen(pbgp->as_path)) {
	    if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-22s   ", pbgp->as_path);
	    else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), pbgp->as_path);
	  }
	  else {
	    if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-22s   ", empty_aspath); 
	    else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), pbgp->as_path); 
	  }
        }

        if (!have_wtc || (what_to_count & COUNT_SRC_AS_PATH)) {
	  as_path = pbgp->src_as_path;
	  while (as_path) {
	    as_path = strchr(pbgp->src_as_path, ' ');
	    if (as_path) *as_path = '_';
	  }
          if (strlen(pbgp->src_as_path)) {
	    if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-22s   ", pbgp->src_as_path);
	    else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), pbgp->src_as_path);
	  }
          else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-22s   ", empty_aspath);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), empty_aspath);
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

#if defined ENABLE_IPV6
          if (strlen(ip_address)) {
	    if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45s  ", ip_address);
	    else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), ip_address);
	  }
          else {
	    if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45u  ", 0);
	    else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), 0);
	  }
#else
          if (strlen(ip_address)) {
	    if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-15s  ", ip_address);
	    else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), ip_address);
	  }
          else {
	    if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-15u  ", 0);
	    else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), 0);
	  }
#endif
        }

        if (!have_wtc || (what_to_count & COUNT_PEER_DST_IP)) {
          addr_to_str(ip_address, &pbgp->peer_dst_ip);

#if defined ENABLE_IPV6
          if (strlen(ip_address)) {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45s  ", ip_address);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), ip_address);
          }
          else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45u  ", 0);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), 0);
          }
#else
          if (strlen(ip_address)) {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-15s  ", ip_address);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), ip_address);
          }
          else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-15u  ", 0);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), 0);
          }
#endif
        }

        if (!have_wtc || (what_to_count & COUNT_MPLS_VPN_RD)) {
          pmc_bgp_rd2str(rd_str, (rd_t *) &pbgp->mpls_vpn_rd);

          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-18s  ", rd_str);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), rd_str);
	}

	if (!have_wtc || (what_to_count & (COUNT_SRC_HOST|COUNT_SUM_HOST|
					   COUNT_SRC_NET|COUNT_SUM_NET))) {
	  addr_to_str(ip_address, &acc_elem->primitives.src_ip);

#if defined ENABLE_IPV6
          if (strlen(ip_address)) {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45s  ", ip_address);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), ip_address);
          }
          else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45u  ", 0);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), 0);
          }
#else
          if (strlen(ip_address)) {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-15s  ", ip_address);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), ip_address);
          }
          else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-15u  ", 0);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), 0);
          }
#endif
	}

	if (!have_wtc || (what_to_count & (COUNT_DST_HOST|COUNT_DST_NET))) {
	  addr_to_str(ip_address, &acc_elem->primitives.dst_ip);

#if defined ENABLE_IPV6
          if (strlen(ip_address)) {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45s  ", ip_address);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), ip_address);
          }
          else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45u  ", 0);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), 0);
          }
#else
          if (strlen(ip_address)) {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-15s  ", ip_address);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), ip_address);
          }
          else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-15u  ", 0);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), 0);
          }
#endif
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
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-5s       ", GeoIP_code_by_id(acc_elem->primitives.src_ip_country));
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), GeoIP_code_by_id(acc_elem->primitives.src_ip_country));
        }

        if (!have_wtc || (what_to_count_2 & COUNT_DST_HOST_COUNTRY)) {
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-5s       ", GeoIP_code_by_id(acc_elem->primitives.dst_ip_country));
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), GeoIP_code_by_id(acc_elem->primitives.dst_ip_country));
        }
#endif

	if (!have_wtc || (what_to_count_2 & COUNT_SAMPLING_RATE)) {
	  if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-7u       ", acc_elem->primitives.sampling_rate); 
	  else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), acc_elem->primitives.sampling_rate); 
	}

        if (!have_wtc || (what_to_count_2 & COUNT_PKT_LEN_DISTRIB)) {
          char *pkt_len_distrib_table_ptr = NULL;

          if (pkt_len_distrib_table[0])
	    pkt_len_distrib_table_ptr = pkt_len_distrib_table[acc_elem->primitives.pkt_len_distrib];
	  else
	    pkt_len_distrib_table_ptr = unknown_pkt_len_distrib;

          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-10s      ", pkt_len_distrib_table_ptr);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), pkt_len_distrib_table_ptr);
        }

        if (!have_wtc || (what_to_count_2 & COUNT_POST_NAT_SRC_HOST)) {
          addr_to_str(ip_address, &pnat->post_nat_src_ip);

#if defined ENABLE_IPV6
          if (strlen(ip_address)) {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45s  ", ip_address);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), ip_address);
          }
          else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45u  ", 0);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), 0);
          }
#else
          if (strlen(ip_address)) {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-15s  ", ip_address);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), ip_address);
          }
          else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-15u  ", 0);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), 0);
          }
#endif
        }

        if (!have_wtc || (what_to_count_2 & COUNT_POST_NAT_DST_HOST)) {
          addr_to_str(ip_address, &pnat->post_nat_dst_ip);

#if defined ENABLE_IPV6
          if (strlen(ip_address)) {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45s  ", ip_address);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), ip_address);
          }
          else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-45u  ", 0);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), 0);
          }
#else
          if (strlen(ip_address)) {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-15s  ", ip_address);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), ip_address);
          }
          else {
            if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-15u  ", 0);
            else if (want_output & PRINT_OUTPUT_CSV) printf("%s%u", write_sep(sep_ptr, &count), 0);
          }
#endif
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

        if (!have_wtc || (what_to_count_2 & COUNT_TIMESTAMP_START)) {
	  char buf1[SRVBUFLEN], buf2[SRVBUFLEN];
	  time_t time1;
	  struct tm *time2;

	  time1 = pnat->timestamp_start.tv_sec;
	  time2 = localtime(&time1);
	  strftime(buf1, SRVBUFLEN, "%Y-%m-%d %H:%M:%S", time2);
	  snprintf(buf2, SRVBUFLEN, "%s.%u", buf1, pnat->timestamp_start.tv_usec);
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-30s ", buf2);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), buf2);
        }

        if (!have_wtc || (what_to_count_2 & COUNT_TIMESTAMP_END)) {
          char buf1[SRVBUFLEN], buf2[SRVBUFLEN];
          time_t time1;
          struct tm *time2;

          time1 = pnat->timestamp_end.tv_sec;
          time2 = localtime(&time1);
          strftime(buf1, SRVBUFLEN, "%Y-%m-%d %H:%M:%S", time2);
          snprintf(buf2, SRVBUFLEN, "%s.%u", buf1, pnat->timestamp_end.tv_usec);
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-30s ", buf2);
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%s", write_sep(sep_ptr, &count), buf2);
        }

	if (!(want_output & PRINT_OUTPUT_EVENT)) {
#if defined HAVE_64BIT_COUNTERS
	  if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-20llu  ", acc_elem->pkt_num);
	  else if (want_output & PRINT_OUTPUT_CSV) printf("%s%llu", write_sep(sep_ptr, &count), acc_elem->pkt_num);

	  if (!have_wtc || (what_to_count & COUNT_FLOWS)) {
	    if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-20llu  ", acc_elem->flo_num);
	    else if (want_output & PRINT_OUTPUT_CSV) printf("%s%llu", write_sep(sep_ptr, &count), acc_elem->flo_num);
	  }

	  printf("%s%llu\n", write_sep(sep_ptr, &count), acc_elem->pkt_len);
#else
          if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-10lu  ", acc_elem->pkt_num); 
          else if (want_output & PRINT_OUTPUT_CSV) printf("%s%lu", write_sep(sep_ptr, &count), acc_elem->pkt_num); 

          if (!have_wtc || (what_to_count & COUNT_FLOWS)) {
	    if (want_output & PRINT_OUTPUT_FORMATTED) printf("%-10lu  ", acc_elem->flo_num); 
	    else if (want_output & PRINT_OUTPUT_CSV) printf("%s%lu", write_sep(sep_ptr, &count), acc_elem->flo_num); 
	  }

          printf("%s%lu\n", write_sep(sep_ptr, &count), acc_elem->pkt_len); 
#endif
        }
	else printf("\n");

        counter++;
      }
      elem += datasize;
      printed += datasize;
    }
    if (want_output & PRINT_OUTPUT_FORMATTED) printf("\nFor a total of: %d entries\n", counter);
  }
  else if (want_erase) printf("OK: Clearing stats.\n");
  else if (want_status) {
    unpacked = Recv(sd, &largebuf);
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
  else if (want_counter) {
    unsigned char *base;
#if defined HAVE_64BIT_COUNTERS
    u_int64_t bcnt = 0, pcnt = 0, fcnt = 0;
#else
    u_int32_t bcnt = 0, pcnt = 0, fcnt = 0; 
#endif
    int printed;

    unpacked = Recv(sd, &largebuf);
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
#if defined HAVE_64BIT_COUNTERS
	/* print bytes */
        if (which_counter == 0) printf("%llu\n", acc_elem->pkt_len); 
	/* print packets */
	else if (which_counter == 1) printf("%llu\n", acc_elem->pkt_num); 
	/* print packets+bytes+flows+num */
	else if (which_counter == 2) printf("%llu %llu %llu %lu\n", acc_elem->pkt_num, acc_elem->pkt_len, acc_elem->flo_num, acc_elem->time_start.tv_sec);
	/* print flows */
	else if (which_counter == 3) printf("%llu\n", acc_elem->flo_num);
#else
        if (which_counter == 0) printf("%lu\n", acc_elem->pkt_len); 
        else if (which_counter == 1) printf("%lu\n", acc_elem->pkt_num); 
        else if (which_counter == 2) printf("%lu %lu %lu %lu\n", acc_elem->pkt_num, acc_elem->pkt_len, acc_elem->flo_num, acc_elem->time_start.tv_sec); 
        else if (which_counter == 3) printf("%lu\n", acc_elem->flo_num); 
#endif
      }
    }
      
    if (sum_counters) {
#if defined HAVE_64BIT_COUNTERS
      if (which_counter == 0) printf("%llu\n", bcnt); /* print bytes */
      else if (which_counter == 1) printf("%llu\n", pcnt); /* print packets */
      else if (which_counter == 2) printf("%llu %llu %llu %u\n", pcnt, bcnt, fcnt, num_counters); /* print packets+bytes+flows+num */
      else if (which_counter == 3) printf("%llu\n", fcnt); /* print flows */
#else
      if (which_counter == 0) printf("%lu\n", bcnt); 
      else if (which_counter == 1) printf("%lu\n", pcnt); 
      else if (which_counter == 2) printf("%lu %lu %lu %u\n", pcnt, bcnt, fcnt, num_counters); 
      else if (which_counter == 3) printf("%lu\n", fcnt); 
#endif
    }
  }
  else if (want_class_table) { 
    int ct_eff=0;

    Recv(sd, &ct);
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
  else if (want_pkt_len_distrib_table) {
    struct stripped_pkt_len_distrib *pldt_elem;
    int pldt_eff=0;

    Recv(sd, &pldt);
    write_pkt_len_distrib_table_header();
    pldt_num = ((struct query_header *)pldt)->num;
    elem = pldt+sizeof(struct query_header);
    pldt_elem = (struct stripped_pkt_len_distrib *) elem;
    while (pldt_idx < pldt_num) {
      pkt_len_distrib_table[pldt_idx] = pldt_elem->str;
      printf("%u\t%s\n", pldt_idx, pkt_len_distrib_table[pldt_idx]);
      pldt_idx++; pldt_elem++;
    }
    printf("\nFor a total of: %d packet length distributions\n", pldt_idx);
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
  int num, unpacked = 0, round = 0; 
  unsigned char rxbuf[LARGEBUFLEN], *elem;

  *buf = (unsigned char *) malloc(LARGEBUFLEN);
  memset(*buf, 0, LARGEBUFLEN);
  memset(rxbuf, 0, LARGEBUFLEN);

  do {
    num = recv(sd, rxbuf, LARGEBUFLEN, 0);
    if (num > 0) {
      /* check 1: enough space in allocated buffer */
      if (unpacked+num >= round*LARGEBUFLEN) {
        round++;
        *buf = realloc((unsigned char *) *buf, round*LARGEBUFLEN);
        if (!(*buf)) {
          printf("ERROR: realloc() out of memory\n");
          exit(1);
        }
        /* ensuring realloc() didn't move somewhere else our memory area */
        elem = *buf;
        elem += unpacked;
      }
      /* check 2: enough space in dss */
      if (((u_int32_t)elem+num) > (u_int32_t)sbrk(0)) sbrk(LARGEBUFLEN);

      memcpy(elem, rxbuf, num);
      unpacked += num;
      elem += num;
    }
  } while (num > 0);

  return unpacked;
}

int check_data_sizes(struct query_header *qh, struct pkt_data *acc_elem)
{
  if (qh->cnt_sz != sizeof(acc_elem->pkt_len)) {
    printf("ERROR: Counter sizes mismatch: daemon: %d  client: %d\n", qh->cnt_sz*8, sizeof(acc_elem->pkt_len)*8);
    printf("ERROR: It's very likely that a 64bit package has been mixed with a 32bit one.\n\n");
    printf("ERROR: Please fix the issue before trying again.\n");
    return (qh->cnt_sz-sizeof(acc_elem->pkt_len));
  }

  if (qh->ip_sz != sizeof(acc_elem->primitives.src_ip)) {
    printf("ERROR: IP address sizes mismatch. daemon: %d  client: %d\n", qh->ip_sz, sizeof(acc_elem->primitives.src_ip));
    printf("ERROR: It's very likely that an IPv6-enabled package has been mixed with a IPv4-only one.\n\n");
    printf("ERROR: Please fix the issue before trying again.\n");
    return (qh->ip_sz-sizeof(acc_elem->primitives.src_ip));
  } 

  return 0;
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

  if ((!v1) || (!v2)) printf("ERROR: Memory sold out while sorting statistics.\n");

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

int pmc_bgp_rd2str(char *str, rd_t *rd)
{
  struct rd_ip  *rdi;
  struct rd_as  *rda;
  struct rd_as4 *rda4;
  struct host_addr a;
  u_char ip_address[INET6_ADDRSTRLEN];

  switch (rd->type) {
  case RD_TYPE_AS:
    rda = (struct rd_as *) rd;
    sprintf(str, "%u:%u:%u", rda->type, rda->as, rda->val);
    break;
  case RD_TYPE_IP:
    rdi = (struct rd_ip *) rd;
    a.family = AF_INET;
    a.address.ipv4.s_addr = rdi->ip.s_addr;
    addr_to_str(ip_address, &a);
    sprintf(str, "%u:%s:%u", rdi->type, ip_address, rdi->val);
    break;
  case RD_TYPE_AS4:
    rda4 = (struct rd_as4 *) rd;
    sprintf(str, "%u:%u:%u", rda4->type, rda4->as, rda4->val);
    break;
  default:
    sprintf(str, "unknown");
    break;
  }
}

int pmc_bgp_str2rd(rd_t *output, char *value)
{
  struct host_addr a;
  char *endptr, *token;
  u_int32_t tmp32;
  u_int16_t tmp16;
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

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

#define __SQL_HANDLERS_C

/*
  PG_* functions are used only by PostgreSQL plugin;
  MY_* functions are used only by MySQL plugin;
  count_* functions are used by more than one plugin;
  fake_* functions are used to supply static zero-filled values;
*/ 

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "sql_common.h"
#include "ip_flow.h"
#include "classifier.h"

static const char fake_mac[] = "0:0:0:0:0:0";
static const char fake_host[] = "0.0.0.0";
static const char fake_as[] = "0";
static const char fake_comm[] = "";
static const char fake_as_path[] = "";

/* Functions */
#if defined (HAVE_L2)
void count_src_mac_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char sbuf[18];
  u_int8_t ubuf[ETH_ADDR_LEN];

  memcpy(&ubuf, &cache_elem->primitives.eth_shost, ETH_ADDR_LEN);
  etheraddr_string(ubuf, sbuf);
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, sbuf);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, sbuf);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, sbuf);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_dst_mac_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char sbuf[18];
  u_int8_t ubuf[ETH_ADDR_LEN];

  memcpy(ubuf, &cache_elem->primitives.eth_dhost, ETH_ADDR_LEN);
  etheraddr_string(ubuf, sbuf);
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, sbuf);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, sbuf);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_vlan_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.vlan_id);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.vlan_id);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_cos_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.cos);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.cos);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_etype_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.etype);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.etype);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}
#endif

void count_src_host_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char ptr[INET6_ADDRSTRLEN];

  addr_to_str(ptr, &cache_elem->primitives.src_ip);
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_src_as_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.src_as);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.src_as);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_dst_host_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char ptr[INET6_ADDRSTRLEN];

  addr_to_str(ptr, &cache_elem->primitives.dst_ip);
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_dst_as_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.dst_as);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.dst_as);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_in_iface_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.ifindex_in);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.ifindex_in);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_out_iface_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.ifindex_out);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.ifindex_out);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_src_nmask_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.src_nmask);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.src_nmask);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_dst_nmask_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.dst_nmask);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.dst_nmask);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

#if defined WITH_GEOIP
void count_src_host_country_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, GeoIP_code_by_id(cache_elem->primitives.src_ip_country));
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, GeoIP_code_by_id(cache_elem->primitives.src_ip_country));
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_dst_host_country_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, GeoIP_code_by_id(cache_elem->primitives.dst_ip_country));
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, GeoIP_code_by_id(cache_elem->primitives.dst_ip_country));
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}
#endif

void count_sampling_rate_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.sampling_rate);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.sampling_rate);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_pkt_len_distrib_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, idata->cfg->pkt_len_distrib_bins[cache_elem->primitives.pkt_len_distrib]);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, idata->cfg->pkt_len_distrib_bins[cache_elem->primitives.pkt_len_distrib]);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_post_nat_src_ip_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char ptr[INET6_ADDRSTRLEN];

  addr_to_str(ptr, &cache_elem->pnat->post_nat_src_ip);
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_post_nat_dst_ip_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char ptr[INET6_ADDRSTRLEN];

  addr_to_str(ptr, &cache_elem->pnat->post_nat_dst_ip);
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_post_nat_src_port_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pnat->post_nat_src_port);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->pnat->post_nat_src_port);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_post_nat_dst_port_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pnat->post_nat_dst_port);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->pnat->post_nat_dst_port);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_nat_event_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pnat->nat_event);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->pnat->nat_event);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void PG_copy_count_timestamp_start_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  static char time_str[LONGSRVBUFLEN];
  struct tm *tme;

  tme = localtime(&cache_elem->pnat->timestamp_start.tv_sec);
  strftime(time_str, LONGSRVBUFLEN, "%Y-%m-%d %H:%M:%S", tme);

  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pnat->timestamp_start.tv_sec); // dummy
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, time_str);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_timestamp_start_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pnat->timestamp_start.tv_sec);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->pnat->timestamp_start.tv_sec);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_timestamp_start_residual_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pnat->timestamp_start.tv_usec);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->pnat->timestamp_start.tv_usec);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void PG_copy_count_timestamp_end_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  static char time_str[LONGSRVBUFLEN];
  struct tm *tme;

  tme = localtime(&cache_elem->pnat->timestamp_end.tv_sec);
  strftime(time_str, LONGSRVBUFLEN, "%Y-%m-%d %H:%M:%S", tme);

  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pnat->timestamp_end.tv_sec); // dummy
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, time_str);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_timestamp_end_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pnat->timestamp_end.tv_sec);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->pnat->timestamp_end.tv_sec);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_timestamp_end_residual_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->pnat->timestamp_end.tv_usec);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->pnat->timestamp_end.tv_usec);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_std_comm_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->cbgp->std_comms);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->cbgp->std_comms);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_ext_comm_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->cbgp->ext_comms);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->cbgp->ext_comms);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_as_path_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->cbgp->as_path);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->cbgp->as_path);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_src_std_comm_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->cbgp->src_std_comms);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->cbgp->src_std_comms);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_src_ext_comm_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->cbgp->src_ext_comms);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->cbgp->src_ext_comms);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_src_as_path_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->cbgp->src_as_path);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->cbgp->src_as_path);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_local_pref_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->cbgp->local_pref);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->cbgp->local_pref);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_src_local_pref_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->cbgp->src_local_pref);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->cbgp->src_local_pref);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_med_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->cbgp->med);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->cbgp->med);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_src_med_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->cbgp->src_med);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->cbgp->src_med);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_mpls_vpn_rd_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char ptr[SRVBUFLEN];

  bgp_rd2str(ptr, &cache_elem->cbgp->mpls_vpn_rd);
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_peer_src_as_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->cbgp->peer_src_as);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->cbgp->peer_src_as);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_peer_dst_as_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->cbgp->peer_dst_as);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->cbgp->peer_dst_as);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_peer_src_ip_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char ptr[INET6_ADDRSTRLEN];

  addr_to_str(ptr, &cache_elem->cbgp->peer_src_ip);
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_peer_dst_ip_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char ptr[INET6_ADDRSTRLEN], *indirect_ptr = ptr;

  addr_to_str(ptr, &cache_elem->cbgp->peer_dst_ip);
  if (!strlen(ptr)) indirect_ptr = (char *) fake_host;
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, indirect_ptr);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, indirect_ptr);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_src_port_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.src_port);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.src_port);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_dst_port_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.dst_port);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.dst_port);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_tcpflags_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->tcp_flags);
  *ptr_values += strlen(*ptr_values);
}

void count_ip_tos_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.tos);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.tos);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}


void MY_count_ip_proto_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  if (cache_elem->primitives.proto < protocols_number) {
    snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, _protocols[cache_elem->primitives.proto].name);
    snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, _protocols[cache_elem->primitives.proto].name);
  }
  else {
    char proto_str[PROTO_LEN];

    snprintf(proto_str, sizeof(proto_str), "%d", cache_elem->primitives.proto);
    snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, proto_str);
    snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, proto_str);
  }
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void PG_count_ip_proto_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.proto);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.proto);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_copy_timestamp_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  static char btime_str[LONGSRVBUFLEN], now_str[LONGSRVBUFLEN];
  struct tm *tme;

  tme = localtime(&cache_elem->basetime);
  strftime(btime_str, LONGSRVBUFLEN, "%Y-%m-%d %H:%M:%S", tme);

  tme = localtime(&idata->now);
  strftime(now_str, LONGSRVBUFLEN, "%Y-%m-%d %H:%M:%S", tme);
  
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->basetime); // dummy
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, now_str, btime_str);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_timestamp_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  time_t tme = idata->now;

  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->basetime);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, tme, cache_elem->basetime);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_id_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.id);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.id);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_id2_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, cache_elem->primitives.id2);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, cache_elem->primitives.id2);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_class_id_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  char buf[MAX_PROTOCOL_LEN+1];

  memset(buf, 0, MAX_PROTOCOL_LEN+1);
  if (cache_elem->primitives.class && class[cache_elem->primitives.class-1].id) {
    strlcpy(buf, class[cache_elem->primitives.class-1].protocol, MAX_PROTOCOL_LEN);
    buf[sizeof(buf)-1] = '\0';
  }
  else strlcpy(buf, "unknown", MAX_PROTOCOL_LEN);

  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, buf);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, buf);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void count_counters_setclause_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_set, char **ptr_none)
{
  snprintf(*ptr_set, SPACELEFT(set_clause), set[num].string, cache_elem->packet_counter, cache_elem->bytes_counter);
  *ptr_set  += strlen(*ptr_set);
}

void count_flows_setclause_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_set, char **ptr_none)
{
  snprintf(*ptr_set, SPACELEFT(set_clause), set[num].string, cache_elem->flows_counter);
  *ptr_set  += strlen(*ptr_set);
}

void count_tcpflags_setclause_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_set, char **ptr_none)
{
  snprintf(*ptr_set, SPACELEFT(set_clause), set[num].string, cache_elem->tcp_flags);
  *ptr_set  += strlen(*ptr_set);
}

void count_noop_setclause_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_set, char **ptr_none)
{
  strncpy(*ptr_set, set[num].string, SPACELEFT(set_clause));
  *ptr_set  += strlen(*ptr_set);
}

void count_noop_setclause_event_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_set, char **ptr_none)
{
  strncpy(*ptr_set, set_event[num].string, SPACELEFT(set_clause));
  *ptr_set  += strlen(*ptr_set);
}

/* Fake handlers next */ 
void fake_mac_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, fake_mac);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, fake_mac);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void fake_host_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, fake_host);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, fake_host);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void fake_as_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, fake_as);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, fake_as);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void fake_comms_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, fake_comm);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, fake_comm);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

void fake_as_path_handler(const struct db_cache *cache_elem, const struct insert_data *idata, int num, char **ptr_values, char **ptr_where)
{
  snprintf(*ptr_where, SPACELEFT(where_clause), where[num].string, fake_as_path);
  snprintf(*ptr_values, SPACELEFT(values_clause), values[num].string, fake_as_path);
  *ptr_where += strlen(*ptr_where);
  *ptr_values += strlen(*ptr_values);
}

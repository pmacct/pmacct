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

#define __CFG_HANDLERS_C

/* includes */
#include "pmacct.h"
#include "nfacctd.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "cfg_handlers.h"

int parse_truefalse(char *value_ptr)
{
  int value;

  lower_string(value_ptr);
  
  if (!strcmp("true", value_ptr)) value = TRUE;
  else if (!strcmp("false", value_ptr)) value = FALSE;
  else value = ERR;

  return value;
}

int cfg_key_debug(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr); 
  if (value < 0) return ERR; 

  if (!name) for (; list; list = list->next, changes++) list->cfg.debug = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) { 
	list->cfg.debug = value;
	changes++;
	break;
      }
    }
  }

  return changes;
}

int cfg_key_syslog(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.syslog = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.syslog = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_logfile(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.logfile = value_ptr;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'logfile'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pidfile(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.pidfile = value_ptr;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'pidfile'. Globalized.\n", filename);

  return changes;
}

int cfg_key_daemonize(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.daemon = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'daemonize'. Globalized.\n", filename); 

  return changes;
}

int cfg_key_aggregate(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  char *count_token;
  u_int64_t value[3];
  u_int32_t changes = 0; 

  trim_all_spaces(value_ptr);
  memset(&value, 0, sizeof(value));

  while (count_token = extract_token(&value_ptr, ',')) {
    if (!strcmp(count_token, "src_host")) cfg_set_aggregate(filename, value, COUNT_INT_SRC_HOST, count_token);
    else if (!strcmp(count_token, "dst_host")) cfg_set_aggregate(filename, value, COUNT_INT_DST_HOST, count_token);
    else if (!strcmp(count_token, "src_net")) cfg_set_aggregate(filename, value, COUNT_INT_SRC_NET, count_token);
    else if (!strcmp(count_token, "dst_net")) cfg_set_aggregate(filename, value, COUNT_INT_DST_NET, count_token);
    else if (!strcmp(count_token, "sum")) cfg_set_aggregate(filename, value, COUNT_INT_SUM_HOST, count_token);
    else if (!strcmp(count_token, "src_port")) cfg_set_aggregate(filename, value, COUNT_INT_SRC_PORT, count_token);
    else if (!strcmp(count_token, "dst_port")) cfg_set_aggregate(filename, value, COUNT_INT_DST_PORT, count_token);
    else if (!strcmp(count_token, "proto")) cfg_set_aggregate(filename, value, COUNT_INT_IP_PROTO, count_token);
#if defined (HAVE_L2)
    else if (!strcmp(count_token, "src_mac")) cfg_set_aggregate(filename, value, COUNT_INT_SRC_MAC, count_token);
    else if (!strcmp(count_token, "dst_mac")) cfg_set_aggregate(filename, value, COUNT_INT_DST_MAC, count_token);
    else if (!strcmp(count_token, "vlan")) cfg_set_aggregate(filename, value, COUNT_INT_VLAN, count_token);
    else if (!strcmp(count_token, "sum_mac")) cfg_set_aggregate(filename, value, COUNT_INT_SUM_MAC, count_token);
#endif
    else if (!strcmp(count_token, "tos")) cfg_set_aggregate(filename, value, COUNT_INT_IP_TOS, count_token);
    else if (!strcmp(count_token, "none")) cfg_set_aggregate(filename, value, COUNT_INT_NONE, count_token);
    else if (!strcmp(count_token, "src_as")) cfg_set_aggregate(filename, value, COUNT_INT_SRC_AS, count_token);
    else if (!strcmp(count_token, "dst_as")) cfg_set_aggregate(filename, value, COUNT_INT_DST_AS, count_token);
    else if (!strcmp(count_token, "sum_host")) cfg_set_aggregate(filename, value, COUNT_INT_SUM_HOST, count_token);
    else if (!strcmp(count_token, "sum_net")) cfg_set_aggregate(filename, value, COUNT_INT_SUM_NET, count_token);
    else if (!strcmp(count_token, "sum_as")) cfg_set_aggregate(filename, value, COUNT_INT_SUM_AS, count_token);
    else if (!strcmp(count_token, "sum_port")) cfg_set_aggregate(filename, value, COUNT_INT_SUM_PORT, count_token);
    else if (!strcmp(count_token, "tag")) cfg_set_aggregate(filename, value, COUNT_INT_ID, count_token);
    else if (!strcmp(count_token, "tag2")) cfg_set_aggregate(filename, value, COUNT_INT_ID2, count_token);
    else if (!strcmp(count_token, "flows")) cfg_set_aggregate(filename, value, COUNT_INT_FLOWS, count_token);
    else if (!strcmp(count_token, "class")) cfg_set_aggregate(filename, value, COUNT_INT_CLASS, count_token);
    else if (!strcmp(count_token, "tcpflags")) cfg_set_aggregate(filename, value, COUNT_INT_TCPFLAGS, count_token);
    else if (!strcmp(count_token, "std_comm")) cfg_set_aggregate(filename, value, COUNT_INT_STD_COMM, count_token);
    else if (!strcmp(count_token, "ext_comm")) cfg_set_aggregate(filename, value, COUNT_INT_EXT_COMM, count_token);
    else if (!strcmp(count_token, "as_path")) cfg_set_aggregate(filename, value, COUNT_INT_AS_PATH, count_token);
    else if (!strcmp(count_token, "local_pref")) cfg_set_aggregate(filename, value, COUNT_INT_LOCAL_PREF, count_token);
    else if (!strcmp(count_token, "med")) cfg_set_aggregate(filename, value, COUNT_INT_MED, count_token);
    else if (!strcmp(count_token, "peer_src_as")) cfg_set_aggregate(filename, value, COUNT_INT_PEER_SRC_AS, count_token);
    else if (!strcmp(count_token, "peer_dst_as")) cfg_set_aggregate(filename, value, COUNT_INT_PEER_DST_AS, count_token);
    else if (!strcmp(count_token, "peer_src_ip")) cfg_set_aggregate(filename, value, COUNT_INT_PEER_SRC_IP, count_token);
    else if (!strcmp(count_token, "peer_dst_ip")) cfg_set_aggregate(filename, value, COUNT_INT_PEER_DST_IP, count_token);
    else if (!strcmp(count_token, "src_as_path")) cfg_set_aggregate(filename, value, COUNT_INT_SRC_AS_PATH, count_token);
    else if (!strcmp(count_token, "src_std_comm")) cfg_set_aggregate(filename, value, COUNT_INT_SRC_STD_COMM, count_token);
    else if (!strcmp(count_token, "src_ext_comm")) cfg_set_aggregate(filename, value, COUNT_INT_SRC_EXT_COMM, count_token);
    else if (!strcmp(count_token, "src_local_pref")) cfg_set_aggregate(filename, value, COUNT_INT_SRC_LOCAL_PREF, count_token);
    else if (!strcmp(count_token, "src_med")) cfg_set_aggregate(filename, value, COUNT_INT_SRC_MED, count_token);
    else if (!strcmp(count_token, "in_iface")) cfg_set_aggregate(filename, value, COUNT_INT_IN_IFACE, count_token);
    else if (!strcmp(count_token, "out_iface")) cfg_set_aggregate(filename, value, COUNT_INT_OUT_IFACE, count_token);
    else if (!strcmp(count_token, "src_mask")) cfg_set_aggregate(filename, value, COUNT_INT_SRC_NMASK, count_token);
    else if (!strcmp(count_token, "dst_mask")) cfg_set_aggregate(filename, value, COUNT_INT_DST_NMASK, count_token);
    else if (!strcmp(count_token, "cos")) cfg_set_aggregate(filename, value, COUNT_INT_COS, count_token);
    else if (!strcmp(count_token, "etype")) cfg_set_aggregate(filename, value, COUNT_INT_ETHERTYPE, count_token);
    else if (!strcmp(count_token, "mpls_vpn_rd")) cfg_set_aggregate(filename, value, COUNT_INT_MPLS_VPN_RD, count_token);
    else if (!strcmp(count_token, "sampling_rate")) cfg_set_aggregate(filename, value, COUNT_INT_SAMPLING_RATE, count_token);
    else if (!strcmp(count_token, "src_host_country")) cfg_set_aggregate(filename, value, COUNT_INT_SRC_HOST_COUNTRY, count_token);
    else if (!strcmp(count_token, "dst_host_country")) cfg_set_aggregate(filename, value, COUNT_INT_DST_HOST_COUNTRY, count_token);
    else if (!strcmp(count_token, "pkt_len_distrib")) cfg_set_aggregate(filename, value, COUNT_INT_PKT_LEN_DISTRIB, count_token);
    else if (!strcmp(count_token, "post_nat_src_host")) cfg_set_aggregate(filename, value, COUNT_INT_POST_NAT_SRC_HOST, count_token);
    else if (!strcmp(count_token, "post_nat_dst_host")) cfg_set_aggregate(filename, value, COUNT_INT_POST_NAT_DST_HOST, count_token);
    else if (!strcmp(count_token, "post_nat_src_port")) cfg_set_aggregate(filename, value, COUNT_INT_POST_NAT_SRC_PORT, count_token);
    else if (!strcmp(count_token, "post_nat_dst_port")) cfg_set_aggregate(filename, value, COUNT_INT_POST_NAT_DST_PORT, count_token);
    else if (!strcmp(count_token, "nat_event")) cfg_set_aggregate(filename, value, COUNT_INT_NAT_EVENT, count_token);
    else if (!strcmp(count_token, "timestamp_start")) cfg_set_aggregate(filename, value, COUNT_INT_TIMESTAMP_START, count_token);
    else if (!strcmp(count_token, "timestamp_end")) cfg_set_aggregate(filename, value, COUNT_INT_TIMESTAMP_END, count_token);
    else Log(LOG_WARNING, "WARN ( %s ): ignoring unknown aggregation method: %s.\n", filename, count_token);
  }

  if (!name) for (; list; list = list->next, changes++) {
    list->cfg.what_to_count = value[1];
    list->cfg.what_to_count_2 = value[2];
  }
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.what_to_count = value[1];
        list->cfg.what_to_count_2 = value[2];
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_snaplen(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < DEFAULT_SNAPLEN) {
    Log(LOG_WARNING, "WARN ( %s ): 'snaplen' has to be >= %d.\n", filename, DEFAULT_SNAPLEN);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.snaplen = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'snaplen'. Globalized.\n", filename);

  return changes;
}

int cfg_key_aggregate_filter(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) {
    Log(LOG_ERR, "ERROR ( %s ): aggregation filter cannot be global. Not loaded.\n", filename);
    changes++;
  }
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.a_filter = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_pre_tag_filter(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) {
    Log(LOG_ERR, "ERROR ( %s ): TAG filter cannot be global. Not loaded.\n", filename);
    changes++;
  }
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
	changes = load_tags(filename, &list->cfg.ptf, value_ptr);
        break;
      }
    }
  }

  return changes;
}

int cfg_key_pre_tag2_filter(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  char *count_token, *range_ptr;
  pm_id_t value = 0, range = 0;
  int changes = 0;
  char *endptr_v, *endptr_r;
  u_int8_t neg;

  if (!name) {
    Log(LOG_ERR, "ERROR ( %s ): TAG2 filter cannot be global. Not loaded.\n", filename);
    changes++;
  }
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        changes = load_tags(filename, &list->cfg.pt2f, value_ptr);
        break;
      }
    }
  }

  return changes;
}


int cfg_key_pcap_filter(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.clbuf = value_ptr;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'pcap_filter'. Globalized.\n", filename);

  return changes;
}

int cfg_key_interface(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.dev = value_ptr;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'interface'. Globalized.\n", filename);

  return changes;
}

int cfg_key_files_umask(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;
  char *endp;

  value = strtoul(value_ptr, &endp, 8);
  if (value < 2) {
    Log(LOG_WARNING, "WARN ( %s ): 'files_umask' has to be >= '002'.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.files_umask = value & 0666;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.files_umask = value & 0666;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_files_uid(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 1) {
    Log(LOG_ERR, "WARN ( %s ): 'files_uid' has to be >= 1.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.files_uid = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.files_uid = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_files_gid(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 1) {
    Log(LOG_ERR, "WARN ( %s ): 'files_gid' has to be >= 1.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.files_gid = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.files_gid = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_interface_wait(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.if_wait = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'interface_wait'. Globalized.\n", filename);

  return changes;
}

int cfg_key_savefile_wait(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.sf_wait = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'savefile_wait'. Globalized.\n", filename);

  return changes;
}

int cfg_key_promisc(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.promisc = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'promisc'. Globalized.\n", filename);

  return changes;
}

int cfg_key_imt_path(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.imt_plugin_path = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.imt_plugin_path = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_imt_passwd(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.imt_plugin_passwd = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.imt_plugin_passwd = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_imt_buckets(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN ( %s ): 'imt_buckets' has to be > 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.buckets = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.buckets = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_imt_mem_pools_number(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;
  
  value = atoi(value_ptr);
  if (value < 0) {
    Log(LOG_WARNING, "WARN ( %s ): 'imt_mem_pools_number' has to be >= 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.num_memory_pools = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.num_memory_pools = value;
        changes++;
        break;
      }
    }
  }

  have_num_memory_pools = TRUE;
  return changes;
}

int cfg_key_imt_mem_pools_size(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  /* legal values should be >= sizeof(struct acc), though we are unable to check
     this condition here. Thus, this function will just cut clearly wrong values
     ie. < = 0. Strict checks will be accomplished later, by the memory plugin */ 
  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN ( %s ): 'imt_mem_pools_size' has to be > 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.memory_pool_size = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.memory_pool_size = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_db(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_db = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_db = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_table(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  /* validations: we allow only a) certain variable names, b) a maximum of 8 variables
     and c) a maximum table name length of 64 chars */ 
  {
    int num = 0;
    char *c, *ptr = value_ptr;

    while (c = strchr(ptr, '%')) {
      c++;
      ptr = c;
      switch (*c) {
      case 'd':
	num++;
	break;
      case 'H':
	num++;
	break;
      case 'm':
	num++;
	break;
      case 'M':
	num++;
	break;
      case 'w':
	num++;
	break;
      case 'W':
	num++;
	break;
      case 'Y':
	num++;
	break;
      case 's':
	num++;
	break;
      default:
	Log(LOG_ERR, "ERROR ( %s ): sql_table, %%%c not supported.\n", filename, *c);
	exit(1);
	break;
      } 
    } 

    if (num > 8) {
      Log(LOG_ERR, "ERROR ( %s ): sql_table, exceeded the maximum allowed variables (8) into the table name.\n", filename);
      exit(1);
    }
  }

  if (strlen(value_ptr) > 64) {
    Log(LOG_ERR, "ERROR ( %s ): sql_table, exceeded the maximum SQL table name length (255).\n", filename);
    exit(1);
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_table = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_table = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_print_output_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  /* validations: we allow only a) certain variable names, b) a maximum of 8 variables */
  {
    int num = 0;
    char *c, *ptr = value_ptr;

    while (c = strchr(ptr, '%')) {
      c++;
      ptr = c;
      switch (*c) {
      case 'd':
        num++;
        break;
      case 'H':
        num++;
        break;
      case 'm':
        num++;
        break;
      case 'M':
        num++;
        break;
      case 'w':
        num++;
        break;
      case 'W':
        num++;
        break;
      case 'Y':
        num++;
        break;
      case 's':
        num++;
        break;
      default:
        Log(LOG_ERR, "ERROR ( %s ): sql_table, %%%c not supported.\n", filename, *c);
        exit(1);
        break;
      }
    }

    if (num > 8) {
      Log(LOG_ERR, "ERROR ( %s ): sql_table, exceeded the maximum allowed variables (8) into the table name.\n", filename);
      exit(1);
    }
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_table = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_table = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_table_schema(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_table_schema = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_table_schema = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_table_version(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "ERROR ( %s ): invalid 'sql_table_version' value.\n", filename);
    exit(1);
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_table_version = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_table_version = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_table_type(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_table_type = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_table_type = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_data(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_data = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_data = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_host(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_host = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_host = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_recovery_backup_host(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_backup_host = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_backup_host = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_max_writers(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 1 || value >= 100) {
    Log(LOG_WARNING, "WARN ( %s ): invalid 'sql_max_writers' value). Allowed values are: 1 <= sql_max_writers < 100.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_max_writers = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_max_writers = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_trigger_exec(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_trigger_exec = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_trigger_exec = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_trigger_time(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, t, t_howmany;

  parse_time(filename, value_ptr, &t, &t_howmany);

  if (!name) {
    for (; list; list = list->next, changes++) {
      list->cfg.sql_trigger_time = t;
      list->cfg.sql_trigger_time_howmany = t_howmany;
    }
  }
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_trigger_time = t;
	list->cfg.sql_trigger_time_howmany = t_howmany;
	changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_user(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_user = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_user = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_passwd(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_passwd = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_passwd = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_refresh_time(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0, i, len = strlen(value_ptr);

  for (i = 0; i < len; i++) {
    if (!isdigit(value_ptr[i]) && !isspace(value_ptr[i])) {
      Log(LOG_ERR, "WARN ( %s ): 'sql_refresh_time' is expected in secs but contains non-digit chars: '%c'\n", filename, value_ptr[i]);
      return ERR;
    }
  }

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN ( %s ): 'sql_refresh_time' has to be > 0.\n", filename);
    return ERR;
  }
     
  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_refresh_time = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_refresh_time = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_startup_delay(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN ( %s ): 'sql_startup_delay' has to be > 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_startup_delay = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_startup_delay = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_optimize_clauses(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_optimize_clauses = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_optimize_clauses = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_history_roundoff(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;
  int i, check, len;

  len = strlen(value_ptr);
  for (i = 0, check = 0; i < len; i++) {
    if (value_ptr[i] == 'd') check |= COUNT_DAILY;
    if (value_ptr[i] == 'w') check |= COUNT_WEEKLY;
    if (value_ptr[i] == 'M') check |= COUNT_MONTHLY;
  } 
  if (((check & COUNT_DAILY) || (check & COUNT_MONTHLY)) && (check & COUNT_WEEKLY)) {
    Log(LOG_ERR, "WARN ( %s ): 'sql_history_roundoff' 'w' is not compatible with either 'd' or 'M'.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_history_roundoff = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_history_roundoff = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_recovery_logfile(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_recovery_logfile = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_recovery_logfile = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_history(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, sql_history, sql_history_howmany;

  parse_time(filename, value_ptr, &sql_history, &sql_history_howmany);

  if (!name) {
    for (; list; list = list->next, changes++) {
      list->cfg.sql_history = sql_history;
      list->cfg.sql_history_howmany = sql_history_howmany;
    }
  }
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_history = sql_history;
        list->cfg.sql_history_howmany = sql_history_howmany;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_history_since_epoch(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_history_since_epoch = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_history_since_epoch = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_cache_entries(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN ( %s ): 'sql_cache_entries' has to be > 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_cache_entries = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_cache_entries = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_dont_try_update(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_dont_try_update = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_dont_try_update = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_preprocess(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_preprocess = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_preprocess = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_preprocess_type(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, value = 0;

  if (!strncmp(value_ptr, "any", 3)) value = FALSE;
  if (!strncmp(value_ptr, "all", 3)) value = TRUE;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_preprocess_type = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
	list->cfg.sql_preprocess_type = value;
	changes++;
	break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_multi_values(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, value = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN ( %s ): 'sql_multi_values' has to be > 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_multi_values = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_multi_values = value; 
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_mongo_insert_batch(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, value = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN ( %s ): 'mongo_insert_batch' has to be > 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.mongo_insert_batch = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.mongo_insert_batch = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_aggressive_classification(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_aggressive_classification = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_aggressive_classification = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_locking_style(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_locking_style = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
	list->cfg.sql_locking_style = value_ptr;
	changes++;
	break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_use_copy(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_use_copy = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_use_copy = value;
	changes++;
	break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_delimiter(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  /* delimiter is only one character */
  if (strlen(value_ptr) != 1) {
    Log(LOG_WARNING, "WARN ( %s ): 'sql_delimiter' length has to be 1.\n", filename);
    return ERR; 
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_delimiter = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_delimiter = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_timestamps_secs(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.timestamps_secs = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.timestamps_secs = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_plugin_pipe_size(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  /* legal values should be >= sizeof(struct pkt_data)+sizeof(struct ch_buf_hdr)
     though we are unable to check this condition here. Thus, this function will
     just cut clearly wrong values ie. < = 0. Strict checks will be accomplished
     later, by the load_plugins() */ 
  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN ( %s ): 'plugin_pipe_size' has to be > 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.pipe_size = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.pipe_size = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_plugin_pipe_backlog(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 0 || value >= 100) {
    Log(LOG_WARNING, "WARN ( %s ): 'plugin_pipe_backlog' is a percentage: 0 <= plugin_pipe_backlog < 100.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.pipe_backlog = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.pipe_backlog = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_plugin_buffer_size(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  /* legal values should be >= sizeof(struct pkt_data) and < plugin_pipe_size
     value, if any though we are unable to check this condition here. Thus, this
     function will just cut clearly wrong values ie. < = 0. Strict checks will 
     be accomplished later, by the load_plugins() */
  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN ( %s ): 'plugin_buffer_size' has to be > 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.buffer_size = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.buffer_size = value; 
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_networks_mask(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN ( %s ): 'networks_mask' has to be > 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.networks_mask = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.networks_mask = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_networks_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.networks_file = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.networks_file = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_networks_file_filter(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.networks_file_filter = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.networks_file_filter = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_networks_cache_entries(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  if (value <= 0) {
    Log(LOG_WARNING, "WARN ( %s ): 'networks_cache_entries' has to be > 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.networks_cache_entries = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.networks_cache_entries = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_ports_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.ports_file = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.ports_file = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_refresh_maps(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.refresh_maps = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'refresh_maps'. Globalized.\n", filename);

  return changes;
}

int cfg_key_print_cache_entries(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN ( %s ): 'print_cache_entries' has to be > 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.print_cache_entries = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.print_cache_entries = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_print_markers(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.print_markers = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.print_markers = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_print_output(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  if (!strcmp(value_ptr, "formatted"))
    value = PRINT_OUTPUT_FORMATTED;
  else if (!strcmp(value_ptr, "csv"))
    value = PRINT_OUTPUT_CSV;
  else if (!strcmp(value_ptr, "event_formatted")) {
    value = PRINT_OUTPUT_FORMATTED;
    value |= PRINT_OUTPUT_EVENT;
  }
  else if (!strcmp(value_ptr, "event_csv")) {
    value = PRINT_OUTPUT_CSV;
    value |= PRINT_OUTPUT_EVENT;
  }
  else {
    Log(LOG_WARNING, "WARN ( %s ): Invalid print output value '%s'\n", filename, value_ptr);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.print_output = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.print_output = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_print_output_separator(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (strlen(value_ptr) != 1) {
    Log(LOG_WARNING, "WARN ( %s ): Invalid print_output_separator value '%s'. Only one char allowed.\n", filename, value_ptr);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.print_output_separator = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.print_output_separator = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_num_protos(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.num_protos = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.num_protos = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_num_hosts(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.num_hosts = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.num_hosts = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_post_tag(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  pm_id_t value, changes = 0;
  char *endptr;

  value = strtoul(value_ptr, &endptr, 10);
  if (value < 1) {
    Log(LOG_ERR, "WARN ( %s ): 'post_tag' cannot be zero.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.post_tag = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.post_tag = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sampling_rate(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 1) {
    Log(LOG_ERR, "WARN ( %s ): 'sampling_rate' has to be >= 1.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.sampling_rate = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sampling_rate = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sampling_map(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.sampling_map = value_ptr;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'sampling_map'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_port(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value <= 0) || (value > 65535)) {
    Log(LOG_ERR, "WARN ( %s ): 'nfacctd_port' has to be in the range 0-65535.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_port = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'nfacctd_port'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_ip(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_ip = value_ptr;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'nfacctd_ip'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_allow_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_allow_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'nfacctd_allow_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_allow_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_allow_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'bgp_daemon_allow_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_md5_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_md5_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'bgp_daemon_md5_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pre_tag_map(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.pre_tag_map = value_ptr;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'pre_tag_map'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pre_tag_map_entries(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN ( %s ): 'pre_tag_map_entries' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.pre_tag_map_entries = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'pre_tag_map_entries'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_time_secs(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_time = NF_TIME_SECS;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'nfacctd_time_secs'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_time_new(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_time = NF_TIME_NEW;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'nfacctd_time_new'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_mcast_groups(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  struct host_addr tmp_addr;
  char *count_token;
  u_int32_t value = 0, changes = 0; 
  u_int8_t idx = 0, more = 0, mcast_family; 

  trim_all_spaces(value_ptr);
  memset(mcast_groups, 0, sizeof(mcast_groups));

  while (count_token = extract_token(&value_ptr, ',')) {
    memset(&tmp_addr, 0, sizeof(tmp_addr));
    str_to_addr(count_token, &tmp_addr);
    if (is_multicast(&tmp_addr)) {
      if (idx < MAX_MCAST_GROUPS) {
        memcpy(&mcast_groups[idx], &tmp_addr, sizeof(tmp_addr));
        idx++;
      }
      else more++;
    } 
  }

  for (; list; list = list->next, changes++); /* Nothing to do because of the global array, just rolling changes counters */
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for keys '[nfacctd|sfacctd]_mcast_groups'. Globalized.\n",
		  filename);
  if (more) Log(LOG_WARNING, "WARN ( %s ): Only the first %u (on a total of %u) multicast groups will be joined.\n",
		  filename, MAX_MCAST_GROUPS, MAX_MCAST_GROUPS+more);

  return changes;
}

int cfg_key_nfacctd_bgp(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'bgp_daemon'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_msglog(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_msglog = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'bgp_daemon_msglog'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_aspath_radius(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 1) {
        Log(LOG_ERR, "WARN ( %s ): 'bgp_aspath_radius' has to be >= 1.\n", filename);
        return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_aspath_radius = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'bgp_aspath_radius'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_stdcomm_pattern(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_stdcomm_pattern = value_ptr;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'bgp_stdcomm_pattern'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_extcomm_pattern(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_extcomm_pattern = value_ptr;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'bgp_extcomm_pattern'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_stdcomm_pattern_to_asn(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_stdcomm_pattern_to_asn = value_ptr;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'bgp_stdcomm_pattern_to_asn'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_peer_src_as_type(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  if (!strncmp(value_ptr, "netflow", strlen("netflow"))) value = BGP_SRC_PRIMITIVES_KEEP;
  else if (!strncmp(value_ptr, "sflow", strlen("sflow"))) value = BGP_SRC_PRIMITIVES_KEEP;
  else if (!strncmp(value_ptr, "map", strlen("map"))) value = BGP_SRC_PRIMITIVES_MAP;
  else if (!strncmp(value_ptr, "bgp", strlen("bgp"))) value = BGP_SRC_PRIMITIVES_BGP;
  else if (!strncmp(value_ptr, "fallback", strlen("fallback"))) {
    value = BGP_SRC_PRIMITIVES_KEEP;
    value |= BGP_SRC_PRIMITIVES_BGP;
  }
  else Log(LOG_WARNING, "WARN ( %s ): Ignoring uknown 'bgp_peer_src_as_type' value.\n", filename);

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_peer_as_src_type = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'bgp_peer_src_as_type'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_src_std_comm_type(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  if (!strncmp(value_ptr, "bgp", strlen("bgp"))) value = BGP_SRC_PRIMITIVES_BGP;
  else Log(LOG_WARNING, "WARN ( %s ): Ignoring uknown 'bgp_src_std_comm_type' value.\n", filename);

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_src_std_comm_type = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'bgp_src_std_comm_type'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_src_ext_comm_type(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  if (!strncmp(value_ptr, "bgp", strlen("bgp"))) value = BGP_SRC_PRIMITIVES_BGP;
  else Log(LOG_WARNING, "WARN ( %s ): Ignoring uknown 'bgp_src_ext_comm_type' value.\n", filename);

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_src_ext_comm_type = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'bgp_src_ext_comm_type'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_src_as_path_type(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  if (!strncmp(value_ptr, "bgp", strlen("bgp"))) value = BGP_SRC_PRIMITIVES_BGP;
  else Log(LOG_WARNING, "WARN ( %s ): Ignoring uknown 'bgp_src_as_path_type' value.\n", filename);

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_src_as_path_type = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'bgp_src_as_path_type'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_src_local_pref_type(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  if (!strncmp(value_ptr, "map", strlen("map"))) value = BGP_SRC_PRIMITIVES_MAP;
  else if (!strncmp(value_ptr, "bgp", strlen("bgp"))) value = BGP_SRC_PRIMITIVES_BGP;
  else Log(LOG_WARNING, "WARN ( %s ): Ignoring uknown 'bgp_src_local_pref_type' value.\n", filename);

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_src_local_pref_type = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'bgp_src_local_pref_type'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_src_med_type(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  if (!strncmp(value_ptr, "map", strlen("map"))) value = BGP_SRC_PRIMITIVES_MAP;
  else if (!strncmp(value_ptr, "bgp", strlen("bgp"))) value = BGP_SRC_PRIMITIVES_BGP;
  else Log(LOG_WARNING, "WARN ( %s ): Ignoring uknown 'bgp_src_med_type' value.\n", filename);

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_src_med_type = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'bgp_src_med_type'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_peer_as_skip_subas(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_peer_as_skip_subas = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'bgp_peer_as_skip_subas'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_src_local_pref_map(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_src_local_pref_map = value_ptr;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'bgp_src_local_pref_map'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_peer_src_as_map(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_peer_as_src_map = value_ptr;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'bgp_peer_src_as_map'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_src_med_map(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_src_med_map = value_ptr;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'bgp_src_med_map'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_to_agent_map(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_to_agent_map = value_ptr;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'bgp_to_agent_map'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_iface_to_rd_map(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_iface_to_rd_map = value_ptr;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'bgp_iface_rd_map'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_follow_default(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_follow_default = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'bgp_follow_default'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_follow_nexthop(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  char *count_token;
  int changes = 0, idx = 0, valid;

  trim_all_spaces(value_ptr);

  while ((count_token = extract_token(&value_ptr, ',')) && idx < FOLLOW_BGP_NH_ENTRIES) {
    for (list = plugins_list; list; list = list->next) {
      valid = str2prefix(count_token, &list->cfg.nfacctd_bgp_follow_nexthop[idx]);
      if (!valid) {
	Log(LOG_WARNING, "WARN ( %s ): bgp_follow_nexthop: invalid IP prefix '%s'.\n", filename, count_token);
	break;
      }
    }
    if (valid) idx++;
  }

  changes = idx;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'bgp_follow_nexthop'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_neighbors_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_neighbors_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'bgp_neighbors_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_max_peers(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 1) {
        Log(LOG_ERR, "WARN ( %s ): 'nfacctd_bgp_max_peers' has to be >= 1.\n", filename);
        return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_max_peers = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'bgp_daemon_max_peers'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_ip(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_ip = value_ptr;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'bgp_daemon_ip'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_port(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value <= 0) || (value > 65535)) {
    Log(LOG_ERR, "WARN ( %s ): 'bgp_daemon_port' has to be in the range 0-65535.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_port = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'bgp_daemon_port'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_ip_precedence(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value < 0) || (value > 7)) {
    Log(LOG_ERR, "WARN ( %s ): 'bgp_daemon_ipprec' has to be in the range 0-7.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_ipprec = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'bgp_daemon_ipprec'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_table_peer_buckets(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value <= 0) || (value > 1000)) {
    Log(LOG_ERR, "WARN ( %s ): 'bgp_table_peer_buckets' has to be in the range 1-1000.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.bgp_table_peer_buckets = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'bgp_table_peer_buckets'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_isis(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_isis = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'isis_daemon'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_isis_ip(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_isis_ip = value_ptr;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'isis_daemon_ip'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_isis_net(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_isis_net = value_ptr;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'isis_daemon_net'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_isis_iface(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_isis_iface = value_ptr;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'isis_daemon_iface'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_isis_mtu(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < SNAPLEN_ISIS_MIN) {
    Log(LOG_WARNING, "WARN ( %s ): 'isis_daemon_mtu' has to be >= %d.\n", filename, SNAPLEN_ISIS_MIN);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_isis_mtu = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'isis_daemon_mtu'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_isis_msglog(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_isis_msglog = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'isis_daemon_msglog'. Globalized.\n", filename);

  return changes;
}

int cfg_key_igp_daemon_map(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.igp_daemon_map = value_ptr;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'igp_daemon_map'. Globalized.\n", filename);

  return changes;
}

int cfg_key_igp_daemon_map_msglog(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  for (; list; list = list->next, changes++) list->cfg.igp_daemon_map_msglog = value_ptr;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'igp_daemon_map_msglog'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pmacctd_force_frag_handling(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.handle_fragments = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'pmacctd_force_frag_handling'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pmacctd_frag_buffer_size(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN ( %s ): 'pmacctd_frag_buffer_size' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.frag_bufsz = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'pmacctd_frag_buffer_size'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pmacctd_flow_buffer_size(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN ( %s ): 'pmacctd_flow_buffer_size' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.flow_bufsz = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'pmacctd_flow_buffer_size'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pmacctd_flow_buffer_buckets(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN ( %s ): 'flow_buffer_buckets' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.flow_hashsz = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'pmacctd_flow_buffer_buckets'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pmacctd_conntrack_buffer_size(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN ( %s ): 'pmacctd_conntrack_buffer_size' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.conntrack_bufsz = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'pmacctd_conntrack_buffer_size'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pmacctd_flow_lifetime(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN ( %s ): 'pmacctd_flow_lifetime' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.flow_lifetime = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'pmacctd_flow_lifetime'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pmacctd_ext_sampling_rate(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 1) {
    Log(LOG_ERR, "WARN ( %s ): 'pmacctd_ext_sampling_rate' has to be >= 1.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.ext_sampling_rate = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'pmacctd_ext_sampling_rate'. Globalized.\n", filename);

  return changes;
}

int cfg_key_sfacctd_renormalize(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.sfacctd_renormalize = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'sfacctd_renormalize'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pcap_savefile(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.pcap_savefile = value_ptr;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'pcap_savefile'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_as_new(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  if (!strcmp(value_ptr, "false"))
    value = NF_AS_KEEP;
  else if (!strcmp(value_ptr, "true") || !strcmp(value_ptr, "file"))
    value = NF_AS_NEW;
  else if (!strcmp(value_ptr, "bgp"))
    value = NF_AS_BGP;
  else if (!strcmp(value_ptr, "fallback")) {
    value = NF_AS_FALLBACK;
    if (config.acct_type == ACCT_NF || config.acct_type == ACCT_SF) { 
      value |= NF_AS_KEEP;
      value |= NF_AS_BGP;
    }
    else value = NF_AS_BGP; /* NF_AS_KEEP does not apply to ACCT_PM and ACCT_UL;
			       we set value to NF_AS_BGP since we can't fallback
			       to any alternative method as of yet */
  }
  else {
    Log(LOG_ERR, "WARN ( %s ): Invalid AS aggregation value '%s'\n", filename, value_ptr);
    return ERR;
  } 

  for (; list; list = list->next, changes++) list->cfg.nfacctd_as = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key '[nf|pm|sf|ua]acctd_as_new'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_net(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  if (!strcmp(value_ptr, "sflow") || !strcmp(value_ptr, "netflow"))
    value = NF_NET_KEEP;
  else if (!strcmp(value_ptr, "file"))
    value = NF_NET_NEW;
  else if (!strcmp(value_ptr, "mask"))
    value = NF_NET_STATIC;
  else if (!strcmp(value_ptr, "bgp"))
    value = NF_NET_BGP;
  else if (!strcmp(value_ptr, "igp"))
    value = NF_NET_IGP;
  else if (!strcmp(value_ptr, "fallback")) {
    value = NF_NET_FALLBACK;
    if (config.acct_type == ACCT_NF || config.acct_type == ACCT_SF) {
      value |= NF_NET_KEEP;
      value |= NF_NET_BGP;
      value |= NF_NET_IGP;
    }
    else {
      value |= NF_NET_BGP;
      value |= NF_NET_IGP;
    }
  }
  else {
    Log(LOG_ERR, "WARN ( %s ): Invalid network aggregation value '%s'\n", filename, value_ptr);
    return ERR;
  } 

  if (!name) for (; list; list = list->next, changes++) list->cfg.nfacctd_net = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.nfacctd_net = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_nfacctd_disable_checks(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_disable_checks = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key '[ns]facctd_disable_checks'. Globalized.\n", filename);

  return changes;
}


int cfg_key_classifiers(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.classifiers_path = value_ptr;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'classifiers'. Globalized.\n", filename);

  return changes;
}

int cfg_key_classifier_tentatives(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_INFO, "INFO ( %s ): 'classifier_tentatives' has to be >= 1.\n", filename);  
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.classifier_tentatives = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'classifier_tentatives'. Globalized.\n", filename);

  return changes;
}

int cfg_key_classifier_table_num(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_INFO, "INFO ( %s ): 'classifier_table_num' has to be >= 1.\n", filename);  
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.classifier_table_num = value;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'classifier_table_num'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfprobe_timeouts(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.nfprobe_timeouts = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
	list->cfg.nfprobe_timeouts = value_ptr;
	changes++;
	break;
      }
    }
  }

  return changes;
}

int cfg_key_nfprobe_hoplimit(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value < 1) || (value > 255)) {
    Log(LOG_ERR, "WARN ( %s ): 'nfprobe_hoplimit' has to be in the range 1-255.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.nfprobe_hoplimit = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.nfprobe_hoplimit = value;
	changes++;
	break;
      }
    }
  }

  return changes;
}

int cfg_key_nfprobe_maxflows(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 1) {
    Log(LOG_ERR, "WARN ( %s ): 'nfprobe_maxflows' has to be >= 1.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.nfprobe_maxflows = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
	list->cfg.nfprobe_maxflows = value;
	changes++;
	break;
      }
    }
  }

  return changes;
}

int cfg_key_nfprobe_receiver(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.nfprobe_receiver = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.nfprobe_receiver = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_nfprobe_source_ip(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.nfprobe_source_ip = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.nfprobe_source_ip = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_nfprobe_version(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value != 1 && value != 5 && value != 9 && value != 10) {
    Log(LOG_ERR, "WARN ( %s ): 'nfprobe_version' has to be either 1/5/9/10.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.nfprobe_version = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.nfprobe_version = value;
        changes++;
	break;
      }
    }
  }

  return changes;
}

int cfg_key_nfprobe_engine(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.nfprobe_engine = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.nfprobe_engine = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_nfprobe_peer_as(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.nfprobe_peer_as = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.nfprobe_peer_as = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_nfprobe_ip_precedence(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value <= 0) || (value > 7)) {
    Log(LOG_ERR, "WARN ( %s ): 'nfprobe_ipprec' and 'sfprobe_ipprec' have to be in the range 0-7.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.nfprobe_ipprec = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
	list->cfg.nfprobe_ipprec = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_nfprobe_direction(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  if (!strcmp(value_ptr, "tag"))
    value = DIRECTION_TAG;
  else if (!strcmp(value_ptr, "tag2"))
    value = DIRECTION_TAG2;
  else if (!strcmp(value_ptr, "in"))
    value = DIRECTION_IN;
  else if (!strcmp(value_ptr, "out"))
    value = DIRECTION_OUT;
  else {
    Log(LOG_ERR, "WARN ( %s ): Invalid nfprobe_direction or sfprobe_direction value '%s'\n", filename, value_ptr);
    return ERR;
  }

  if (!name) {
    Log(LOG_ERR, "ERROR ( %s ): nfprobe_direction and sfprobe_direction cannot be global. Not loaded.\n", filename);
    changes++;
  }
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.nfprobe_direction = value;
	changes++;
	break;
      }
    }
  }

  return changes;
}

int cfg_key_nfprobe_ifindex(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, value2 = 0;
  u_int32_t value = 0;

  if (!strcmp(value_ptr, "tag"))
    value2 = IFINDEX_TAG;
  else if (!strcmp(value_ptr, "tag2"))
    value2 = IFINDEX_TAG2;
  else if (value = strtol(value_ptr, NULL, 0))
    value2 = IFINDEX_STATIC;
  else {
    Log(LOG_ERR, "WARN ( %s ): Invalid nfprobe_ifindex or sfprobe_ifindex value '%s'\n", filename, value_ptr);
    return ERR;
  }

  if (!name) {
    Log(LOG_ERR, "ERROR ( %s ): nfprobe_ifindex and sfprobe_ifindex cannot be global. Not loaded.\n", filename);
    changes++;
  }
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
	list->cfg.nfprobe_ifindex = value;
	list->cfg.nfprobe_ifindex_type = value2;
	changes++;
	break;
      }
    }
  }

  return changes;
}

int cfg_key_sfprobe_receiver(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sfprobe_receiver = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sfprobe_receiver = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sfprobe_agentip(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sfprobe_agentip = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sfprobe_agentip = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sfprobe_agentsubid(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 0) {
    Log(LOG_ERR, "WARN ( %s ): 'sfprobe_agentsubid' has to be >= 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.sfprobe_agentsubid = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sfprobe_agentsubid = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sfprobe_ifspeed(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;
  u_int64_t value;

  value = strtoll(value_ptr, NULL, 0);

  if (!name) for (; list; list = list->next, changes++) list->cfg.sfprobe_ifspeed = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
	list->cfg.sfprobe_ifspeed = value;
	changes++;
	break;
      }
    }
  }

  return changes;
}

int cfg_key_tee_transparent(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.tee_transparent = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.tee_transparent = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_tee_max_receivers(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 1) {
    Log(LOG_WARNING, "WARN ( %s ): invalid 'tee_max_receivers' value). Allowed values are >= 1.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.tee_max_receivers = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.tee_max_receivers = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_tee_max_receiver_pools(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 1) {
    Log(LOG_WARNING, "WARN ( %s ): invalid 'tee_max_receiver_pools' value). Allowed values are >= 1.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.tee_max_receiver_pools = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.tee_max_receiver_pools = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_tee_receivers(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.tee_receivers = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.tee_receivers = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

void parse_time(char *filename, char *value, int *mu, int *howmany)
{
  int k, j, len;

  len = strlen(value);
  for (j = 0; j < len; j++) {
    if (!isdigit(value[j])) {
      if (value[j] == 'm') *mu = COUNT_MINUTELY;
      else if (value[j] == 'h') *mu = COUNT_HOURLY;
      else if (value[j] == 'd') *mu = COUNT_DAILY;
      else if (value[j] == 'w') *mu = COUNT_WEEKLY;
      else if (value[j] == 'M') *mu = COUNT_MONTHLY;
      else {
        Log(LOG_WARNING, "WARN ( %s ): Ignoring unknown time measuring unit: '%c'.\n", filename, value[j]);
        *mu = 0;
        *howmany = 0;
        return;
      }
      if (*mu) {
        value[j] = '\0';
        break;
      }
    }
  }
  k = atoi(value);
  if (k > 0) *howmany = k;
  else {
    Log(LOG_WARNING, "WARN ( %s ): ignoring invalid time value: %d\n", filename, k);
    *mu = 0;
    *howmany = 0;
  }
}

int cfg_key_uacctd_group(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 1 || value > 32) return ERR;

  for (; list; list = list->next, changes++) list->cfg.uacctd_group = (1 << (value-1));
  return changes;
}

int cfg_key_uacctd_nl_size(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);

  for (; list; list = list->next, changes++) list->cfg.uacctd_nl_size = value;
  return changes;
}

int cfg_key_tunnel_0(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  trim_all_spaces(value_ptr);

  for (; list; list = list->next, changes++) list->cfg.tunnel0 = value_ptr;
  if (name) Log(LOG_WARNING, "WARN ( %s ): plugin name not supported for key 'tunnel_0'. Globalized.\n", filename);

  return changes;
}

#if defined WITH_GEOIP
int cfg_key_geoip_ipv4_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.geoip_ipv4_file = value_ptr;

  return changes;
}

#if defined ENABLE_IPV6
int cfg_key_geoip_ipv6_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.geoip_ipv6_file = value_ptr;

  return changes;
}
#endif
#endif

int cfg_key_pkt_len_distrib_bins(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.pkt_len_distrib_bins_str = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.pkt_len_distrib_bins_str = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

void cfg_set_aggregate(char *filename, u_int64_t registry[], u_int64_t input, char *token)
{
  u_int64_t index = (input >> COUNT_REGISTRY_BITS) & COUNT_INDEX_MASK;
  u_int64_t value = (input & COUNT_REGISTRY_MASK);

  if (registry[index] & value) {
    Log(LOG_ERR, "ERROR ( %s ): '%s' repeated in 'aggregate' or invalid 0x%x bit code.\n", filename, token, input);
    exit(1);
  }
  else registry[index] |= value;
}

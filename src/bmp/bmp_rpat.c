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

/* includes */
#include "pmacct.h"
#include "addr.h"
#include "bgp/bgp.h"
#include "bmp.h"
#ifdef WITH_AVRO
#include "plugin_cmn_avro.h"
#endif

/* functions */
void bmp_process_msg_rpat(char **bmp_packet, u_int32_t *len, struct bmp_peer *bmpp)
{
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;
  struct bmp_data bdata;
  struct bmp_rpat_common_hdr *brch;
  struct bmp_rpat_event_hdr *breh; 
  struct bmp_log_rpat blrpat;
  int idx, tecount, telen;

  if (!bmpp) return;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  memset(&bdata, 0, sizeof(bdata));
  memset(&blrpat, 0, sizeof(blrpat));

  if (!(brch = (struct bmp_rpat_common_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_rpat_common_hdr)))) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [rpat] packet discarded: failed bmp_get_and_check_length() BMP rpat common hdr\n",
	config.name, bms->log_str, peer->addr_str);
    return;
  }

  gettimeofday(&bdata.tstamp_arrival, NULL);

  bmp_rpat_common_hdr_get_v_flag(brch, &bdata.family);
  bmp_rpat_common_hdr_get_bgp_id(brch, &bdata.bgp_id);
  bmp_rpat_common_hdr_get_rd(brch, &bdata.chars.rd);
  bmp_rpat_common_hdr_get_prefix(brch, &blrpat.prefix, &bdata.family);
  bmp_rpat_common_hdr_get_prefix_len(brch, &blrpat.prefix_len);

  tecount = brch->events_count;
  telen = ntohs(brch->events_length);

  /* Events parsing */
  for (idx = 0; (idx < tecount) && (telen > 0); idx++) {
    u_int32_t orig_loc_len, rmn_loc_len;
    int ret, elen;

    /* TLV vars */
    struct bmp_tlv_hdr *bth;
    u_int16_t bmp_tlv_type, bmp_tlv_len;
    char *bmp_tlv_value;
    struct pm_list *tlvs = NULL;

    tlvs = bmp_tlv_list_new(NULL, bmp_tlv_list_node_del);
    if (!tlvs) return;

    if (!(breh = (struct bmp_rpat_event_hdr *) bmp_get_and_check_length(bmp_packet, len, sizeof(struct bmp_rpat_event_hdr)))) {
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] [rpat] packet discarded: failed bmp_get_and_check_length() BMP rpat event hdr\n",
	  config.name, bms->log_str, peer->addr_str);
      bmp_tlv_list_destroy(tlvs);
      return;
    }

    elen = rmn_loc_len = ntohs(breh->len);
    orig_loc_len = rmn_loc_len = (rmn_loc_len - sizeof(struct bmp_rpat_event_hdr));
    
    bmp_rpat_event_hdr_get_index(breh, &blrpat.event_idx);
    bmp_rpat_event_hdr_get_tstamp(breh, &bdata.tstamp);
    bmp_rpat_event_hdr_get_path_id(breh, &blrpat.path_id);
    bmp_rpat_event_hdr_get_afi_safi(breh, &blrpat.afi, &blrpat.safi);

    /* event TLVs parsing */
    while (rmn_loc_len) {
      if (!(bth = (struct bmp_tlv_hdr *) bmp_get_and_check_length(bmp_packet, &rmn_loc_len, sizeof(struct bmp_tlv_hdr)))) {
	Log(LOG_INFO, "INFO ( %s/%s ): [%s] [rpat] packet discarded: failed bmp_get_and_check_length() BMP TLV hdr\n",
	    config.name, bms->log_str, peer->addr_str);
	(*len) -= (orig_loc_len - rmn_loc_len);
        bmp_tlv_list_destroy(tlvs);
        return;
      }

      bmp_tlv_hdr_get_type(bth, &bmp_tlv_type);
      bmp_tlv_hdr_get_len(bth, &bmp_tlv_len);

      if (!(bmp_tlv_value = bmp_get_and_check_length(bmp_packet, &rmn_loc_len, bmp_tlv_len))) {
	Log(LOG_INFO, "INFO ( %s/%s ): [%s] [rpat] packet discarded: failed bmp_get_and_check_length() BMP TLV info\n",
	    config.name, bms->log_str, peer->addr_str);
	(*len) -= (orig_loc_len - rmn_loc_len);
	bmp_tlv_list_destroy(tlvs);
	return;
      }

      ret = bmp_tlv_list_add(tlvs, 0, bmp_tlv_type, bmp_tlv_len, bmp_tlv_value);
      if (ret == ERR) {
	Log(LOG_ERR, "ERROR ( %s/%s ): [%s] [rpat] bmp_tlv_list_add() failed.\n", config.name, bms->log_str, peer->addr_str);
	exit_gracefully(1);
      }
    }

    if (bms->msglog_backend_methods) {
      char event_type[] = "log";

      bmp_log_msg(peer, &bdata, tlvs, &blrpat, bgp_peer_log_seq_get(&bms->log_seq), event_type, config.bmp_daemon_msglog_output, BMP_LOG_TYPE_RPAT);
    }

    if (bms->dump_backend_methods) bmp_dump_se_ll_append(peer, &bdata, tlvs, &blrpat, BMP_LOG_TYPE_RPAT);

    if (bms->msglog_backend_methods || bms->dump_backend_methods) bgp_peer_log_seq_increment(&bms->log_seq);

    if (!pm_listcount(tlvs) || !bms->dump_backend_methods) bmp_tlv_list_destroy(tlvs);

    (*len) -= orig_loc_len;
    telen -= elen;
  }
}

void bmp_rpat_common_hdr_get_v_flag(struct bmp_rpat_common_hdr *brch, u_int8_t *family)
{
  u_int8_t version;

  if (brch && family) {
    version = (brch->flags & BMP_PEER_FLAGS_ARI_V);
    (*family) = FALSE;

    if (version == 0) (*family) = AF_INET;
    else (*family) = AF_INET6;
  }
}

void bmp_rpat_common_hdr_get_bgp_id(struct bmp_rpat_common_hdr *brch, struct host_addr *a)
{
  if (brch && a) {
    a->family = AF_INET;
    a->address.ipv4.s_addr = brch->bgp_id;
  }
}

void bmp_rpat_common_hdr_get_rd(struct bmp_rpat_common_hdr *brch, rd_t *rd)
{
  if (brch && rd) {
    memcpy(rd, brch->rd, RD_LEN);
    bgp_rd_ntoh(rd);
  }
}

void bmp_rpat_common_hdr_get_prefix(struct bmp_rpat_common_hdr *brch, struct host_addr *a, u_int8_t *family)
{
  if (brch && a) {
    if ((*family) == AF_INET) a->address.ipv4.s_addr = brch->prefix[3];
    else if ((*family) == AF_INET6) memcpy(&a->address.ipv6, &brch->prefix, 16);
    else {
      memset(a, 0, sizeof(struct host_addr));
      if (!brch->prefix[0] && !brch->prefix[1] && !brch->prefix[2] && !brch->prefix[3]) {
        (*family) = AF_INET; /* we just set this up to something non-zero */
      }
    }

    a->family = (*family);
  }
}

void bmp_rpat_common_hdr_get_prefix_len(struct bmp_rpat_common_hdr *brch, u_int8_t *plen)
{
  if (brch && plen) (*plen) = brch->prefix_len;
}

void bmp_rpat_event_hdr_get_index(struct bmp_rpat_event_hdr *breh, u_int8_t *idx)
{
  if (breh && idx) (*idx) = breh->idx;
}

void bmp_rpat_event_hdr_get_tstamp(struct bmp_rpat_event_hdr *breh, struct timeval *tv)
{
  u_int32_t sec, usec;

  if (breh && tv) {
    if (breh->tstamp_sec) {
      sec = ntohl(breh->tstamp_sec);
      usec = ntohl(breh->tstamp_usec);

      tv->tv_sec = sec;
      tv->tv_usec = usec;
    }
  }
}

void bmp_rpat_event_hdr_get_path_id(struct bmp_rpat_event_hdr *breh, u_int32_t *path_id)
{
  if (breh && path_id) (*path_id) = ntohl(breh->path_id);
}

void bmp_rpat_event_hdr_get_afi_safi(struct bmp_rpat_event_hdr *breh, afi_t *afi, safi_t *safi)
{
  if (breh) {
    if (afi && safi) {
      (*afi) = ntohs(breh->afi);
      (*safi) = breh->safi;
    }
  }
}

void bmp_rpat_policy_tlv_get_m_flag(struct bmp_rpat_policy_tlv_hdr *brpth, u_int8_t *is_match)
{
  if (brpth && is_match) {
    if (brpth->flag & BMP_RPAT_POLICY_FLAG_M) (*is_match) = TRUE;
    else (*is_match) = FALSE;
  }
}

void bmp_rpat_policy_tlv_get_p_flag(struct bmp_rpat_policy_tlv_hdr *brpth, u_int8_t *is_permit)
{
  if (brpth && is_permit) {
    if (brpth->flag & BMP_RPAT_POLICY_FLAG_P) (*is_permit) = TRUE;
    else (*is_permit) = FALSE;
  }
}

void bmp_rpat_policy_tlv_get_d_flag(struct bmp_rpat_policy_tlv_hdr *brpth, u_int8_t *is_diff)
{
  if (brpth && is_diff) {
    if (brpth->flag & BMP_RPAT_POLICY_FLAG_D) (*is_diff) = TRUE;
    else (*is_diff) = FALSE;
  }
}

void bmp_rpat_policy_tlv_np_get_c_flag(u_int8_t *np_flags, u_int8_t *is_chained)
{
  if (np_flags && is_chained) {
    if ((*np_flags) & BMP_RPAT_POLICY_NP_FLAG_C) (*is_chained) = TRUE;
    else (*is_chained) = FALSE;
  }
}

void bmp_rpat_policy_tlv_np_get_r_flag(u_int8_t *np_flags, u_int8_t *is_recursive)
{
  if (np_flags && is_recursive) {
    if ((*np_flags) & BMP_RPAT_POLICY_NP_FLAG_R) (*is_recursive) = TRUE;
    else (*is_recursive) = FALSE;
  }
}

void bmp_rpat_policy_tlv_get_bgp_id(struct bmp_rpat_policy_tlv_hdr *brpth, struct host_addr *a)
{
  if (brpth && a) {
    a->family = AF_INET;
    a->address.ipv4.s_addr = brpth->peer_bgp_id;
  }
}

void bmp_rpat_policy_tlv_get_peer_ip(struct bmp_rpat_policy_tlv_hdr *brpth, struct host_addr *a, u_int8_t *family)
{
  if (brpth && a) {
    if ((*family) == AF_INET) a->address.ipv4.s_addr = brpth->peer_ip[3];
    else if ((*family) == AF_INET6) memcpy(&a->address.ipv6, &brpth->peer_ip, 16);
    else {
      memset(a, 0, sizeof(struct host_addr));
      if (!brpth->peer_ip[0] && !brpth->peer_ip[1] && !brpth->peer_ip[2] && !brpth->peer_ip[3]) {
	(*family) = AF_INET; /* we just set this up to something non-zero */
      }
    }

    a->family = (*family);
  }
}

int bmp_log_msg_rpat(struct bgp_peer *peer, struct bmp_data *bdata, struct pm_list *tlvs, struct bmp_log_rpat *blrpat, char *event_type, int output, void *vobj)
{
  int ret = 0;

  if (!peer || !bdata || !blrpat || !vobj) return ERR;

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    char bmp_msg_type[] = "rpat";
    char ip_address[INET6_ADDRSTRLEN];
    json_t *obj = (json_t *) vobj;

    json_object_set_new_nocheck(obj, "bmp_msg_type", json_string(bmp_msg_type));

    if (!is_empty_256b(&bdata->chars.rd, sizeof(bdata->chars.rd))) {
      char rd_str[SHORTSHORTBUFLEN];

      bgp_rd2str(rd_str, &bdata->chars.rd);
      json_object_set_new_nocheck(obj, "rd", json_string(rd_str));
    }

    addr_to_str(ip_address, &blrpat->prefix);
    json_object_set_new_nocheck(obj, "prefix", json_string(ip_address));
    json_object_set_new_nocheck(obj, "prefix_len", json_integer((json_int_t)blrpat->prefix_len));

    json_object_set_new_nocheck(obj, "bgp_id", json_string(inet_ntoa(bdata->bgp_id.address.ipv4)));

    if (blrpat->path_id) {
      json_object_set_new_nocheck(obj, "path_id", json_integer((json_int_t)blrpat->path_id));
    }
    json_object_set_new_nocheck(obj, "afi", json_integer((json_int_t)blrpat->afi));
    json_object_set_new_nocheck(obj, "safi", json_integer((json_int_t)blrpat->safi));

    if (tlvs) {
      struct pm_listnode *node = NULL;
      struct bmp_log_tlv *tlv = NULL;

      for (PM_ALL_LIST_ELEMENTS_RO(tlvs, node, tlv)) {
	char *type = NULL, *value = NULL;

	switch (tlv->type) {
	case BMP_RPAT_INFO_VRF:
	  (*bmp_rpat_info_types[tlv->type].logdump_func)(peer, bdata, tlv, blrpat, event_type, output, vobj);
	  break;
	case BMP_RPAT_INFO_POLICY:
	  (*bmp_rpat_info_types[tlv->type].logdump_func)(peer, bdata, tlv, blrpat, event_type, output, vobj);
	  break;
	default:
	  type = bmp_tlv_type_print(tlv, "bmp_rpat_info", bmp_rpat_info_types, BMP_RPAT_INFO_MAX);
	  value = bmp_tlv_value_print(tlv, bmp_rpat_info_types, BMP_RPAT_INFO_MAX);
	  break;
	}

	if (type) {
	  if (value) {
	    /* Allow for multiple String TLVs */
	    if (tlv->type == BMP_RPAT_INFO_STRING) {
	      json_t *string_tlv_array = NULL;

	      string_tlv_array = json_object_get(obj, bmp_rpat_info_types[tlv->type].name);

	      if (!string_tlv_array || !json_is_array(string_tlv_array)) {
		string_tlv_array = json_array();
	        json_array_append_new(string_tlv_array, json_string(value));
	        json_object_set_new_nocheck(obj, type, string_tlv_array);
	      }
	      else {
	        json_array_append_new(string_tlv_array, json_string(value));
	      }
	    }
	    else {
	      json_object_set_new_nocheck(obj, type, json_string(value));
	    }

	    free(value);
	  }
	  else {
	    json_object_set_new_nocheck(obj, type, json_null());
	  }

	  free(type);
	}
      }
    }
#endif
  }
  else if ((output == PRINT_OUTPUT_AVRO_BIN) ||
	   (output == PRINT_OUTPUT_AVRO_JSON)) {
#ifdef WITH_AVRO
    avro_value_t *obj = (avro_value_t *) vobj, p_avro_field;
    char bmp_msg_type[] = "rpat";

    pm_avro_check(avro_value_get_by_name(obj, "bmp_msg_type", &p_avro_field, NULL));
    pm_avro_check(avro_value_set_string(&p_avro_field, bmp_msg_type));

    // XXX: to be worked out later
#endif
  }

  return ret;
}

int bmp_log_msg_rpat_vrf(struct bgp_peer *peer, struct bmp_data *bdata, void *vtlv, void *bl, char *event_type, int output, void *vobj)
{
  struct bmp_log_rpat *blrpat = bl;
  struct bmp_log_tlv *tlv = vtlv; 
  int ret = 0;

  if (!peer || !bdata || !blrpat || !tlv || !vobj) return ERR;

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    json_t *obj = (json_t *) vobj;

    struct bmp_rpat_vrf_tlv_hdr *vrf_tlv = NULL;
    char *vrf_name = NULL, *str_ptr = NULL;
    int vrf_name_len = 0;

    vrf_tlv = (struct bmp_rpat_vrf_tlv_hdr *) tlv->val; 
    str_ptr = (char *)(tlv->val + 4);
    vrf_name_len = (tlv->len - 4);

    json_object_set_new_nocheck(obj, "vrf_id", json_integer((json_int_t)ntohl(vrf_tlv->id)));

    if (vrf_name_len) {
      vrf_name = null_terminate(str_ptr, vrf_name_len);
      json_object_set_new_nocheck(obj, "vrf_name", json_string(vrf_name));
      free(vrf_name);
    }
    else {
      json_object_set_new_nocheck(obj, "vrf_name", json_null());
    }
#endif
  }
  else if ((output == PRINT_OUTPUT_AVRO_BIN) ||
	   (output == PRINT_OUTPUT_AVRO_JSON)) {
#ifdef WITH_AVRO
    // XXX: to be worked out later
#endif
  }

  return ret;
}

int bmp_log_msg_rpat_policy(struct bgp_peer *peer, struct bmp_data *bdata, void *vtlv, void *bl, char *event_type, int output, void *vobj)
{
  struct bmp_log_rpat *blrpat = bl;
  struct bmp_log_tlv *tlv = vtlv;
  int ret = 0;

  if (!peer || !bdata || !blrpat || !tlv || !vobj) return ERR;

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    json_t *obj = (json_t *) vobj;

    struct bmp_rpat_policy_tlv_hdr *policy_tlv = NULL;
    char ip_address[INET6_ADDRSTRLEN];
    struct host_addr ha;
    u_int8_t flag = 0, idx = 0;

    policy_tlv = (struct bmp_rpat_policy_tlv_hdr *) tlv->val;

    bmp_rpat_policy_tlv_get_m_flag(policy_tlv, &flag);
    json_object_set_new_nocheck(obj, "policy_is_match", json_integer((json_int_t)flag));

    bmp_rpat_policy_tlv_get_p_flag(policy_tlv, &flag);
    json_object_set_new_nocheck(obj, "policy_is_permit", json_integer((json_int_t)flag));

    bmp_rpat_policy_tlv_get_d_flag(policy_tlv, &flag);
    json_object_set_new_nocheck(obj, "policy_is_diff", json_integer((json_int_t)flag));

    if (policy_tlv->class <= BMP_RPAT_POLICY_CLASS_MAX) {
      json_object_set_new_nocheck(obj, "policy_class", json_string(bmp_rpat_class_types[policy_tlv->class]));
    }
    else {
      json_object_set_new_nocheck(obj, "policy_class", json_string("Unknown"));
    }

    bmp_rpat_policy_tlv_get_bgp_id(policy_tlv, &ha);
    json_object_set_new_nocheck(obj, "peer_bgp_id", json_string(inet_ntoa(ha.address.ipv4)));

    bmp_rpat_policy_tlv_get_peer_ip(policy_tlv, &ha, &bdata->family);
    addr_to_str(ip_address, &ha);
    json_object_set_new_nocheck(obj, "peer_ip", json_string(ip_address));

    json_object_set_new_nocheck(obj, "peer_asn", json_integer((json_int_t)ntohl(policy_tlv->peer_asn)));

    if (policy_tlv->count) {
      json_t *policy_name_array = json_array();
      json_t *policy_id_array = json_array();
      json_t *policy_nf_array = json_array();
      void *policy_ptr = tlv->val + sizeof(struct bmp_rpat_policy_tlv_hdr);

      json_object_set_new_nocheck(obj, "policy_name", policy_name_array);
      json_object_set_new_nocheck(obj, "policy_id", policy_id_array);
      json_object_set_new_nocheck(obj, "policy_nf", policy_nf_array);

      for (idx = 0; idx < policy_tlv->count; idx++) {
        struct bmp_rpat_policy_hdr *brph = policy_ptr;
	char *policy_id = NULL, *policy_name = NULL, *str_ptr = NULL;

	int is_last = ((idx + 1) < policy_tlv->count) ? FALSE : TRUE;
	int is_first = (idx == 0) ? TRUE : FALSE;

	brph->name_len = ntohs(brph->name_len);
	brph->id_len = ntohs(brph->id_len);

	str_ptr = (policy_ptr + 4 /* lenghts */);

	if (brph->name_len) {
	  policy_name = null_terminate((char *) str_ptr, brph->name_len);
	  json_array_append_new(policy_name_array, json_string(policy_name));
	  free(policy_name);
	}
	else {
	  json_array_append_new(policy_name_array, json_null());
	}

	str_ptr = (policy_ptr + 4 /* lengths */ + brph->name_len);

	if (brph->id_len) {
	  policy_id = null_terminate((char *) str_ptr, brph->id_len);
	  json_array_append_new(policy_id_array, json_string(policy_id));
	  free(policy_id);
	}
	else {
	  json_array_append_new(policy_id_array, json_null());
	}

	if (is_first) {
	  json_array_append_new(policy_nf_array, json_null());
	}

	if (!is_last) {
	  u_int8_t *np_flags = (policy_ptr + 4 /* lengths */ + brph->name_len + brph->id_len);

	  bmp_rpat_policy_tlv_np_get_c_flag(np_flags, &flag);
	  json_object_set_new_nocheck(obj, "policy_nf_is_chained", json_integer((json_int_t)flag));

	  bmp_rpat_policy_tlv_np_get_r_flag(np_flags, &flag);
	  json_object_set_new_nocheck(obj, "policy_nf_is_recursive", json_integer((json_int_t)flag));

	  policy_ptr = (policy_ptr + 4 /* lengths */ + brph->name_len + brph->id_len + 1 /* next policy flags */);
	}
      }
    }
#endif
  }
  else if ((output == PRINT_OUTPUT_AVRO_BIN) ||
           (output == PRINT_OUTPUT_AVRO_JSON)) {
#ifdef WITH_AVRO
    // XXX: to be worked out later
#endif
  }

  return ret;
}


#ifdef WITH_AVRO
avro_schema_t p_avro_schema_build_bmp_rpat(char *schema_name)
{
  avro_schema_t schema = NULL;
  avro_schema_t optlong_s = avro_schema_union();
  avro_schema_t optstr_s = avro_schema_union();
  avro_schema_t optint_s = avro_schema_union();

  p_avro_schema_init_bgp(&schema, &optlong_s, &optstr_s, &optint_s, FUNC_TYPE_BMP, schema_name);
  p_avro_schema_build_bmp_common(&schema, &optlong_s, &optstr_s, &optint_s);

  /* XXX: incomplete, more work needed */

  avro_schema_decref(optlong_s);
  avro_schema_decref(optstr_s);
  avro_schema_decref(optint_s);

  return schema;
}
#endif

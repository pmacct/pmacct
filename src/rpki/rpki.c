/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2019 by Paolo Lucente
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

/* defines */
#define __RPKI_C

/* includes */
#include "pmacct.h"
#include "bgp/bgp.h"
#include "rpki.h"
#include "thread_pool.h"

/* variables to be exported away */
thread_pool_t *rpki_pool;

/* Functions */
void rpki_daemon_wrapper()
{
  /* initialize threads pool */
  rpki_pool = allocate_thread_pool(1);
  assert(rpki_pool);
  Log(LOG_DEBUG, "DEBUG ( %s/core/RPKI ): %d thread(s) initialized\n", config.name, 1);

  rpki_prepare_thread();

  /* giving a kick to the RPKI thread */
  send_to_pool(rpki_pool, rpki_daemon, NULL);
}

void rpki_prepare_thread()
{
  rpki_misc_db = &inter_domain_misc_dbs[FUNC_TYPE_RPKI];
  memset(rpki_misc_db, 0, sizeof(struct bgp_misc_structs));

  rpki_misc_db->is_thread = TRUE;
  rpki_misc_db->log_str = malloc(strlen("core/RPKI") + 1);
  strcpy(rpki_misc_db->log_str, "core/RPKI");
}

void rpki_daemon()
{
  struct bgp_misc_structs *r_data = rpki_misc_db;
  afi_t afi;
  safi_t safi;

  rpki_routing_db = &inter_domain_routing_dbs[FUNC_TYPE_RPKI];
  memset(rpki_routing_db, 0, sizeof(struct bgp_rt_structs));

  bgp_attr_init(HASHTABSIZE, rpki_routing_db);

  /* Let's initialize clean shared RIB */
  for (afi = AFI_IP; afi < AFI_MAX; afi++) {
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
      rpki_routing_db->rib[afi][safi] = bgp_table_init(afi, safi);
    }
  }

  rpki_link_misc_structs(r_data);

  if (config.rpki_roas_map) rpki_roas_map_load(config.rpki_roas_map);
}

int rpki_roas_map_load(char *file)
{
  struct bgp_misc_structs *r_data = rpki_misc_db;
  struct bgp_peer peer;

  Log(LOG_INFO, "INFO ( %s/%s ): [%s] (re)loading map.\n", config.name, r_data->log_str, file);

#if defined WITH_JANSSON
  json_t *roas_obj, *roa_json, *roas_json;
  json_error_t file_err;
  int roas_idx;

  rpki_init_dummy_peer(&peer);

  roas_obj = json_load_file(file, 0, &file_err);

  if (roas_obj) {
    if (!json_is_object(roas_obj)) {
      Log(LOG_ERR, "ERROR ( %s/%s ): [%s] json_is_object() failed for results: %s\n", config.name, r_data->log_str, file, file_err.text);
      exit_gracefully(1);
    }
    else {
      roas_json = json_object_get(roas_obj, "roas");
      if (roas_json == NULL || !json_is_array(roas_json)) {
        Log(LOG_ERR, "ERROR ( %s/%s ): [%s] no 'roas' element or not an array.\n", config.name, r_data->log_str, file);
        exit_gracefully(1);
      }
      else {
	for (roas_idx = 0; roa_json = json_array_get(roas_json, roas_idx); roas_idx++) {
	  json_t *prefix_json, *maxlen_json, *asn_json;
	  struct prefix p;
	  u_int8_t maxlen;
	  as_t asn;
	    
	  prefix_json = json_object_get(roa_json, "prefix");
	  if (prefix_json == NULL || !json_is_string(prefix_json)) {
	    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] no 'prefix' element in ROA #%u.\n", config.name, r_data->log_str, file, (roas_idx + 1));
	    goto exit_lane;
	  }
	  else {
	    str2prefix(json_string_value(prefix_json), &p);
	    json_decref(prefix_json);
	  }

	  asn_json = json_object_get(roa_json, "asn");
	  if (asn_json == NULL || !json_is_string(asn_json)) {
	    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] no 'asn' element in ROA #%u.\n", config.name, r_data->log_str, file, (roas_idx + 1));
	    goto exit_lane;
	  }
	  else {
	    asn = str2asn((char *)json_string_value(asn_json));
	    json_decref(asn_json);
	  }

	  maxlen_json = json_object_get(roa_json, "maxLength");
	  if (maxlen_json == NULL || !json_is_integer(maxlen_json)) {
	    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] no 'maxLength' element in ROA #%u.\n", config.name, r_data->log_str, file, (roas_idx + 1));
	    goto exit_lane;
	  }
	  else {
	    maxlen = json_integer_value(maxlen_json);
	    json_decref(maxlen_json);
	  }

	  rpki_info_add(&peer, &p, asn, maxlen);

	  exit_lane:
	  json_decref(roa_json);
	}
      }

      json_decref(roas_json);
      json_decref(roas_obj);
    }

    Log(LOG_INFO, "INFO ( %s/%s ): [%s] map successfully (re)loaded.\n", config.name, r_data->log_str, file);
  }
  else {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] json_loads() failed: %s.\n", config.name, r_data->log_str, file, file_err.text);
    exit_gracefully(1);
  }
#else
  Log(LOG_WARNING, "WARN ( %s/%s ): rpki_roas_map will not load (missing --enable-jansson).\n", config.name, r_data->log_str);
#endif

  return SUCCESS;
}

void rpki_init_dummy_peer(struct bgp_peer *peer)
{
  memset(peer, 0, sizeof(struct bgp_peer));
  peer->type = FUNC_TYPE_RPKI;
}

int rpki_info_add(struct bgp_peer *peer, struct prefix *p, as_t asn, u_int8_t maxlen)
{
  struct bgp_misc_structs *r_data = rpki_misc_db;
  struct bgp_node *route = NULL;
  struct bgp_info *ri = NULL, *new = NULL;
  struct bgp_attr attr, *attr_new = NULL;
  afi_t afi;
  safi_t safi;
  u_int32_t modulo;
  
  if (!rpki_routing_db || !r_data || !peer || !p) return;

  afi = family2afi(p->family); 
  safi = SAFI_UNICAST;
  modulo = 0;

  route = bgp_node_get(peer, rpki_routing_db->rib[afi][safi], p);

  memset(&attr, 0, sizeof(attr));
  // XXX: compose attr
  attr_new = bgp_attr_intern(peer, &attr);

  for (ri = route->info[modulo]; ri; ri = ri->next) {
    /* Received same information */
    if (attrhash_cmp(ri->attr, attr_new)) {
      /* route_node_get lock */
      bgp_unlock_node(peer, route);

      bgp_attr_unintern(peer, attr_new);

      return SUCCESS;
    }
  }

  /* Make new BGP info. */
  if (!ri) {
    new = bgp_info_new(peer);

    if (new) {
      new->peer = peer;
      new->attr = attr_new;
    }
    else return ERR;
  }

  /* Register new BGP information. */
  bgp_info_add(peer, route, new, modulo);

  /* route_node_get lock */
  bgp_unlock_node(peer, route);

  return SUCCESS;
}

void rpki_link_misc_structs(struct bgp_misc_structs *r_data)
{
  r_data->table_peer_buckets = DEFAULT_BGP_INFO_HASH; 
  r_data->table_per_peer_buckets = DEFAULT_BGP_INFO_PER_PEER_HASH; 
  r_data->table_attr_hash_buckets = HASHTABSIZE;
  r_data->table_per_peer_hash = BGP_ASPATH_HASH_PATHID;
  r_data->route_info_modulo = NULL;

/*
  XXX:
  r_data->bgp_lookup_find_peer = XXX ;
  r_data->bgp_lookup_node_match_cmp = XXX ; 
*/
}

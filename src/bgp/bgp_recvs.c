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

#define __BGP_RECVS_C

#include "../pmacct.h"
#include "bgp.h"
#include "bgp_recvs.h"

void bgp_recvs_map_validate(char *filename, struct plugin_requests *req)
{
  struct bgp_receivers *table = (struct bgp_receivers *) req->key_value_table;
  int valid = FALSE;

  /* If we have got: a) a valid pool ID and b) a valid id THEN ok */
  if (table && table->pool && table->pool[table->num].id) {
    valid = TRUE;
    table->num++;
  }
  else {
    valid = FALSE;
    table->pool[table->num].id = 0;
    table->pool[table->num].dest_len = 0;
    memset(&table->pool[table->num].dest, 0, sizeof(table->pool[table->num].dest));
    memset(&table->pool[table->num].tag_filter, 0, sizeof(struct pretag_filter));
  }
}

int bgp_recvs_parse_hostport(const char *s, struct sockaddr *addr, socklen_t *len)
{
  return Tee_parse_hostport(s, addr, len);
}

int bgp_recvs_map_id_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  struct bgp_receivers *table = (struct bgp_receivers *) req->key_value_table;
  int pool_idx;
  u_int32_t pool_id;
  char *endptr = NULL;

  if (table && table->pool) {
    if (table->num < config.nfacctd_bgp_max_peers) {
      pool_id = strtoull(value, &endptr, 10);

      if (!pool_id || pool_id > UINT32_MAX) {
        Log(LOG_ERR, "ERROR ( %s/%s ): [%s] Invalid Pool ID specified.\n", config.name, config.type, filename);
        return TRUE;
      }

      /* Ensure no pool ID duplicates */
      for (pool_idx = 0; pool_idx < table->num; pool_idx++) {
        if (pool_id == table->pool[table->num].id) {
          Log(LOG_ERR, "ERROR ( %s/%s ): [%s] Duplicate Pool ID specified: %u.\n", config.name, config.type, filename, pool_id);
          return TRUE;
        }
      }

      table->pool[table->num].id = pool_id;
    }
    else {
      Log(LOG_ERR, "ERROR ( %s/%s ): [%s] Maximum amount of receivers pool reached: %u.\n", config.name, config.type, filename, config.nfacctd_bgp_max_peers);
      return TRUE;
    }
  }
  else {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] Receivers table not allocated.\n", config.name, config.type, filename);
    return TRUE;
  }

  return FALSE;
}

int bgp_recvs_map_ip_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  struct bgp_receivers *table = (struct bgp_receivers *) req->key_value_table;
  struct bgp_receiver *target = NULL;

  if (table && table->pool) {
    target = &table->pool[table->num];
    target->dest_len = sizeof(target->dest);
    if (bgp_recvs_parse_hostport(value, (struct sockaddr *)&target->dest, &target->dest_len)) { 
      Log(LOG_ERR, "ERROR ( %s/%s ): [%s] No valid receivers.\n", config.name, config.type, filename);
      return TRUE;
    }
  }
  else {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] Receivers table not allocated.\n", config.name, config.type, filename);
    return TRUE;
  }

  return FALSE;
}

int bgp_recvs_map_tag_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  struct bgp_receivers *table = (struct bgp_receivers *) req->key_value_table;
  int ret;

  if (table && table->pool) ret = load_tags(filename, &table->pool[table->num].tag_filter, value);
  else {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] BGP receivers table not allocated.\n", config.name, config.type, filename);
    return TRUE;
  }

  if (!ret) return TRUE;
  else return FALSE;
}

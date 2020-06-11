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

#include "pmacct.h"
#include "addr.h"
#include "bgp.h"
#include "bgp_xcs.h"

void bgp_xcs_map_validate(char *filename, struct plugin_requests *req)
{
  struct bgp_xconnects *table = (struct bgp_xconnects *) req->key_value_table;
  int valid = FALSE;

  /* IF we have got 1) AF for _only one_ of src and src_addr, and dst AND
     2) AFs of src_addr and src_mask are consistent THEN we are good to go */
  if (table && table->pool) {
    if (sa_has_family((struct sockaddr *) &table->pool[table->num].src) &&
	sa_has_family((struct sockaddr *) &table->pool[table->num].dst))
      valid = TRUE;

    if (table->pool[table->num].src_addr.family &&
	table->pool[table->num].src_mask.family &&
	sa_has_family((struct sockaddr *) &table->pool[table->num].dst))
      valid = TRUE;

    if (table->pool[table->num].src_addr.family ==
	table->pool[table->num].src_mask.family)
      valid = TRUE;

    if (sa_has_family((struct sockaddr *) &table->pool[table->num].src) &&
	(table->pool[table->num].src_addr.family ||
        table->pool[table->num].src_mask.family))
      valid = FALSE;

    if (valid && table->num < req->map_entries) {
      table->num++;
      table->pool[table->num].id = table->num;
    }
    else memset(&table->pool[table->num], 0, sizeof(struct bgp_xconnect));
  }
}

int bgp_xcs_parse_hostport(const char *s, struct sockaddr *addr, socklen_t *len)
{
  return Tee_parse_hostport(s, addr, len, TRUE);
}

int bgp_xcs_map_dst_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  struct bgp_xconnects *table = (struct bgp_xconnects *) req->key_value_table;
  struct bgp_xconnect *target = NULL;

  if (table && table->pool) {
    if (table->num < req->map_entries) {
      target = &table->pool[table->num];
      target->dst_len = sizeof(target->dst);
      if (bgp_xcs_parse_hostport(value, (struct sockaddr *)&target->dst, &target->dst_len)) { 
	Log(LOG_ERR, "ERROR ( %s/%s ): [%s] Invalid BGP xconnect destination.\n", config.name, config.type, filename);
	return TRUE;
      }
    }
  }
  else {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] BGP xconnect table not allocated.\n", config.name, config.type, filename);
    return TRUE;
  }

  return FALSE;
}

int bgp_xcs_map_src_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  struct bgp_xconnects *table = (struct bgp_xconnects *) req->key_value_table;
  struct bgp_xconnect *target = NULL;

  if (table && table->pool) {
    if (table->num < req->map_entries) {
      target = &table->pool[table->num];
      target->src_len = sizeof(target->src);

      if (bgp_xcs_parse_hostport(value, (struct sockaddr *)&target->src, &target->src_len)) { 
	memset(&target->src, 0, sizeof(target->src));
	target->src_len = 0;

	if (!str_to_addr_mask(value, &target->src_addr, &target->src_mask)) {
          Log(LOG_ERR, "ERROR ( %s/%s ): [%s] Invalid BGP xconnect source.\n", config.name, config.type, filename);
          return TRUE;
	}
      }
    }
  }
  else {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] BGP xconnect table not allocated.\n", config.name, config.type, filename);
    return TRUE;
  }

  return FALSE;
}

void bgp_xcs_map_destroy()
{
  int idx;

  for (idx = 0; idx < bgp_xcs_map.num; idx++) memset(&bgp_xcs_map.pool[idx], 0, sizeof(struct bgp_xconnect));

  bgp_xcs_map.num = 0;
}

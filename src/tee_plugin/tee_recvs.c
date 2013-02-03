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

#define __TEE_RECVS_C

#include "../pmacct.h"
#include "tee_plugin.h"
#include "tee_recvs.h"

int tee_recvs_map_id_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  struct tee_receivers *table = (struct tee_receivers *) req->key_value_table; 
  int pool_idx, recv_idx, pool_id;
  char *endptr = NULL;

  if (table) {
    pool_id = strtoull(value, &endptr, 10);

    if (!pool_id || pool_id > UINT32_MAX) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Invalid Pool ID specified. ", config.name, config.type);
      return TRUE;
    }

    // XXX
  }

  return FALSE;
}

int tee_recvs_map_ip_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  return FALSE;
}

void tee_recvs_map_validate(char *filename, struct plugin_requests *req)
{
}

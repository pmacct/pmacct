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
#include "pmacct-data.h"
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

  /* select() stuff */
  struct timeval select_timeout;
  int select_fd;

  /* initial cleanups */
  reload_map_rpki_thread = FALSE;
  reload_log_rpki_thread = FALSE;

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

  if (config.rpki_roas_file) rpki_roas_file_load(config.rpki_roas_file);

  for (;;) {
    /* simplified select() until we have fds to read from */
    select_timeout.tv_sec = 1;
    select_timeout.tv_usec = 0;
    select_fd = 0;

    select(select_fd, NULL, NULL, NULL, &select_timeout);

    /* signals handling */
    if (reload_map_rpki_thread) {
      if (config.rpki_roas_file) rpki_roas_file_load(config.rpki_roas_file);

      reload_map_rpki_thread = FALSE;
    }
  }
}

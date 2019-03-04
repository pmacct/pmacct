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
  int ret;

  /* select() stuff */
  struct timeval select_timeout;
  int select_fd, select_num;
  fd_set read_desc;

  /* rpki_rtr_cache stuff */
  struct rpki_rtr_handle rpki_cache;

  /* initial cleanups */
  reload_map_rpki_thread = FALSE;
  reload_log_rpki_thread = FALSE;
  memset(&rpki_cache, 0, sizeof(rpki_cache));

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

  if (config.rpki_roas_file && config.rpki_rtr_cache) {
    Log(LOG_ERR, "ERROR ( %s/core/RPKI ): rpki_roas_file and rpki_rtr_cache are mutual exclusive. Exiting.\n", config.name);
    exit_gracefully(1);
  }

  if (config.rpki_roas_file) {
    ret = rpki_roas_file_load(config.rpki_roas_file,
			rpki_routing_db->rib[AFI_IP][SAFI_UNICAST],
			rpki_routing_db->rib[AFI_IP6][SAFI_UNICAST]);
  }

  if (config.rpki_rtr_cache) {
    if (config.rpki_rtr_cache_version != RPKI_RTR_V0 && config.rpki_rtr_cache_version != RPKI_RTR_V1) {
      Log(LOG_ERR, "ERROR ( %s/core/RPKI ): rpki_rtr_cache_version must be 0 or 1. Exiting.\n", config.name);
      exit_gracefully(1);
    }
 
    rpki_cache.fd = ERR;
    rpki_cache.socklen = sizeof(rpki_cache.sock);
    parse_hostport(config.rpki_rtr_cache, (struct sockaddr *)&rpki_cache.sock, &rpki_cache.socklen);
  }

  for (;;) {
    select_again:

    /* select inits */
    FD_ZERO(&read_desc);
    select_fd = 0;
    select_timeout.tv_sec = 1;
    select_timeout.tv_usec = 0;

    if (config.rpki_rtr_cache) {
      if (rpki_cache.fd > 0) {
	select_fd = (rpki_cache.fd + 1);
	FD_SET(rpki_cache.fd, &read_desc);
      }
    }

    select_num = select(select_fd, &read_desc, NULL, NULL, &select_timeout);
    if (select_num < 0) goto select_again;

    /* signals handling */
    if (reload_map_rpki_thread) {
      if (config.rpki_roas_file) {
	struct bgp_table *backup_rib_v4, *backup_rib_v6;
	struct bgp_table *saved_rib_v4, *saved_rib_v6;

	backup_rib_v4 = bgp_table_init(AFI_IP, SAFI_UNICAST);
	backup_rib_v6 = bgp_table_init(AFI_IP6, SAFI_UNICAST);

	saved_rib_v4 = rpki_routing_db->rib[AFI_IP][SAFI_UNICAST];
	saved_rib_v6 = rpki_routing_db->rib[AFI_IP6][SAFI_UNICAST];

	ret = rpki_roas_file_load(config.rpki_roas_file, backup_rib_v4, backup_rib_v6);

	/* load successful */
	if (!ret) {
	  rpki_routing_db->rib[AFI_IP][SAFI_UNICAST] = backup_rib_v4;
	  rpki_routing_db->rib[AFI_IP6][SAFI_UNICAST] = backup_rib_v6;

	  /* allow some generous time for any existing lookup to complete */
	  sleep(DEFAULT_SLOTH_SLEEP_TIME);

	  bgp_table_info_delete(&rpki_peer, saved_rib_v4, AFI_IP, SAFI_UNICAST);
	  bgp_table_info_delete(&rpki_peer, saved_rib_v6, AFI_IP6, SAFI_UNICAST);

	  bgp_table_free(saved_rib_v4);
	  bgp_table_free(saved_rib_v6);
	}
	else {
	  bgp_table_info_delete(&rpki_peer, backup_rib_v4, AFI_IP, SAFI_UNICAST);
	  bgp_table_info_delete(&rpki_peer, backup_rib_v6, AFI_IP6, SAFI_UNICAST);

	  bgp_table_free(backup_rib_v4);
	  bgp_table_free(backup_rib_v6);
	}
      }

      reload_map_rpki_thread = FALSE;
    }

    if (config.rpki_rtr_cache) {
      /* timeout */
      if (!select_num) {
	if (rpki_cache.fd < 0) rpki_rtr_connect(&rpki_cache);
	if (!rpki_cache.session_id) rpki_rtr_send_reset_query(&rpki_cache);
	if (rpki_cache.serial) rpki_rtr_send_serial_query(&rpki_cache);
      }
      else rpki_rtr_parse_msg(&rpki_cache);
    }
  }
}

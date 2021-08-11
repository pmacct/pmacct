/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2021 by Paolo Lucente
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
#include "pmacct-data.h"
#include "bgp/bgp.h"
#include "rpki.h"
#include "thread_pool.h"

/* variables to be exported away */
thread_pool_t *rpki_pool;
struct bgp_rt_structs *rpki_roa_db;
struct bgp_misc_structs *rpki_misc_db;
struct bgp_peer rpki_peer;

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

int rpki_daemon()
{
  struct bgp_misc_structs *m_data = rpki_misc_db;
  afi_t afi;
  safi_t safi;

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
  rpki_init_dummy_peer(&rpki_peer);

  rpki_roa_db = &inter_domain_routing_dbs[FUNC_TYPE_RPKI];
  memset(rpki_roa_db, 0, sizeof(struct bgp_rt_structs));

  bgp_attr_init(HASHTABSIZE, rpki_roa_db);

  /* Let's initialize clean shared RIB */
  for (afi = AFI_IP; afi < AFI_MAX; afi++) {
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
      rpki_roa_db->rib[afi][safi] = bgp_table_init(afi, safi);
    }
  }

  rpki_link_misc_structs(m_data);

  if (config.rpki_roas_file && config.rpki_rtr_cache) {
    Log(LOG_ERR, "ERROR ( %s/core/RPKI ): rpki_roas_file and rpki_rtr_cache are mutual exclusive. Exiting.\n", config.name);
    exit_gracefully(1);
  }

  if (config.rpki_roas_file) {
    rpki_roas_file_load(config.rpki_roas_file,
			rpki_roa_db->rib[AFI_IP][SAFI_UNICAST],
			rpki_roa_db->rib[AFI_IP6][SAFI_UNICAST]);
  }

  if (config.rpki_rtr_cache) {
    if (config.rpki_rtr_cache_version != RPKI_RTR_V0 && config.rpki_rtr_cache_version != RPKI_RTR_V1) {
      Log(LOG_ERR, "ERROR ( %s/core/RPKI ): rpki_rtr_cache_version must be 0 or 1. Exiting.\n", config.name);
      exit_gracefully(1);
    }

    if (config.rpki_rtr_cache_version == RPKI_RTR_V0) {
      rpki_cache.retry.ivl = RPKI_RTR_V0_DEFAULT_RETRY_IVL;
      rpki_cache.refresh.ivl = RPKI_RTR_V0_DEFAULT_REFRESH_IVL;
      rpki_cache.expire.ivl = RPKI_RTR_V0_DEFAULT_EXPIRE_IVL;
    }

    if (config.rpki_rtr_cache_version == RPKI_RTR_V1) {
      rpki_cache.retry.ivl = RPKI_RTR_V1_DEFAULT_RETRY_IVL;
      rpki_cache.refresh.ivl = RPKI_RTR_V1_DEFAULT_REFRESH_IVL;
      rpki_cache.expire.ivl = RPKI_RTR_V1_DEFAULT_EXPIRE_IVL;
    }
 
    rpki_cache.now = rpki_cache.expire.tstamp = time(NULL);

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

      select_timeout.tv_sec = rpki_rtr_eval_timeout(&rpki_cache);
    }

    select_num = select(select_fd, &read_desc, NULL, NULL, &select_timeout);

    if (config.rpki_rtr_cache) rpki_cache.now = time(NULL);
    if (select_num < 0) goto select_again;

    /* signals handling */
    if (reload_map_rpki_thread) {
      rpki_roas_file_reload();
      reload_map_rpki_thread = FALSE;
    }

    if (config.rpki_rtr_cache) {
      /* timeout */
      if (!select_num) {
	if (rpki_cache.fd < 0) rpki_rtr_connect(&rpki_cache);
	if (!rpki_cache.session_id) rpki_rtr_send_reset_query(&rpki_cache);
	if (rpki_cache.serial) rpki_rtr_send_serial_query(&rpki_cache);
	rpki_rtr_eval_expire(&rpki_cache);
      }
      else rpki_rtr_parse_msg(&rpki_cache);
    }
  }

  return SUCCESS;
}

void rpki_roas_file_reload()
{
  struct bgp_table *saved_rib_v4, *saved_rib_v6;
  struct bgp_table *new_rib_v4, *new_rib_v6;
  int ret;

  if (config.rpki_roas_file) {
    new_rib_v4 = bgp_table_init(AFI_IP, SAFI_UNICAST);
    new_rib_v6 = bgp_table_init(AFI_IP6, SAFI_UNICAST);

    saved_rib_v4 = rpki_roa_db->rib[AFI_IP][SAFI_UNICAST];
    saved_rib_v6 = rpki_roa_db->rib[AFI_IP6][SAFI_UNICAST];

    ret = rpki_roas_file_load(config.rpki_roas_file, new_rib_v4, new_rib_v6);

    /* load successful */
    if (!ret) {
      rpki_roa_db->rib[AFI_IP][SAFI_UNICAST] = new_rib_v4;
      rpki_roa_db->rib[AFI_IP6][SAFI_UNICAST] = new_rib_v6;

      /* allow some generous time for any existing lookup to complete */
      sleep(DEFAULT_SLOTH_SLEEP_TIME);

      rpki_ribs_free(&rpki_peer, saved_rib_v4, saved_rib_v6);
    }
    else rpki_ribs_free(&rpki_peer, new_rib_v4, new_rib_v6);
  }
}

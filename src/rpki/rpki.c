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
  int select_fd;

  /* rpki_rtr_server stuff */
  struct sockaddr_storage rpki_srv;
  socklen_t rpki_srv_len;
  int rpki_srv_fd;

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

  if (config.rpki_roas_file && config.rpki_rtr_server) {
    Log(LOG_ERR, "ERROR ( %s/core/RPKI ): rpki_roas_file and rpki_rtr_server are mutual exclusive. Exiting.\n", config.name);
    exit_gracefully(1);
  }

  if (config.rpki_roas_file) {
    ret = rpki_roas_file_load(config.rpki_roas_file,
			rpki_routing_db->rib[AFI_IP][SAFI_UNICAST],
			rpki_routing_db->rib[AFI_IP6][SAFI_UNICAST]);
  }

  if (config.rpki_rtr_server) {
    if (config.rpki_rtr_server_version != RPKI_RTR_V0 && config.rpki_rtr_server_version != RPKI_RTR_V1) {
      Log(LOG_ERR, "ERROR ( %s/core/RPKI ): rpki_rtr_server_version must be 0 or 1. Exiting.\n", config.name);
      exit_gracefully(1);
    }
 
    rpki_srv_len = sizeof(rpki_srv);
    parse_hostport(config.rpki_rtr_server, (struct sockaddr *)&rpki_srv, &rpki_srv_len);

    if ((rpki_srv_fd = socket(rpki_srv.ss_family, SOCK_DGRAM, 0)) == -1) {
      Log(LOG_ERR, "ERROR ( %s/core/RPKI ): rpki_rtr_server: socket() failed: %s\n", config.name, strerror(errno));
      exit_gracefully(1);
    }

    if (config.rpki_rtr_server_ipprec) {
      int rc, opt = config.rpki_rtr_server_ipprec << 5;

      rc = setsockopt(rpki_srv_fd, IPPROTO_IP, IP_TOS, &opt, (socklen_t) sizeof(opt));
      if (rc < 0) Log(LOG_ERR, "WARN ( %s/core/RPKI ): rpki_rtr_server: setsockopt() failed for IP_TOS (errno: %d).\n", config.name, errno);
    }

    if (config.rpki_rtr_server_pipe_size) {
      socklen_t l = sizeof(config.rpki_rtr_server_pipe_size);
      int saved = 0, obtained = 0;

      getsockopt(rpki_srv_fd, SOL_SOCKET, SO_RCVBUF, &saved, &l);
      Setsocksize(rpki_srv_fd, SOL_SOCKET, SO_RCVBUF, &config.rpki_rtr_server_pipe_size, (socklen_t) sizeof(config.rpki_rtr_server_pipe_size));
      getsockopt(rpki_srv_fd, SOL_SOCKET, SO_RCVBUF, &obtained, &l);

      Setsocksize(rpki_srv_fd, SOL_SOCKET, SO_RCVBUF, &saved, l);
      getsockopt(rpki_srv_fd, SOL_SOCKET, SO_RCVBUF, &obtained, &l);
      Log(LOG_INFO, "INFO ( %s/core/RPKI ): rpki_rtr_srv_pipe_size: obtained=%d target=%d.\n",
	  config.name, obtained, config.rpki_rtr_server_pipe_size);
    }

    if (connect(rpki_srv_fd, (struct sockaddr *) &rpki_srv, rpki_srv_len) == -1) {
      Log(LOG_ERR, "ERROR ( %s/core/RPKI ): rpki_rtr_server: connect() failed: %s\n", config.name, strerror(errno));
      exit_gracefully(1);
    }

    Log(LOG_INFO, "INFO ( %s/core/RPKI ): Connecting to RTR Server: %s\n", config.name, config.rpki_rtr_server);

    // XXX
  }

  for (;;) {
    /* simplified select() until we have fds to read from */
    select_timeout.tv_sec = 1;
    select_timeout.tv_usec = 0;
    select_fd = 0;

    select(select_fd, NULL, NULL, NULL, &select_timeout);

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
  }
}

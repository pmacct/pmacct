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
#define __BGP_BLACKHOLE_C

/* includes */
#include "pmacct.h"
#include "addr.h"
#include "bgp.h"
#include "bgp_blackhole.h"
#include "thread_pool.h"

/* variables to be exported away */
thread_pool_t *bgp_blackhole_pool;

/* Functions */
void bgp_blackhole_daemon_wrapper()
{
  /* initialize threads pool */
  bgp_blackhole_pool = allocate_thread_pool(1);
  assert(bgp_blackhole_pool);
  Log(LOG_DEBUG, "DEBUG ( %s/core/BH ): %d thread(s) initialized\n", config.name, 1);

  bgp_blackhole_prepare_filter();
  bgp_blackhole_prepare_thread();

  /* giving a kick to the BGP blackhole thread */
  send_to_pool(bgp_blackhole_pool, bgp_blackhole_daemon, NULL);
}

void bgp_blackhole_prepare_thread()
{
  bgp_blackhole_misc_db = &inter_domain_misc_dbs[FUNC_TYPE_BGP_BLACKHOLE];
  memset(bgp_blackhole_misc_db, 0, sizeof(struct bgp_misc_structs));

  bgp_blackhole_misc_db->is_thread = TRUE;
  bgp_blackhole_misc_db->log_str = malloc(strlen("core/BH") + 1);
  strcpy(bgp_blackhole_misc_db->log_str, "core/BH");
}

void bgp_blackhole_prepare_filter()
{
  char *stdcomms, *token;
  int len;

  bloom_init(bgp_blackhole_filter, BGP_BLACKHOLE_DEFAULT_BF_ENTRIES, 0.01);

  stdcomms = strdup(config.bgp_blackhole_stdcomm_list);
  while ((token = extract_token(&stdcomms, ','))) {
    u_int32_t stdcomm;
    int ret;

    ret = community_str2com_simple(token, &stdcomm);
    if (ret == ERR) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Invalid community '%s' in 'bgp_blackhole_stdcomm_list'.\n", config.name, bgp_blackhole_misc_db->log_str, token);
      exit_gracefully(1);
    }
    
    bloom_add(bgp_blackhole_filter, &stdcomm, sizeof(stdcomm));
  }
}

void bgp_blackhole_daemon()
{
  struct bgp_misc_structs *m_data = bgp_blackhole_misc_db;
  afi_t afi;
  safi_t safi;
  int ret;

  // XXX

  bgp_blackhole_db = &inter_domain_routing_dbs[FUNC_TYPE_BGP_BLACKHOLE];
  memset(bgp_blackhole_db, 0, sizeof(struct bgp_rt_structs));

  bgp_attr_init(HASHTABSIZE, bgp_blackhole_db);

  /* Let's initialize clean shared RIB */
  for (afi = AFI_IP; afi < AFI_MAX; afi++) {
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
      bgp_blackhole_db->rib[afi][safi] = bgp_table_init(afi, safi);
    }
  }

  bgp_blackhole_link_misc_structs(m_data);

  // XXX

  for (;;) {
    // XXX

    sleep(DEFAULT_SLOTH_SLEEP_TIME);
  }
}

int bgp_blackhole_evaluate_comms(void *a)
{
  struct bgp_attr *attr = (struct bgp_attr *) a;
  struct community *comm;
  int idx, ret;
  u_int32_t val;

  if (attr && attr->community && attr->community->val) {
    comm = attr->community;

    for (idx = 0; idx < comm->size; idx++) {
      val = community_val_get(comm, idx);

      ret = bloom_check(bgp_blackhole_filter, &val, sizeof(val)); 
      if (ret) return ret;
    }
  }

  return FALSE;
}

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
#if defined WITH_ZMQ
#include "zmq_common.h"
#endif

/* variables to be exported away */
thread_pool_t *bgp_blackhole_pool;

/* Functions */
void bgp_blackhole_daemon_wrapper()
{
#if defined WITH_ZMQ
  struct p_zmq_host *bgp_blackhole_zmq_host = NULL;
  char inproc_blackhole_str[] = "inproc://bgp_blackhole";
#endif

  /* initialize threads pool */
  bgp_blackhole_pool = allocate_thread_pool(1);
  assert(bgp_blackhole_pool);
  Log(LOG_DEBUG, "DEBUG ( %s/core/BH ): %d thread(s) initialized\n", config.name, 1);

  bgp_blackhole_prepare_filter();
  bgp_blackhole_prepare_thread();

#if defined WITH_ZMQ
  bgp_blackhole_zmq_host = malloc(sizeof(struct p_zmq_host));
  if (!bgp_blackhole_zmq_host) {
    Log(LOG_ERR, "ERROR ( %s/%s ): Unable to malloc() bgp_blackhole_zmq_host. Terminating thread.\n", config.name, bgp_misc_db->log_str);
    exit_gracefully(1);
  }
  else memset(bgp_blackhole_zmq_host, 0, sizeof(struct p_zmq_host));

  p_zmq_set_log_id(bgp_blackhole_zmq_host, bgp_blackhole_misc_db->log_str);
  p_zmq_set_address(bgp_blackhole_zmq_host, inproc_blackhole_str);
  p_zmq_ctx_setup(bgp_blackhole_zmq_host);
  bgp_blackhole_misc_db->bgp_blackhole_zmq_host = bgp_blackhole_zmq_host;
#endif

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

void bgp_blackhole_init_dummy_peer(struct bgp_peer *peer)
{
  memset(peer, 0, sizeof(struct bgp_peer));
  peer->type = FUNC_TYPE_BGP_BLACKHOLE;
}

void bgp_blackhole_prepare_filter()
{
  char *stdcomms, *token;
  int len;

  bgp_blackhole_filter = malloc(sizeof(struct bloom));
  bloom_init(bgp_blackhole_filter, BGP_BLACKHOLE_DEFAULT_BF_ENTRIES, 0.01);

  stdcomms = strdup(config.bgp_blackhole_stdcomm_list);
  bgp_blackhole_comms = community_new(&bgp_blackhole_peer);
 
  while ((token = extract_token(&stdcomms, ','))) {
    u_int32_t stdcomm;
    int ret;

    ret = community_str2com_simple(token, &stdcomm);
    if (ret == ERR) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Invalid community '%s' in 'bgp_blackhole_stdcomm_list'.\n", config.name, bgp_blackhole_misc_db->log_str, token);
      exit_gracefully(1);
    }
    
    bloom_add(bgp_blackhole_filter, &stdcomm, sizeof(stdcomm));
    community_add_val(&bgp_blackhole_peer, bgp_blackhole_comms, stdcomm); 
  }
}

void bgp_blackhole_daemon()
{
  struct bgp_misc_structs *m_data = bgp_blackhole_misc_db;
  struct bgp_blackhole_itc bbitc;
  
  afi_t afi;
  safi_t safi;
  int ret;

  /* ZeroMQ stuff */
#if defined WITH_ZMQ
  struct p_zmq_host *bgp_blackhole_zmq_host;
  
  bgp_blackhole_zmq_host = m_data->bgp_blackhole_zmq_host;
  p_zmq_pull_bind_setup(bgp_blackhole_zmq_host);
#endif

  bgp_blackhole_init_dummy_peer(&bgp_blackhole_peer);

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

  for (;;) {
    ret = p_zmq_recv_poll(&bgp_blackhole_zmq_host->sock_inproc, (DEFAULT_SLOTH_SLEEP_TIME * 1000));

    switch (ret) {
    case TRUE: /* got data */
      ret = p_zmq_recv_bin(&bgp_blackhole_zmq_host->sock_inproc, &bbitc, sizeof(bbitc));
      if (ret < 0) continue; /* ZMQ_RECONNECT_IVL */
      break;
    case FALSE: /* timeout */
      continue;
      break;
    case ERR: /* error */
    default:
      continue; /* ZMQ_RECONNECT_IVL */
      break;
    }

    // XXX: process data

    // XXX: free not needed alloc'd structs
  }
}

int bgp_blackhole_evaluate_comms(void *a)
{
  struct bgp_attr *attr = (struct bgp_attr *) a;
  struct community *comm;
  int idx, idx2, ret, ret2;
  u_int32_t val, val2;

  if (attr && attr->community && attr->community->val) {
    comm = attr->community;

    for (idx = 0; idx < comm->size; idx++) {
      val = community_val_get(comm, idx);

      ret = bloom_check(bgp_blackhole_filter, &val, sizeof(val)); 
      if (ret) {
	/* let's make sure it is not a false positive */
	for (idx2 = 0; idx2 < bgp_blackhole_comms->size; idx2++) {
	  val2 = community_val_get(bgp_blackhole_comms, idx2);
	  ret2 = community_compare(&val, &val2);
	  if (!ret2) return ret;
	}
	/* if we are here it was a false positive; let's continue our quest */
      }
    }
  }

  return FALSE;
}

int bgp_blackhole_instrument(struct bgp_peer *peer, struct prefix *p, void *a, afi_t afi, safi_t safi)
{
  struct bgp_misc_structs *m_data = bgp_blackhole_misc_db;
  struct bgp_attr *acopy, *attr = (struct bgp_attr *) a;
  struct prefix *pcopy;
  struct bgp_peer *peer_copy;
  struct bgp_blackhole_itc bbitc;
  struct p_zmq_host *bgp_blackhole_zmq_host;

  pcopy = prefix_new();
  prefix_copy(pcopy, p);

  acopy = malloc(sizeof(struct bgp_attr));
  memcpy(acopy, attr, sizeof(struct bgp_attr));

  peer_copy = malloc(sizeof(struct bgp_peer));
  memcpy(peer_copy, peer, sizeof(struct bgp_peer));

  if (attr->aspath) acopy->aspath = aspath_dup(attr->aspath);
  if (attr->community) acopy->community = community_dup(attr->community);
  if (attr->ecommunity) acopy->ecommunity = ecommunity_dup(attr->ecommunity);
  if (attr->lcommunity) acopy->lcommunity = lcommunity_dup(attr->lcommunity);

  memset(&bbitc, 0, sizeof(bbitc));
  bbitc.peer = peer_copy;
  bbitc.afi = afi;
  bbitc.safi = safi;
  bbitc.p = pcopy;
  bbitc.attr = acopy;

  bgp_blackhole_zmq_host = m_data->bgp_blackhole_zmq_host;
  p_zmq_send_bin(&bgp_blackhole_zmq_host->sock_inproc, &bbitc, sizeof(bbitc), FALSE);
}

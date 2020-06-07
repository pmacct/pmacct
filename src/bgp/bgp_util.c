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

/* includes */
#include "pmacct.h"
#include "addr.h"
#include "pmacct-data.h"
#include "addr.h"
#include "bgp.h"
#include "thread_pool.h"
#if defined WITH_RABBITMQ
#include "amqp_common.h"
#endif
#ifdef WITH_KAFKA
#include "kafka_common.h"
#endif

/* BGP Address Famiy Identifier to UNIX Address Family converter. */
int bgp_afi2family (int afi)
{
  if (afi == AFI_IP)
    return AF_INET;
  else if (afi == AFI_IP6)
    return AF_INET6;
  return SUCCESS;
}

int bgp_rd_ntoh(rd_t *rd)
{
  struct rd_ip  *rdi;
  struct rd_as  *rda;
  struct rd_as4 *rda4;

  if (!rd) return ERR;

  rd->type = ntohs(rd->type);

  switch(rd->type) {
  case RD_TYPE_AS:
    rda = (struct rd_as *) rd;
    rda->as = ntohs(rda->as);
    rda->val = ntohl(rda->val);
    break;
  case RD_TYPE_IP:
    rdi = (struct rd_ip *) rd;
    rdi->val = ntohs(rdi->val);
    break;
  case RD_TYPE_AS4:
    rda4 = (struct rd_as4 *) rd;
    rda4->as = ntohl(rda4->as);
    rda4->val = ntohs(rda4->val);
    break;
  default:
    return ERR;
    break;
  }

  return SUCCESS;
}

int bgp_rd2str(char *str, rd_t *rd)
{
  struct rd_ip  *rdi;
  struct rd_as  *rda;
  struct rd_as4 *rda4;
  struct host_addr a;
  char ip_address[INET6_ADDRSTRLEN];

  switch (rd->type) {
  case RD_TYPE_AS:
    rda = (struct rd_as *) rd;
    sprintf(str, "%u:%u:%u", rda->type, rda->as, rda->val); 
    break;
  case RD_TYPE_IP:
    rdi = (struct rd_ip *) rd;
    a.family = AF_INET;
    a.address.ipv4.s_addr = rdi->ip.s_addr;
    addr_to_str(ip_address, &a);
    sprintf(str, "%u:%s:%u", rdi->type, ip_address, rdi->val); 
    break;
  case RD_TYPE_AS4:
    rda4 = (struct rd_as4 *) rd;
    sprintf(str, "%u:%u:%u", rda4->type, rda4->as, rda4->val); 
    break;
  case RD_TYPE_VRFID:
    rda = (struct rd_as *) rd; 
    sprintf(str, "vrfid:%u", rda->val);
    break;
  default:
    sprintf(str, "unknown");
    break; 
  }

  return TRUE;
}

int bgp_str2rd(rd_t *output, char *value)
{
  struct host_addr a;
  char *endptr, *token;
  u_int32_t tmp32;
  struct rd_ip  *rdi;
  struct rd_as  *rda;
  struct rd_as4 *rda4;
  int idx = 0;
  rd_t rd;

  memset(&a, 0, sizeof(a));
  memset(&rd, 0, sizeof(rd));

  /* type:RD_subfield1:RD_subfield2 */
  while ( (token = extract_token(&value, ':')) && idx < 3) {
    if (idx == 0) {
      tmp32 = strtoul(token, &endptr, 10);
      rd.type = tmp32;
      switch (rd.type) {
      case RD_TYPE_AS:
        rda = (struct rd_as *) &rd;
        break;
      case RD_TYPE_IP:
        rdi = (struct rd_ip *) &rd;
        break;
      case RD_TYPE_AS4:
        rda4 = (struct rd_as4 *) &rd;
        break;
      default:
        printf("ERROR: Invalid RD type specified\n");
        return FALSE;
      }
    }
    if (idx == 1) {
      switch (rd.type) {
      case RD_TYPE_AS:
        tmp32 = strtoul(token, &endptr, 10);
        rda->as = tmp32;
        break;
      case RD_TYPE_IP:
        memset(&a, 0, sizeof(a));
        str_to_addr(token, &a);
        if (a.family == AF_INET) rdi->ip.s_addr = a.address.ipv4.s_addr;
        break;
      case RD_TYPE_AS4:
        tmp32 = strtoul(token, &endptr, 10);
        rda4->as = tmp32;
        break;
      }
    }
    if (idx == 2) {
      switch (rd.type) {
      case RD_TYPE_AS:
        tmp32 = strtoul(token, &endptr, 10);
        rda->val = tmp32;
        break;
      case RD_TYPE_IP:
        tmp32 = strtoul(token, &endptr, 10);
        rdi->val = tmp32;
        break;
      case RD_TYPE_AS4:
        tmp32 = strtoul(token, &endptr, 10);
        rda4->val = tmp32;
        break;
      }
    }

    idx++;
  }

  memcpy(output, &rd, sizeof(rd));

  return TRUE;
}

int bgp_label2str(char *str, u_char *label)
{
  unsigned long int tmp;
  char *endp;

  snprintf(str, 10, "0x%02x%02x%01x",
	(unsigned)(unsigned char)label[0],
	(unsigned)(unsigned char)label[1],
	(unsigned)(unsigned char)(label[2] >> 4));
  
  tmp = strtoul(str, &endp, 16);
  snprintf(str, 8, "%lu", tmp);

  return TRUE;
}

/* Allocate bgp_attr_extra */
struct bgp_attr_extra *bgp_attr_extra_new(struct bgp_info *ri)
{
  struct bgp_misc_structs *bms;
  struct bgp_attr_extra *new;

  if (!ri || !ri->peer) return NULL;

  bms = bgp_select_misc_db(ri->peer->type);

  if (!bms) return NULL;

  new = malloc(sizeof(struct bgp_attr_extra));
  if (!new) {
    Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (bgp_attr_extra_new). Exiting ..\n", config.name, bms->log_str);
    exit_gracefully(1);
  }
  else memset(new, 0, sizeof (struct bgp_attr_extra));

  return new;
}

void bgp_attr_extra_free(struct bgp_peer *peer, struct bgp_attr_extra **attr_extra)
{
  struct bgp_misc_structs *bms;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  if (attr_extra && (*attr_extra)) {
    free(*attr_extra);
    *attr_extra = NULL;
  }
}

/* Get bgp_info extra information for the given bgp_info */
struct bgp_attr_extra *bgp_attr_extra_get(struct bgp_info *ri)
{
  if (!ri->attr_extra) {
    ri->attr_extra = bgp_attr_extra_new(ri);
  }

  return ri->attr_extra;
}

struct bgp_attr_extra *bgp_attr_extra_process(struct bgp_peer *peer, struct bgp_info *ri, afi_t afi, safi_t safi, struct bgp_attr_extra *attr_extra)
{
  struct bgp_attr_extra *rie = NULL;

  /* Install/update MPLS stuff if required */
  if (safi == SAFI_MPLS_LABEL || safi == SAFI_MPLS_VPN) {
    if (!rie) {
      rie = bgp_attr_extra_get(ri);
    }

    if (rie) {
      if (safi == SAFI_MPLS_VPN) {
	memcpy(&rie->rd, &attr_extra->rd, sizeof(rd_t));
      }

      memcpy(&rie->label, &attr_extra->label, 3);
    }
  }

  /* Install/update BGP ADD-PATHs stuff if required */
  if (peer->cap_add_paths[afi][safi]) {
    if (!rie) {
      rie = bgp_attr_extra_get(ri);
    }

    if (rie) {
      rie->path_id = attr_extra->path_id;
    }
  }

  /* AIGP attribute */
  if (attr_extra->aigp) {
    if (!rie) {
      rie = bgp_attr_extra_get(ri);
    }

    if (rie) {
      rie->aigp = attr_extra->aigp;
    }
  }

  /* Prefix-SID attribute */
  if (attr_extra->psid_li) {
    if (!rie) {
      rie = bgp_attr_extra_get(ri);
    }

    if (rie) {
      rie->psid_li = attr_extra->psid_li;
    }
  }

  return rie;
}

/* Allocate new bgp info structure. */
struct bgp_info *bgp_info_new(struct bgp_peer *peer)
{
  struct bgp_misc_structs *bms;
  struct bgp_info *new;

  if (!peer) return NULL;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) return NULL;

  new = malloc(sizeof(struct bgp_info));
  if (!new) {
    Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (bgp_info_new). Exiting ..\n", config.name, bms->log_str);
    exit_gracefully(1);
  }
  else memset(new, 0, sizeof (struct bgp_info));
  
  return new;
}

void bgp_info_add(struct bgp_peer *peer, struct bgp_node *rn, struct bgp_info *ri, u_int32_t modulo)
{
  struct bgp_info *top;

  top = rn->info[modulo];

  ri->next = rn->info[modulo];
  ri->prev = NULL;
  if (top)
    top->prev = ri;
  rn->info[modulo] = ri;

  bgp_lock_node(peer, rn);
  ri->peer->lock++;
}

void bgp_info_delete(struct bgp_peer *peer, struct bgp_node *rn, struct bgp_info *ri, u_int32_t modulo)
{
  struct bgp_misc_structs *bms;

  bms = bgp_select_misc_db(peer->type);

  if (ri->next) {
    ri->next->prev = ri->prev;
  }
  if (ri->prev) {
    ri->prev->next = ri->next;
  }
  else {
    rn->info[modulo] = ri->next;
  }

  bgp_info_free(peer, ri, bms->bgp_extra_data_free);

  bgp_unlock_node(peer, rn);
}

/* Free bgp route information. */
void bgp_info_free(struct bgp_peer *peer, struct bgp_info *ri, void (*bgp_extra_data_free)(struct bgp_msg_extra_data *))
{
  if (ri->attr) bgp_attr_unintern(peer, ri->attr);

  bgp_attr_extra_free(peer, &ri->attr_extra);
  if (bgp_extra_data_free) (*bgp_extra_data_free)(&ri->bmed);

  ri->peer->lock--;
  free(ri);
}

/* Initialization of attributes */
void bgp_attr_init(int buckets, struct bgp_rt_structs *inter_domain_routing_db)
{
  aspath_init(buckets, &inter_domain_routing_db->ashash);
  attrhash_init(buckets, &inter_domain_routing_db->attrhash);
  community_init(buckets, &inter_domain_routing_db->comhash);
  ecommunity_init(buckets, &inter_domain_routing_db->ecomhash);
  lcommunity_init(buckets, &inter_domain_routing_db->lcomhash);
}

unsigned int attrhash_key_make(void *p)
{
  struct bgp_attr *attr = (struct bgp_attr *) p;
  unsigned int key = 0;

  key += attr->origin;
  key += attr->nexthop.s_addr;
  key += attr->med;
  key += attr->local_pref;

  if (attr->aspath)
    key += aspath_key_make(attr->aspath);
  if (attr->community)
    key += community_hash_make(attr->community);
  if (attr->ecommunity)
    key += ecommunity_hash_make(attr->ecommunity);
  if (attr->lcommunity)
    key += lcommunity_hash_make(attr->lcommunity);

  /* XXX: add mp_nexthop to key */

  return key;
}

int attrhash_cmp(const void *p1, const void *p2)
{
  const struct bgp_attr *attr1 = (const struct bgp_attr *)p1;
  const struct bgp_attr *attr2 = (const struct bgp_attr *)p2;

  if (attr1->flag == attr2->flag
      && attr1->origin == attr2->origin
      && attr1->nexthop.s_addr == attr2->nexthop.s_addr
      && attr1->aspath == attr2->aspath
      && attr1->community == attr2->community
      && attr1->ecommunity == attr2->ecommunity
      && attr1->lcommunity == attr2->lcommunity
      && attr1->med == attr2->med
      && attr1->local_pref == attr2->local_pref
      && !host_addr_cmp2((struct host_addr *)&attr1->mp_nexthop, (struct host_addr *)&attr2->mp_nexthop))
    return TRUE;

  return FALSE;
}

void attrhash_init(int buckets, struct hash **loc_attrhash)
{
  (*loc_attrhash) = (struct hash *) hash_create(buckets, attrhash_key_make, attrhash_cmp);
}

/* Internet argument attribute. */
struct bgp_attr *bgp_attr_intern(struct bgp_peer *peer, struct bgp_attr *attr)
{
  struct bgp_rt_structs *inter_domain_routing_db;
  struct bgp_attr *find;

  if (!peer) return NULL;

  inter_domain_routing_db = bgp_select_routing_db(peer->type);

  if (!inter_domain_routing_db) return NULL;
 
  /* Intern referenced strucutre. */
  if (attr->aspath) {
    if (! attr->aspath->refcnt)
      attr->aspath = aspath_intern(peer, attr->aspath);
  else
    attr->aspath->refcnt++;
  }
  if (attr->community) {
    if (! attr->community->refcnt)
      attr->community = community_intern(peer, attr->community);
    else
      attr->community->refcnt++;
  }
  if (attr->ecommunity) {
    if (!attr->ecommunity->refcnt)
      attr->ecommunity = ecommunity_intern(peer, attr->ecommunity);
  else
    attr->ecommunity->refcnt++;
  }
  if (attr->lcommunity) {
    if (!attr->lcommunity->refcnt)
      attr->lcommunity = lcommunity_intern(peer, attr->lcommunity);
  else
    attr->lcommunity->refcnt++;
  }
 
  find = (struct bgp_attr *) hash_get(peer, inter_domain_routing_db->attrhash, attr, bgp_attr_hash_alloc);
  find->refcnt++;

  return find;
}

/* Free bgp attribute and aspath. */
void bgp_attr_unintern(struct bgp_peer *peer, struct bgp_attr *attr)
{
  struct bgp_rt_structs *inter_domain_routing_db;
  struct bgp_misc_structs *bms;
  struct bgp_attr *ret;
  struct aspath *aspath;
  struct community *community;
  struct ecommunity *ecommunity = NULL;
  struct lcommunity *lcommunity = NULL;

  if (!peer) return;

  inter_domain_routing_db = bgp_select_routing_db(peer->type);
  bms = bgp_select_misc_db(peer->type);

  if (!inter_domain_routing_db || !bms) return;
 
  /* Decrement attribute reference. */
  attr->refcnt--;
  aspath = attr->aspath;
  community = attr->community;
  ecommunity = attr->ecommunity;
  lcommunity = attr->lcommunity;

  /* If reference becomes zero then free attribute object. */
  if (attr->refcnt == 0) {
    ret = (struct bgp_attr *) hash_release(inter_domain_routing_db->attrhash, attr);
    // assert (ret != NULL);
    if (!ret) Log(LOG_INFO, "INFO ( %s/%s ): bgp_attr_unintern() hash lookup failed.\n", config.name, bms->log_str);
    free(attr);
  }

  /* aspath refcount shoud be decrement. */
  if (aspath)
    aspath_unintern(peer, aspath);
  if (community)
    community_unintern(peer, community);
  if (ecommunity)
    ecommunity_unintern(peer, ecommunity);
  if (lcommunity)
    lcommunity_unintern(peer, lcommunity);
}

void *bgp_attr_hash_alloc(void *p)
{
  struct bgp_attr *val = (struct bgp_attr *) p;
  struct bgp_attr *attr;

  attr = malloc(sizeof (struct bgp_attr));
  if (!attr) {
    Log(LOG_ERR, "ERROR ( %s/core/BGP ): malloc() failed (bgp_attr_hash_alloc). Exiting ..\n", config.name); // XXX
    exit_gracefully(1);
  }
  else {
    memset(attr, 0, sizeof (struct bgp_attr));
    memcpy(attr, val, sizeof (struct bgp_attr));
    attr->refcnt = 0;
  }

  return attr;
}

void bgp_peer_cache_init(struct bgp_peer_cache_bucket *cache, u_int32_t buckets)
{
  u_int32_t idx;

  for (idx = 0; idx < buckets; idx++) {
    memset(&cache[idx], 0, sizeof(struct bgp_peer_cache_bucket));
    pthread_mutex_init(&cache[idx].mutex, NULL);
  }
}

struct bgp_peer_cache *bgp_peer_cache_insert(struct bgp_peer_cache_bucket *cache, u_int32_t bucket, struct bgp_peer *peer)
{
  struct bgp_peer_cache *cursor, *last, *new, *ret = NULL;

  pthread_mutex_lock(&peers_cache[bucket].mutex);  

  for (cursor = peers_cache[bucket].e, last = NULL; cursor; cursor = cursor->next) last = cursor;

  new = malloc(sizeof(struct bgp_peer_cache));
  if (new) {
    new->ptr = peer;
    new->next = NULL;

    if (!last) peers_cache[bucket].e = new;
    else last->next = new; 

    ret = new;
  }

  pthread_mutex_unlock(&peers_cache[bucket].mutex);  

  return ret;
}

int bgp_peer_cache_delete(struct bgp_peer_cache_bucket *cache, u_int32_t bucket, struct bgp_peer *peer)
{
  struct bgp_peer_cache *cursor, *last;
  int ret = ERR;

  pthread_mutex_lock(&peers_cache[bucket].mutex);  

  for (cursor = peers_cache[bucket].e, last = NULL; cursor; cursor = cursor->next) {
    if (cursor->ptr == peer) {
      if (!last) peers_cache[bucket].e = cursor->next;
      else last->next = cursor->next;

      free(cursor);

      ret = SUCCESS;
      break;
    }

    last = cursor;
  }

  pthread_mutex_unlock(&peers_cache[bucket].mutex);

  return ret;
}

struct bgp_peer *bgp_peer_cache_search(struct bgp_peer_cache_bucket *cache, u_int32_t bucket, struct host_addr *ha, u_int16_t port)
{
  struct bgp_peer_cache *cursor;
  struct bgp_peer *ret = NULL;

  pthread_mutex_lock(&peers_cache[bucket].mutex);

  for (cursor = peers_cache[bucket].e; cursor; cursor = cursor->next) {
    if (port) {
      if (cursor->ptr->tcp_port != port) continue;
    }

    if (!host_addr_cmp(&cursor->ptr->addr, ha)) {
      ret = cursor->ptr;
      break;
    }
  }

  pthread_mutex_unlock(&peers_cache[bucket].mutex);

  return ret;
}

int bgp_peer_init(struct bgp_peer *peer, int type)
{
  struct bgp_misc_structs *bms;
  int ret = TRUE;

  bms = bgp_select_misc_db(type);

  if (!peer || !bms) return ERR;

  memset(peer, 0, sizeof(struct bgp_peer));
  peer->type = type;
  peer->status = Idle;
  peer->buf.tot_len = BGP_BUFFER_SIZE;
  peer->buf.base = malloc(peer->buf.tot_len);
  if (!peer->buf.base) {
    Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (bgp_peer_init). Exiting ..\n", config.name, bms->log_str);
    exit_gracefully(1);
  }
  else {
    memset(peer->buf.base, 0, peer->buf.tot_len);
    ret = FALSE;
  }

  if (config.bgp_xconnect_map) {
    peer->xbuf.tot_len = BGP_BUFFER_SIZE;
    peer->xbuf.base = malloc(peer->xbuf.tot_len);
    if (!peer->xbuf.base) {
      Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (bgp_peer_init). Exiting ..\n", config.name, bms->log_str);
      exit_gracefully(1);
    }
    else {
      memset(peer->xbuf.base, 0, peer->xbuf.tot_len);
      ret = FALSE;
    }
  }

  return ret;
}

void bgp_peer_close(struct bgp_peer *peer, int type, int no_quiet, int send_notification, u_int8_t n_major, u_int8_t n_minor, char *shutdown_msg)
{
  struct bgp_misc_structs *bms;

  if (!peer) return;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  if (!config.bgp_xconnect_map) {
    if (send_notification) {
      int ret, notification_msglen = (BGP_MIN_NOTIFICATION_MSG_SIZE + BGP_NOTIFY_CEASE_SM_LEN + 1);
      char notification_msg[notification_msglen];

      ret = bgp_write_notification_msg(notification_msg, notification_msglen, n_major, n_minor, shutdown_msg);
      if (ret) send(peer->fd, notification_msg, ret, 0);
    }

    /* be quiet if we are in a signal handler and already set to exit */
    if (!no_quiet) bgp_peer_info_delete(peer);

    if (bms->msglog_file || bms->msglog_amqp_routing_key || bms->msglog_kafka_topic)
      bgp_peer_log_close(peer, bms->msglog_output, peer->type);

    if (bms->peers_cache && bms->peers_port_cache) {
      u_int32_t bucket;

      bucket = addr_hash(&peer->addr, bms->max_peers);
      bgp_peer_cache_delete(bms->peers_cache, bucket, peer);

      bucket = addr_port_hash(&peer->addr, peer->tcp_port, bms->max_peers);
      bgp_peer_cache_delete(bms->peers_port_cache, bucket, peer);
    }
  }
  else {
    if (peer->xconnect_fd && peer->xconnect_fd != ERR) close(peer->xconnect_fd);
  }

  if (peer->fd && peer->fd != ERR) close(peer->fd);

  peer->fd = 0;
  memset(&peer->xc, 0, sizeof(peer->xc));
  peer->xconnect_fd = 0;
  memset(&peer->id, 0, sizeof(peer->id));
  memset(&peer->addr, 0, sizeof(peer->addr));
  memset(&peer->addr_str, 0, sizeof(peer->addr_str));

  free(peer->buf.base);
  if (config.bgp_xconnect_map) {
    free(peer->xbuf.base);
  }

  if (bms->neighbors_file) {
    write_neighbors_file(bms->neighbors_file, peer->type);
  }

  if (bms->peers_limit_log) {
    log_notification_unset(bms->peers_limit_log);
  }
}

int bgp_peer_xconnect_init(struct bgp_peer *peer, int type)
{
  char peer_str[INET6_ADDRSTRLEN], xconnect_str[BGP_XCONNECT_STRLEN];
  struct bgp_misc_structs *bms;
  struct bgp_xconnects *bxm; 
  int ret = TRUE, idx, fd;

  assert(!peer->xconnect_fd);

  bms = bgp_select_misc_db(type);

  if (!peer || !bms) return ERR;

  bxm = bms->xconnects;

  if (bxm) {
    for (idx = 0; idx < bxm->num; idx++) {
      if (!sa_addr_cmp((struct sockaddr *) &bxm->pool[idx].src, &peer->addr) ||
	  !host_addr_mask_cmp(&bxm->pool[idx].src_addr, &bxm->pool[idx].src_mask, &peer->addr)) { 
	struct sockaddr *sa = (struct sockaddr *) &bxm->pool[idx].dst;

	memcpy(&peer->xc, &bxm->pool[idx], sizeof(struct bgp_xconnect));
	bgp_peer_xconnect_print(peer, xconnect_str, BGP_XCONNECT_STRLEN);

	fd = socket(sa->sa_family, SOCK_STREAM, 0);
	if (fd == ERR) {
	  Log(LOG_WARNING, "WARN ( %s/%s ): [%s] bgp_peer_xconnect_init(): socket() failed.\n", config.name, bms->log_str, xconnect_str);
	  memset(&peer->xc, 0, sizeof(peer->xc));
	  peer->xconnect_fd = 0;
	  return ERR;
	}

	ret = connect(fd, sa, bxm->pool[idx].dst_len);
	if (ret == ERR) {
	  Log(LOG_WARNING, "WARN ( %s/%s ): [%s] bgp_peer_xconnect_init(): connect() failed.\n", config.name, bms->log_str, xconnect_str);
	  memset(&peer->xc, 0, sizeof(peer->xc));
	  close(fd);
	  peer->xconnect_fd = 0;
	  return ERR;
	}

	peer->xconnect_fd = fd;
	break;
      }
    }

    if (!peer->xconnect_fd) {
      bgp_peer_print(peer, peer_str, INET6_ADDRSTRLEN);
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] unable to xconnect BGP peer. Missing entry in bgp_daemon_xconnect_map.\n", config.name, bgp_misc_db->log_str, peer_str);
    }
  }

  return ret;
}

void bgp_peer_print(struct bgp_peer *peer, char *buf, int len)
{
  char dumb_buf[] = "0.0.0.0";
  int ret = 0;

  if (!buf || len < INET6_ADDRSTRLEN) return;

  if (peer) {
    if (peer->id.family) {
      inet_ntop(AF_INET, &peer->id.address.ipv4, buf, len);
      ret = AF_INET;
    }
    else ret = addr_to_str(buf, &peer->addr);
  }

  if (!ret) strcpy(buf, dumb_buf);
}

void bgp_peer_xconnect_print(struct bgp_peer *peer, char *buf, int len)
{
  char src[INET6_ADDRSTRLEN + PORT_STRLEN + 1], dst[INET6_ADDRSTRLEN + PORT_STRLEN + 1];
  struct sockaddr *sa_src;
  struct sockaddr *sa_dst;

  if (peer && buf && len >= BGP_XCONNECT_STRLEN) {
    sa_src = (struct sockaddr *) &peer->xc.src;
    sa_dst = (struct sockaddr *) &peer->xc.dst;

    if (sa_src->sa_family) sa_to_str(src, sizeof(src), sa_src);
    else addr_mask_to_str(src, sizeof(src), &peer->xc.src_addr, &peer->xc.src_mask);

    sa_to_str(dst, sizeof(dst), sa_dst);

    snprintf(buf, len, "%s x %s", src, dst);
  }
}

void bgp_peer_info_delete(struct bgp_peer *peer)
{
  struct bgp_rt_structs *inter_domain_routing_db = bgp_select_routing_db(peer->type);
  struct bgp_table *table;
  afi_t afi;
  safi_t safi;

  if (!inter_domain_routing_db) return;

  for (afi = AFI_IP; afi < AFI_MAX; afi++) {
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
      table = inter_domain_routing_db->rib[afi][safi];
      bgp_table_info_delete(peer, table, afi, safi);
    }
  }
}

void bgp_table_info_delete(struct bgp_peer *peer, struct bgp_table *table, afi_t afi, safi_t safi)
{
  struct bgp_misc_structs *bms = bgp_select_misc_db(peer->type);
  struct bgp_node *node;

  node = bgp_table_top(peer, table);

  while (node) {
    u_int32_t modulo;
    u_int32_t peer_buckets;
    struct bgp_info *ri;
    struct bgp_info *ri_next;

    if (bms->route_info_modulo) modulo = bms->route_info_modulo(peer, NULL, bms->table_per_peer_buckets);
    else modulo = 0;

    for (peer_buckets = 0; peer_buckets < bms->table_per_peer_buckets; peer_buckets++) {
      for (ri = node->info[modulo + peer_buckets]; ri; ri = ri_next) {
	if (ri->peer == peer) {
	  if (bms->msglog_backend_methods) {
	    char event_type[] = "log";

	    bgp_peer_log_msg(node, ri, afi, safi, event_type, bms->msglog_output, NULL, BGP_LOG_TYPE_DELETE);
	  }

	  ri_next = ri->next; /* let's save pointer to next before free up */
          bgp_info_delete(peer, node, ri, (modulo + peer_buckets));
        }
	else ri_next = ri->next;
      }
    }

    node = bgp_route_next(peer, node);
  }
}

int bgp_attr_munge_as4path(struct bgp_peer *peer, struct bgp_attr *attr, struct aspath *as4path)
{
  struct aspath *newpath;

  /* If the BGP peer supports 32bit AS_PATH then we are done */ 
  if (peer->cap_4as) return SUCCESS;

  /* pre-requisite for AS4_PATH is AS_PATH indeed */ 
  // XXX if (as4path && !attr->aspath) return ERR;

  newpath = aspath_reconcile_as4(attr->aspath, as4path);
  aspath_unintern(peer, attr->aspath);
  attr->aspath = aspath_intern(peer, newpath);

  return SUCCESS;
}

void load_comm_patterns(char **stdcomm, char **extcomm, char **lrgcomm, char **stdcomm_to_asn, char **lrgcomm_to_asn)
{
  int idx;
  char *token;

  memset(std_comm_patterns, 0, sizeof(std_comm_patterns));
  memset(ext_comm_patterns, 0, sizeof(ext_comm_patterns));
  memset(lrg_comm_patterns, 0, sizeof(lrg_comm_patterns));
  memset(std_comm_patterns_to_asn, 0, sizeof(std_comm_patterns_to_asn));
  memset(lrg_comm_patterns_to_asn, 0, sizeof(lrg_comm_patterns_to_asn));

  if (*stdcomm) {
    idx = 0;
    while ( (token = extract_token(stdcomm, ',')) && idx < MAX_BGP_COMM_PATTERNS ) {
      std_comm_patterns[idx] = token;
      trim_spaces(std_comm_patterns[idx]);
      idx++;
    }
  }
 
  if (*extcomm) {
    idx = 0;
    while ( (token = extract_token(extcomm, ',')) && idx < MAX_BGP_COMM_PATTERNS ) {
      ext_comm_patterns[idx] = token;
      trim_spaces(ext_comm_patterns[idx]);
      idx++;
    }
  }

  if (*lrgcomm) {
    idx = 0;
    while ( (token = extract_token(lrgcomm, ',')) && idx < MAX_BGP_COMM_PATTERNS ) {
      lrg_comm_patterns[idx] = token;
      trim_spaces(lrg_comm_patterns[idx]);
      idx++;
    }
  }

  if (*stdcomm_to_asn) {
    idx = 0;
    while ( (token = extract_token(stdcomm_to_asn, ',')) && idx < MAX_BGP_COMM_PATTERNS ) {
      std_comm_patterns_to_asn[idx] = token;
      trim_spaces(std_comm_patterns_to_asn[idx]);
      idx++;
    }
  }

  if (*lrgcomm_to_asn) {
    idx = 0;
    while ( (token = extract_token(lrgcomm_to_asn, ',')) && idx < MAX_BGP_COMM_PATTERNS ) {
      lrg_comm_patterns_to_asn[idx] = token;
      trim_spaces(lrg_comm_patterns_to_asn[idx]);
      idx++;
    }
  }
}

void evaluate_comm_patterns(char *dst, char *src, char **patterns, int dstlen)
{
  char *ptr, *haystack, *delim_src, *delim_ptn;
  char local_ptr[MAX_BGP_STD_COMMS], *auxptr;
  int idx, i, j;

  if (!src || !dst || !dstlen) return;

  memset(dst, 0, dstlen);

  for (idx = 0, j = 0; patterns[idx]; idx++) {
    haystack = src;

    find_again:
    delim_ptn = strchr(patterns[idx], '.');
    if (delim_ptn) *delim_ptn = '\0';
    ptr = strstr(haystack, patterns[idx]);

    if (ptr && delim_ptn) {
      delim_src = strchr(ptr, ' ');
      if (delim_src) {
	memcpy(local_ptr, ptr, delim_src-ptr);
        local_ptr[delim_src-ptr] = '\0';
      }
      else memcpy(local_ptr, ptr, strlen(ptr)+1);
      *delim_ptn = '.';

      if (strlen(local_ptr) != strlen(patterns[idx])) ptr = NULL;
      else {
	for (auxptr = strchr(patterns[idx], '.'); auxptr; auxptr = strchr(auxptr, '.')) {
	  local_ptr[auxptr-patterns[idx]] = '.';
	  auxptr++;
	} 
	if (strncmp(patterns[idx], local_ptr, strlen(patterns[idx]))) ptr = NULL;
      }
    } 
    else if (delim_ptn) *delim_ptn = '.';

    if (ptr) {
      /* If we have already something on the stack, let's insert a space */
      if (j && j < dstlen) {
	dst[j] = ' ';
	j++;
      }

      /* We should be able to trust this string */
      for (i = 0; ptr[i] != ' ' && ptr[i] != '\0'; i++, j++) {
	if (j < dstlen) dst[j] = ptr[i];
	else break;
      } 

      haystack = &ptr[i];
    }

    /* If we don't have space anymore, let's finish it here */
    if (j >= dstlen) {
      dst[dstlen-2] = '+';
      dst[dstlen-1] = '\0';
      break;
    }

    /* Trick to find multiple occurrences */ 
    if (ptr) goto find_again;
  }
}

as_t evaluate_last_asn(struct aspath *as)
{
  if (!as) return 0;

  return as->last_as;
}

as_t evaluate_first_asn(char *src)
{
  int idx, is_space = FALSE, len = strlen(src), start, sub_as, iteration;
  char *endptr, *ptr, saved;
  as_t asn, real_first_asn;

  start = 0;
  iteration = 0;
  real_first_asn = 0;

  start_again:

  asn = 0;
  sub_as = FALSE;

  for (idx = start; idx < len && (src[idx] != ' ' && src[idx] != ')'); idx++);

  /* Mangling the AS_PATH string */
  if (src[idx] == ' ' || src[idx] == ')') {
    is_space = TRUE;  
    saved =  src[idx];
    src[idx] = '\0';
  }

  if (src[start] == '(') {
    ptr = &src[start+1];
    sub_as = TRUE;
  }
  else ptr = &src[start];

  asn = strtoul(ptr, &endptr, 10);

  /* Restoring mangled AS_PATH */
  if (is_space) {
    src[idx] = saved; 
    saved = '\0';
    is_space = FALSE;
  }

  if (config.bgp_daemon_peer_as_skip_subas /* XXX */ && sub_as) {
    while (idx < len && (src[idx] == ' ' || src[idx] == ')')) idx++;

    if (idx != len-1) { 
      start = idx;
      if (iteration == 0) real_first_asn = asn;
      iteration++;
      goto start_again;
    }
  }

  /* skip sub-as kicks-in only when traffic is delivered to a different ASN */
  if (real_first_asn && (!asn || sub_as)) asn = real_first_asn;

  return asn;
}

void evaluate_bgp_aspath_radius(char *path, int len, int radius)
{
  int count, idx;

  for (idx = 0, count = 0; idx < len; idx++) {
    if (path[idx] == ' ') count++;
    if (count == radius) {
      path[idx] = '\0';
      break;
    }
  }
}

void copy_stdcomm_to_asn(char *stdcomm, as_t *asn, int is_origin)
{
  char *delim, *delim2;
  char *p1, *p2;

  if (!stdcomm || !strlen(stdcomm) || (delim = strchr(stdcomm, ':')) == NULL) return;
  if (validate_truefalse(is_origin)) return;

  delim2 = strchr(stdcomm, ',');
  *delim = '\0';
  if (delim2) *delim2 = '\0';
  p1 = stdcomm;
  p2 = delim+1;

  if (is_origin) *asn = atoi(p2);
  else *asn = atoi(p1);
}

void copy_lrgcomm_to_asn(char *lrgcomm, as_t *asn, int is_origin)
{
  char *delim, *delim2;
  char *p1, *p2, *endptr;

  if (!lrgcomm || !strlen(lrgcomm) || (delim = strchr(lrgcomm, ':')) == NULL) return;
  if (validate_truefalse(is_origin)) return;

  delim2 = strchr(lrgcomm, ':');
  *delim = '\0';
  *delim2 = '\0';
  p1 = lrgcomm;
  p2 = delim+1;

  if (is_origin) *asn = strtoul(p2, &endptr, 10);
  else *asn = strtoul(p1, &endptr, 10);
}

/* XXX: currently only BGP is supported due to use of peers struct */
void write_neighbors_file(char *filename, int type)
{
  struct bgp_misc_structs *bms = bgp_select_misc_db(type);
  FILE *file;
  char neighbor[INET6_ADDRSTRLEN+1];
  int idx, len, ret;
  uid_t owner = -1;
  gid_t group = -1;

  if (!bms) return;

  unlink(filename);

  if (config.files_uid) owner = config.files_uid; 
  if (config.files_gid) group = config.files_gid; 

  file = fopen(filename,"w");
  if (file) {
    if ((ret = chown(filename, owner, group)) == -1)
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Unable to chown() (%s).\n", config.name, bms->log_str, filename, strerror(errno));

    if (file_lock(fileno(file))) {
      Log(LOG_ERR, "ERROR ( %s/%s ): [%s] Unable to obtain lock.\n", config.name, bms->log_str, filename);
      return;
    }
    for (idx = 0; idx < bms->max_peers; idx++) {
      if (peers[idx].fd) {
        if (peers[idx].addr.family == AF_INET) {
          inet_ntop(AF_INET, &peers[idx].addr.address.ipv4, neighbor, INET6_ADDRSTRLEN);
	  len = strlen(neighbor);
	  neighbor[len] = '\n'; len++;
	  neighbor[len] = '\0';
          fwrite(neighbor, len, 1, file);
        }
	else if (peers[idx].addr.family == AF_INET6) {
          inet_ntop(AF_INET6, &peers[idx].addr.address.ipv6, neighbor, INET6_ADDRSTRLEN);
          len = strlen(neighbor);
          neighbor[len] = '\n'; len++;
          neighbor[len] = '\0';
          fwrite(neighbor, len, 1, file);
        }
      }
    }

    file_unlock(fileno(file));
    fclose(file);
  }
  else {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] fopen() failed.\n", config.name, bms->log_str, filename);
    return;
  }
}

void bgp_config_checks(struct configuration *c)
{
  if (c->what_to_count & (COUNT_LOCAL_PREF|COUNT_MED|COUNT_PEER_SRC_AS|COUNT_PEER_DST_AS|
			  COUNT_PEER_SRC_IP|COUNT_PEER_DST_IP|COUNT_SRC_MED|COUNT_SRC_LOCAL_PREF|
			  COUNT_MPLS_VPN_RD)) {
    /* Sanitizing the aggregation method */
      if ( (c->what_to_count & COUNT_SRC_LOCAL_PREF && !c->bgp_daemon_src_local_pref_type) ||
	   (c->what_to_count & COUNT_SRC_MED && !c->bgp_daemon_src_med_type) ||
	   (c->what_to_count & COUNT_PEER_SRC_AS && !c->bgp_daemon_peer_as_src_type &&
	     (config.acct_type != ACCT_SF && config.acct_type != ACCT_NF)) ) {
      printf("ERROR: At least one of the following primitives is in use but its source type is not specified:\n");
      printf("       peer_src_as     =>  bgp_peer_src_as_type\n");
      printf("       src_local_pref  =>  bgp_src_local_pref_type\n");
      printf("       src_med         =>  bgp_src_med_type\n");
      exit_gracefully(1);
    }

    c->data_type |= PIPE_TYPE_BGP;
  }

  if ((c->what_to_count & (COUNT_STD_COMM|COUNT_EXT_COMM|COUNT_AS_PATH|COUNT_SRC_STD_COMM|
			  COUNT_SRC_EXT_COMM|COUNT_SRC_AS_PATH)) ||
      (c->what_to_count_2 & (COUNT_LRG_COMM|COUNT_SRC_LRG_COMM))) {
    /* Sanitizing the aggregation method */
    if ( (c->what_to_count & COUNT_SRC_AS_PATH && !c->bgp_daemon_src_as_path_type) ||
         (c->what_to_count & COUNT_SRC_STD_COMM && !c->bgp_daemon_src_std_comm_type) ||
	 (c->what_to_count & COUNT_SRC_EXT_COMM && !c->bgp_daemon_src_ext_comm_type) ||
	 (c->what_to_count_2 & COUNT_SRC_LRG_COMM && !c->bgp_daemon_src_lrg_comm_type) ) {
      printf("ERROR: At least one of the following primitives is in use but its source type is not specified:\n");
      printf("       src_as_path     =>  bgp_src_as_path_type\n");
      printf("       src_std_comm    =>  bgp_src_std_comm_type\n");
      printf("       src_ext_comm    =>  bgp_src_ext_comm_type\n");
      printf("       src_lrg_comm    =>  bgp_src_lrg_comm_type\n");
      exit_gracefully(1);
    }

    if (c->type_id == PLUGIN_ID_MEMORY) c->data_type |= PIPE_TYPE_LBGP;
    else c->data_type |= PIPE_TYPE_VLEN;
  }
}

void bgp_md5_file_init(struct bgp_md5_table *t)
{
  if (t) memset(t, 0, sizeof(struct bgp_md5_table));
}

void bgp_md5_file_load(char *filename, struct bgp_md5_table *t)
{
  FILE *file;
  char buf[SRVBUFLEN], *ptr;
  int index = 0;

  if (filename && t) {
    Log(LOG_INFO, "INFO ( %s/core/BGP ): [%s] (re)loading map.\n", config.name, filename);

    if ((file = fopen(filename, "r")) == NULL) {
      Log(LOG_ERR, "ERROR ( %s/core/BGP ): [%s] file not found.\n", config.name, filename);
      exit_gracefully(1);
    }

    while (!feof(file)) {
      if (index >= BGP_MD5_MAP_ENTRIES) {
	Log(LOG_WARNING, "WARN ( %s/core/BGP ): [%s] loaded the first %u entries.\n", config.name, filename, BGP_MD5_MAP_ENTRIES);
        break;
      }
      memset(buf, 0, SRVBUFLEN);
      if (fgets(buf, SRVBUFLEN, file)) {
        if (!sanitize_buf(buf)) {
          char *token;
          int tk_idx = 0, ret = 0, len = 0;

          ptr = buf;
	  memset(&t->table[index], 0, sizeof(t->table[index]));
          while ( (token = extract_token(&ptr, ',')) && tk_idx < 2 ) {
            if (tk_idx == 0) ret = str_to_addr(token, &t->table[index].addr);
            else if (tk_idx == 1) {
              strlcpy(t->table[index].key, token, TCP_MD5SIG_MAXKEYLEN);
              len = strlen(t->table[index].key);
            }
            tk_idx++;
          }

          if (ret > 0 && len > 0) index++;
          else Log(LOG_WARNING, "WARN ( %s/core/BGP ): [%s] line '%s' ignored.\n", config.name, filename, buf);
        }
      }
    }
    t->num = index;

    /* Set to -1 to distinguish between no map and empty map conditions */
    if (!t->num) t->num = -1;

    Log(LOG_INFO, "INFO ( %s/core/BGP ): [%s] map successfully (re)loaded.\n", config.name, filename);
    fclose(file);
  }
}

void bgp_md5_file_unload(struct bgp_md5_table *t)
{
  int index = 0;

  if (!t) return;

  while (index < t->num) {
    memset(t->table[index].key, 0, TCP_MD5SIG_MAXKEYLEN);
    index++;
  }
}

void bgp_md5_file_process(int sock, struct bgp_md5_table *bgp_md5)
{
  char peer_str[INET6_ADDRSTRLEN + PORT_STRLEN + 1];
  struct pm_tcp_md5sig md5sig;
  struct sockaddr_storage ss_md5sig, ss_server;
  struct sockaddr *sa_md5sig = (struct sockaddr *)&ss_md5sig, *sa_server = (struct sockaddr *)&ss_server;
  int rc, keylen, idx = 0, ss_md5sig_len;
  socklen_t ss_server_len;

  if (!bgp_md5) return;

  while (idx < bgp_md5->num) {
    memset(&md5sig, 0, sizeof(md5sig));
    memset(&ss_md5sig, 0, sizeof(ss_md5sig));

    ss_md5sig_len = addr_to_sa((struct sockaddr *)&ss_md5sig, &bgp_md5->table[idx].addr, 0);

    ss_server_len = sizeof(ss_server);
    getsockname(sock, (struct sockaddr *)&ss_server, &ss_server_len);

    if (sa_md5sig->sa_family == AF_INET6 && sa_server->sa_family == AF_INET) {
      ipv4_mapped_to_ipv4(&ss_md5sig);
      ss_md5sig_len = sizeof(struct sockaddr_in);
    }
    else if (sa_md5sig->sa_family == AF_INET && sa_server->sa_family == AF_INET6) {
      ipv4_to_ipv4_mapped(&ss_md5sig);
      ss_md5sig_len = sizeof(struct sockaddr_in6);
    }

    memcpy(&md5sig.tcpm_addr, &ss_md5sig, ss_md5sig_len);
    keylen = strlen(bgp_md5->table[idx].key);
    if (keylen) {
      md5sig.tcpm_keylen = keylen;
      memcpy(md5sig.tcpm_key, &bgp_md5->table[idx].key, keylen);
    }

    sa_to_str(peer_str, sizeof(peer_str), sa_md5sig);

    rc = setsockopt(sock, IPPROTO_TCP, TCP_MD5SIG, &md5sig, (socklen_t) sizeof(md5sig));
    if (rc < 0) {
      Log(LOG_WARNING, "WARN ( %s/core/BGP ): setsockopt() failed for TCP_MD5SIG peer=%s (errno: %d)\n", config.name, peer_str, errno);
    }
    else { 
      Log(LOG_DEBUG, "DEBUG ( %s/core/BGP ): setsockopt() set TCP_MD5SIG peer=%s\n", config.name, peer_str);
    }

    idx++;
  }
}

void bgp_batch_init(struct bgp_peer_batch *bp_batch, int num, int interval)
{
  if (bp_batch) {
    memset(bp_batch, 0, sizeof(struct bgp_peer_batch));

    bp_batch->num = num;
    bp_batch->interval = interval;
  }
}

void bgp_batch_reset(struct bgp_peer_batch *bp_batch, time_t now)
{
  if (bp_batch) {
    bp_batch->num_current = bp_batch->num;
    bp_batch->base_stamp = now;
  }
}

int bgp_batch_is_admitted(struct bgp_peer_batch *bp_batch, time_t now)
{
  if (bp_batch) {
    /* bgp_batch_is_not_empty() maybe replaced by a linear
       distribution of the peers over the time interval */
    if (bgp_batch_is_not_empty(bp_batch) || bgp_batch_is_expired(bp_batch, now)) return TRUE;
    else return FALSE;
  }
  else return ERR;
}

int bgp_batch_is_enabled(struct bgp_peer_batch *bp_batch)
{
  if (bp_batch) {
    if (bp_batch->num) return TRUE;
    else return FALSE;
  }
  else return ERR;
}

int bgp_batch_is_expired(struct bgp_peer_batch *bp_batch, time_t now)
{
  if (bp_batch) {
    if (now > (bp_batch->base_stamp + bp_batch->interval)) return TRUE;
    else return FALSE;
  }
  else return ERR;
}

int bgp_batch_is_not_empty(struct bgp_peer_batch *bp_batch)
{
  if (bp_batch) {
    if (bp_batch->num_current) return TRUE;
    else return FALSE;
  }
  else return ERR;
}

void bgp_batch_increase_counter(struct bgp_peer_batch *bp_batch)
{
  if (bp_batch) bp_batch->num_current++;
}

void bgp_batch_decrease_counter(struct bgp_peer_batch *bp_batch)
{
  if (bp_batch) bp_batch->num_current--;
}

void bgp_batch_rollback(struct bgp_peer_batch *bp_batch)
{
  if (bp_batch && bgp_batch_is_enabled(bp_batch)) {
    bgp_batch_increase_counter(bp_batch);
    if (bp_batch->num_current == bp_batch->num)
      bgp_batch_init(bp_batch, bp_batch->num, bp_batch->interval);
  }
}

struct bgp_rt_structs *bgp_select_routing_db(int peer_type)
{
  if (peer_type < FUNC_TYPE_MAX) 
    return &inter_domain_routing_dbs[peer_type];

  return NULL;
}

struct bgp_misc_structs *bgp_select_misc_db(int peer_type)
{
  if (peer_type < FUNC_TYPE_MAX)
    return &inter_domain_misc_dbs[peer_type];

  return NULL;
}

void bgp_link_misc_structs(struct bgp_misc_structs *bms)
{
#if defined WITH_RABBITMQ
  bms->msglog_amqp_host = &bgp_daemon_msglog_amqp_host;
#endif
#if defined WITH_KAFKA
  bms->msglog_kafka_host = &bgp_daemon_msglog_kafka_host;
#endif
  bms->max_peers = config.bgp_daemon_max_peers;
  bms->peers = peers;
  bms->peers_cache = peers_cache;
  bms->peers_port_cache = peers_port_cache;
  bms->peers_limit_log = &log_notifications.bgp_peers_limit;
  bms->xconnects = &bgp_xcs_map;
  bms->neighbors_file = config.bgp_daemon_neighbors_file; 
  bms->dump_file = config.bgp_table_dump_file; 
  bms->dump_amqp_routing_key = config.bgp_table_dump_amqp_routing_key; 
  bms->dump_amqp_routing_key_rr = config.bgp_table_dump_amqp_routing_key_rr;
  bms->dump_kafka_topic = config.bgp_table_dump_kafka_topic;
  bms->dump_kafka_topic_rr = config.bgp_table_dump_kafka_topic_rr;
  bms->dump_kafka_avro_schema_registry = config.bgp_table_dump_kafka_avro_schema_registry;
  bms->msglog_file = config.bgp_daemon_msglog_file;
  bms->msglog_output = config.bgp_daemon_msglog_output;
  bms->msglog_amqp_routing_key = config.bgp_daemon_msglog_amqp_routing_key;
  bms->msglog_amqp_routing_key_rr = config.bgp_daemon_msglog_amqp_routing_key_rr;
  bms->msglog_kafka_topic = config.bgp_daemon_msglog_kafka_topic;
  bms->msglog_kafka_topic_rr = config.bgp_daemon_msglog_kafka_topic_rr;
  bms->msglog_kafka_avro_schema_registry = config.bgp_daemon_msglog_kafka_avro_schema_registry;
  bms->peer_str = malloc(strlen("peer_ip_src") + 1);
  strcpy(bms->peer_str, "peer_ip_src");
  bms->peer_port_str = malloc(strlen("peer_tcp_port") + 1);
  strcpy(bms->peer_port_str, "peer_tcp_port");
  bms->bgp_peer_log_msg_extras = NULL;
  bms->bgp_peer_logdump_initclose_extras = NULL;

  bms->table_peer_buckets = config.bgp_table_peer_buckets;
  bms->table_per_peer_buckets = config.bgp_table_per_peer_buckets;
  bms->table_attr_hash_buckets = config.bgp_table_attr_hash_buckets;
  bms->table_per_peer_hash = config.bgp_table_per_peer_hash;
  bms->route_info_modulo = bgp_route_info_modulo;
  bms->bgp_lookup_find_peer = bgp_lookup_find_bgp_peer;
  bms->bgp_lookup_node_match_cmp = bgp_lookup_node_match_cmp_bgp;

  bms->bgp_msg_open_router_id_check = bgp_router_id_check; 

  if (!bms->is_thread && !bms->dump_backend_methods && !bms->has_lglass && !bms->has_blackhole) {
    bms->skip_rib = TRUE;
  }
}

void bgp_blackhole_link_misc_structs(struct bgp_misc_structs *m_data)
{
  m_data->table_peer_buckets = 1; /* saving on DEFAULT_BGP_INFO_HASH for now */
  m_data->table_per_peer_buckets = DEFAULT_BGP_INFO_PER_PEER_HASH;
  m_data->table_attr_hash_buckets = HASHTABSIZE;
  m_data->table_per_peer_hash = BGP_ASPATH_HASH_PATHID;
  m_data->route_info_modulo = NULL;
  m_data->bgp_lookup_node_match_cmp = NULL;
}

int bgp_peer_cmp(const void *a, const void *b)
{
  return host_addr_cmp(&((struct bgp_peer *)a)->addr, &((struct bgp_peer *)b)->addr);
}

int bgp_peer_host_addr_cmp(const void *a, const void *b)
{
  return host_addr_cmp((struct host_addr *)a, &((struct bgp_peer *)b)->addr);
}

int bgp_peer_sa_addr_cmp(const void *a, const void *b)
{
  return sa_addr_cmp((struct sockaddr *) a, &((struct bgp_peer *)b)->addr);
}

void bgp_peer_free(void *a)
{
}

int bgp_peers_bintree_walk_print(const void *nodep, const pm_VISIT which, const int depth, void *extra)
{
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;
  char peer_str[INET6_ADDRSTRLEN];

  peer = (*(struct bgp_peer **) nodep);
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return FALSE;

  if (!peer) Log(LOG_INFO, "INFO ( %s/%s ): bgp_peers_bintree_walk_print(): null\n", config.name, bms->log_str);
  else {
    addr_to_str(peer_str, &peer->addr);
    Log(LOG_INFO, "INFO ( %s/%s ): bgp_peers_bintree_walk_print(): %s\n", config.name, bms->log_str, peer_str);
  }

  return TRUE;
}

int bgp_peers_bintree_walk_delete(const void *nodep, const pm_VISIT which, const int depth, void *extra)
{
  struct bgp_misc_structs *bms;
  char peer_str[] = "peer_ip", *saved_peer_str;
  struct bgp_peer *peer;

  peer = (*(struct bgp_peer **) nodep);

  if (!peer) return FALSE;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) return FALSE;

  saved_peer_str = bms->peer_str;
  bms->peer_str = peer_str;
  bgp_peer_info_delete(peer);
  bms->peer_str = saved_peer_str;

  // XXX: count tree elements to index and free() later

  return TRUE;
}

int bgp_router_id_check(struct bgp_msg_data *bmd)
{
  struct bgp_peer *peer = bmd->peer;
  struct bgp_misc_structs *bms;
  struct bgp_peer *peers_check;
  int peers_check_idx = 0;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) return ERR;

  peers_check = bms->peers;

  for (; peers_check_idx < bms->max_peers; peers_check_idx++) {
    if (peers_check_idx != peer->idx && !memcmp(&peers_check[peers_check_idx].id, &peer->id, sizeof(peers_check[peers_check_idx].id))) {
      char bgp_peer_str[INET6_ADDRSTRLEN];

      bgp_peer_print(&peers_check[peers_check_idx], bgp_peer_str, INET6_ADDRSTRLEN);
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Refusing new connection from existing Router-ID.\n", config.name, bms->log_str, bgp_peer_str);

      return ERR;
    }
  }

  return FALSE;
}

/*
  utility function when an ASN is prepended by 'AS', 'AS ', etc. strings
  that need to be stripped.
*/
int bgp_str2asn(char *asn_str, as_t *asn)
{
  char *endptr, *asn_ptr = asn_str;
  int len, cnt;

  if (!asn_str || !asn) return ERR;

  len = strlen(asn_str);

  for (cnt = 0; !isdigit(asn_str[cnt]) && (cnt < len); cnt++);

  asn_ptr = &asn_str[cnt];

  (*asn) = strtoul(asn_ptr, &endptr, 10);
  if (endptr == asn_ptr || (*endptr) != '\0') return ERR;
  if (errno) {
    errno = FALSE;
    return ERR;
  }

  return SUCCESS;
}

const char *bgp_origin_print(u_int8_t origin)
{
  if (origin <= BGP_ORIGIN_MAX) return bgp_origin[origin];
  else return bgp_origin[BGP_ORIGIN_UNKNOWN];
}

u_int8_t bgp_str2origin(char *origin_str)
{
  if (!strcmp(origin_str, "i")) return BGP_ORIGIN_IGP;
  else if (!strcmp(origin_str, "e")) return BGP_ORIGIN_EGP;
  else if (!strcmp(origin_str, "u")) return BGP_ORIGIN_INCOMPLETE;

  return BGP_ORIGIN_UNKNOWN;
}

u_int16_t bgp_get_packet_len(char *pkt)
{
  struct bgp_header *bhdr = (struct bgp_header *) pkt;
  u_int16_t blen = 0;

  if (bgp_marker_check(bhdr, BGP_MARKER_SIZE) != ERR) {
    blen = ntohs(bhdr->bgpo_len);
  }

  return blen;
}

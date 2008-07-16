/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2008 by Paolo Lucente
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

#define __LOG_TEMPLATES_C

#include "pmacct.h"
#include "pmacct-data.h"
#include "sql_common.h"

struct template_entry *build_template(struct template_header *th)
{
  struct template_entry *ptr, *base;
  struct db_cache dummy;
  u_char *te;
  u_int16_t tot_size = 0;

  th->num = 17;

  te = malloc(th->num*sizeof(struct template_entry));  
  memset(te, 0, th->num*sizeof(struct template_entry));
  base = (struct template_entry *) te;
  ptr = base;

#if defined (HAVE_L2)
  ptr->tag = COUNT_DST_MAC;
  ptr->size = sizeof(dummy.primitives.eth_dhost);
  tot_size += ptr->size;
  ptr++;

  ptr->tag = COUNT_SRC_MAC;
  ptr->size = sizeof(dummy.primitives.eth_shost);
  tot_size += ptr->size;
  ptr++;

  ptr->tag = COUNT_VLAN;
  ptr->size = sizeof(dummy.primitives.vlan_id);
  tot_size += ptr->size;
  ptr++;
#else 
  th->num--; th->num--; /* we replace 3 entries with just 1 */
  ptr->tag = LT_NO_L2;
  ptr->size = 14; 
  tot_size += ptr->size;
  ptr++;
#endif

  ptr->tag = COUNT_SRC_HOST;
  ptr->size = sizeof(dummy.primitives.src_ip);
  tot_size += ptr->size;
  ptr++;

  ptr->tag = COUNT_DST_HOST;
  ptr->size = sizeof(dummy.primitives.dst_ip);
  tot_size += ptr->size;
  ptr++;

  ptr->tag = COUNT_SRC_AS;
  ptr->size = sizeof(dummy.primitives.src_as);
  tot_size += ptr->size;
  ptr++;

  ptr->tag = COUNT_DST_AS;
  ptr->size = sizeof(dummy.primitives.dst_as);
  tot_size += ptr->size;
  ptr++;

  ptr->tag = COUNT_SRC_PORT;
  ptr->size = sizeof(dummy.primitives.src_port);
  tot_size += ptr->size;
  ptr++;

  ptr->tag = COUNT_DST_PORT;
  ptr->size = sizeof(dummy.primitives.dst_port);
  tot_size += ptr->size;
  ptr++;

  ptr->tag = COUNT_IP_TOS; 
  ptr->size = sizeof(dummy.primitives.tos);
  tot_size += ptr->size;
  ptr++;

  ptr->tag = COUNT_IP_PROTO;
  ptr->size = sizeof(dummy.primitives.proto);
  tot_size += ptr->size;
  ptr++;

  ptr->tag = COUNT_ID;
  ptr->size = sizeof(dummy.primitives.id);
  tot_size += ptr->size;
  ptr++;

  ptr->tag = COUNT_CLASS;
  ptr->size = sizeof(dummy.primitives.class);
  tot_size += ptr->size;
  ptr++;

  ptr->tag = LT_BYTES;
  ptr->size = sizeof(dummy.bytes_counter);
  tot_size += ptr->size;
  ptr++;

  ptr->tag = LT_PACKETS;
  ptr->size = sizeof(dummy.packet_counter);
  tot_size += ptr->size;
  ptr++;

  ptr->tag = LT_FLOWS;
  ptr->size = sizeof(dummy.flows_counter);
  tot_size += ptr->size;
  ptr++;

  ptr->tag = TIMESTAMP;
  ptr->size = sizeof(dummy.basetime);
  tot_size += ptr->size;

  th->magic = htonl(TH_MAGIC);
  th->num = htons(th->num);
  th->sz = htons(tot_size);

  return base;
}

void set_template_funcs(struct template_header *th, struct template_entry *head)
{
  struct template_entry *te;
  int cnt;

  memset(&template_funcs, 0, sizeof(template_funcs));

  for (te = head, cnt = 0; cnt < ntohs(th->num); cnt++, te++) {
    switch (te->tag) {
#if defined (HAVE_L2)
    case COUNT_SRC_MAC:
      template_funcs[cnt] = TPL_push_src_mac;
      break;
    case COUNT_DST_MAC:
      template_funcs[cnt] = TPL_push_dst_mac; 
      break;
    case COUNT_VLAN:
      template_funcs[cnt] = TPL_push_vlan;
      break;
#endif
    case COUNT_SRC_HOST:
      template_funcs[cnt] = TPL_push_src_ip;
      break;
    case COUNT_DST_HOST:
      template_funcs[cnt] = TPL_push_dst_ip;
      break;
    case COUNT_SRC_AS:
      template_funcs[cnt] = TPL_push_src_as;
      break;
    case COUNT_DST_AS:
      template_funcs[cnt] = TPL_push_dst_as;
      break;
    case COUNT_SRC_PORT:
      template_funcs[cnt] = TPL_push_src_port;
      break;
    case COUNT_DST_PORT:
      template_funcs[cnt] = TPL_push_dst_port;
      break;
    case COUNT_IP_TOS: 
      template_funcs[cnt] = TPL_push_tos;
      break;
    case COUNT_IP_PROTO:
      template_funcs[cnt] = TPL_push_proto;
      break;
    case COUNT_ID:
      template_funcs[cnt] = TPL_push_id;
      break;
    case COUNT_CLASS:
      template_funcs[cnt] = TPL_push_class;
      break;
    case LT_BYTES:
      template_funcs[cnt] = TPL_push_bytes_counter;
      break;
    case LT_PACKETS:
      template_funcs[cnt] = TPL_push_packet_counter;
      break;
    case LT_FLOWS:
      template_funcs[cnt] = TPL_push_flows_counter;
      break;
    case TIMESTAMP:
      template_funcs[cnt] = TPL_push_timestamp;
      break;
    case LT_NO_L2:
      template_funcs[cnt] = TPL_push_nol2;
      break;
    default:
      template_funcs[cnt] = NULL;
      break;
    }
  }
}

u_int16_t TPL_push(u_char *dst, const struct db_cache *src)
{
  u_char *ptr = dst;
  int cnt = 0;

  while (template_funcs[cnt]) {
    (*template_funcs[cnt])(&ptr, src);
    cnt++;
  }

  return ptr-dst;
}

#if defined (HAVE_L2)
void TPL_push_src_mac(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->primitives.eth_shost);

  memcpy(*dst, &src->primitives.eth_shost, size); 
  *dst += size;
}	

void TPL_push_dst_mac(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->primitives.eth_dhost);

  memcpy(*dst, &src->primitives.eth_dhost, size);
  *dst += size;
}

void TPL_push_vlan(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->primitives.vlan_id);

  memcpy(*dst, &src->primitives.vlan_id, size);
  *dst += size;
}
#endif

void TPL_push_nol2(u_char **dst, const struct db_cache *src)
{
  int size = 14; 

  memset(*dst, 0, size);
  *dst += size;
}

void TPL_push_src_ip(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->primitives.src_ip);

  memcpy(*dst, &src->primitives.src_ip, size);
  *dst += size;
}

void TPL_push_dst_ip(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->primitives.dst_ip);

  memcpy(*dst, &src->primitives.dst_ip, size);
  *dst += size;
}

void TPL_push_src_as(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->primitives.src_as);

  memcpy(*dst, &src->primitives.src_as, size);
  *dst += size;
}

void TPL_push_dst_as(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->primitives.dst_as);

  memcpy(*dst, &src->primitives.dst_as, size);
  *dst += size;
}

void TPL_push_src_port(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->primitives.src_port);

  memcpy(*dst, &src->primitives.src_port, size);
  *dst += size;
}

void TPL_push_dst_port(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->primitives.dst_port);

  memcpy(*dst, &src->primitives.dst_port, size);
  *dst += size;
}

void TPL_push_tos(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->primitives.tos);

  memcpy(*dst, &src->primitives.tos, size);
  *dst += size;
}

void TPL_push_proto(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->primitives.proto);

  memcpy(*dst, &src->primitives.proto, size);
  *dst += size;
}

void TPL_push_id(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->primitives.id);

  memcpy(*dst, &src->primitives.id, size);
  *dst += size;
}

void TPL_push_class(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->primitives.class);

  memset(*dst, 0, size);
  *dst += size;
}

void TPL_push_bytes_counter(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->bytes_counter);

  memcpy(*dst, &src->bytes_counter, size);
  *dst += size;
}

void TPL_push_packet_counter(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->packet_counter);

  memcpy(*dst, &src->packet_counter, size);
  *dst += size;
}

void TPL_push_flows_counter(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->flows_counter);

  memcpy(*dst, &src->flows_counter, size);
  *dst += size;
}

void TPL_push_timestamp(u_char **dst, const struct db_cache *src)
{
  int size = sizeof(src->basetime);

  memcpy(*dst, &src->basetime, size);
  *dst += size;
}

void TPL_pop(u_char *src, struct db_cache *dst, struct template_header *th, u_char *te)
{
  struct template_entry *teptr = (struct template_entry *)te;
  u_char *ptr = src;
  int cnt = 0, tot_sz = 0, sz = 0;
  u_int32_t t32;
  u_int64_t t64;

  for (; cnt < th->num; cnt++, ptr += sz, tot_sz += sz, teptr++) { 
    if (tot_sz > th->sz) {
      printf("ERROR: malformed template entry. Size mismatch. Exiting.\n");
      exit(1); 
    }
    sz = teptr->size;
    
    switch (teptr->tag) {
#if defined (HAVE_L2)
    case COUNT_SRC_MAC:
      memcpy(&dst->primitives.eth_shost, ptr, sz);
      break;
    case COUNT_DST_MAC:
      memcpy(&dst->primitives.eth_dhost, ptr, sz);
      break;
    case COUNT_VLAN:
      memcpy(&dst->primitives.vlan_id, ptr, sz);
      break;
#endif
    case COUNT_SRC_HOST:
      if (sz == 4) {
	/* legacy IP addresses */
	memcpy(&dst->primitives.src_ip.address.ipv4, ptr, sz);
	dst->primitives.src_ip.family = AF_INET;
	break;
      } 
      memcpy(&dst->primitives.src_ip, ptr, sz);
      break;
    case COUNT_DST_HOST:
      if (sz == 4) {
        /* legacy IP addresses */
	memcpy(&dst->primitives.dst_ip.address.ipv4, ptr, sz);
	dst->primitives.dst_ip.family = AF_INET;
	break;
      }
      memcpy(&dst->primitives.dst_ip, ptr, sz);
      break;
    case COUNT_SRC_AS:
      memcpy(&dst->primitives.src_as, ptr, sz);
      break;
    case COUNT_DST_AS:
      memcpy(&dst->primitives.dst_as, ptr, sz);
      break;
    case COUNT_SRC_PORT:
      memcpy(&dst->primitives.src_port, ptr, sz);
      break;
    case COUNT_DST_PORT:
      memcpy(&dst->primitives.dst_port, ptr, sz);
      break;
    case COUNT_IP_TOS:
      memcpy(&dst->primitives.tos, ptr, sz);
      break;
    case COUNT_IP_PROTO:
      memcpy(&dst->primitives.proto, ptr, sz);
      break;
    case COUNT_ID:
      memcpy(&dst->primitives.id, ptr, sz);
      break;
    case COUNT_CLASS:
      memcpy(&dst->primitives.class, ptr, sz);
      break;
    case LT_BYTES:
      if (sz == 4) {
	memcpy(&t32, ptr, sz);
	dst->bytes_counter = t32;
      }
      else if (sz == 8) {
	memcpy(&t64, ptr, sz);
	dst->bytes_counter = t64;
      }
      break;
    case LT_PACKETS:
      if (sz == 4) {
        memcpy(&t32, ptr, sz);
        dst->packet_counter = t32;
      }
      else if (sz == 8) {
        memcpy(&t64, ptr, sz);
        dst->packet_counter = t64;
      }
      break;
    case LT_FLOWS:
      if (sz == 4) {
        memcpy(&t32, ptr, sz);
        dst->flows_counter = t32;
      }
      else if (sz == 8) {
        memcpy(&t64, ptr, sz);
        dst->flows_counter = t64;
      }
      break;
    case TIMESTAMP:
      memcpy(&dst->basetime, ptr, sz);
      break;
    case LT_NO_L2:
      break;
    default:
      printf("ERROR: template entry not supported: '%d'\n", teptr->tag);
      exit(1); 
    }
  }
}

void TPL_check_sizes(struct template_header *th, struct db_cache *elem, u_char *te)
{
  struct template_entry *teptr = (struct template_entry *) te;
  int cnt = 0;

  for (; cnt < th->num; cnt++, teptr++) {
    switch (teptr->tag) {
#if defined (HAVE_L2)
    case COUNT_SRC_MAC:
      if (teptr->size > sizeof(elem->primitives.eth_shost)) goto exit_lane;
      break;
    case COUNT_DST_MAC:
      if (teptr->size > sizeof(elem->primitives.eth_dhost)) goto exit_lane;
      break;
    case COUNT_VLAN:
      if (teptr->size > sizeof(elem->primitives.vlan_id)) goto exit_lane;
      break;
#endif
    case COUNT_SRC_HOST:
      if (teptr->size > sizeof(elem->primitives.src_ip)) goto exit_lane;
      break;
    case COUNT_DST_HOST:
      if (teptr->size > sizeof(elem->primitives.dst_ip)) goto exit_lane;
      break;
    case COUNT_SRC_AS:
      if (teptr->size > sizeof(elem->primitives.src_as)) goto exit_lane;
      break;
    case COUNT_DST_AS:
      if (teptr->size > sizeof(elem->primitives.dst_as)) goto exit_lane;
      break;
    case COUNT_SRC_PORT:
      if (teptr->size > sizeof(elem->primitives.src_port)) goto exit_lane;
      break;
    case COUNT_DST_PORT:
      if (teptr->size > sizeof(elem->primitives.dst_port)) goto exit_lane;
      break;
    case COUNT_IP_TOS:
      if (teptr->size > sizeof(elem->primitives.tos)) goto exit_lane;
      break;
    case COUNT_IP_PROTO:
      if (teptr->size > sizeof(elem->primitives.proto)) goto exit_lane;
      break;
    case COUNT_ID:
      if (teptr->size > sizeof(elem->primitives.id)) goto exit_lane;
      break;
    case COUNT_CLASS:
      if (teptr->size > sizeof(elem->primitives.class)) goto exit_lane;
      break;
    case LT_BYTES:
      if (teptr->size != 4 && teptr->size != 8) goto exit_lane;
      break;
    case LT_PACKETS:
      if (teptr->size != 4 && teptr->size != 8) goto exit_lane;
      break;
    case LT_FLOWS:
      if (teptr->size != 4 && teptr->size != 8) goto exit_lane;
      break;
    case TIMESTAMP:
      if (teptr->size > sizeof(elem->basetime)) goto exit_lane;
      break;
    case LT_NO_L2:
      break;
    default:
      printf("ERROR: template entry not supported: '%d'\n", teptr->tag);
      exit(1);
    exit_lane:
      printf("ERROR: template entry '%d' is too big. Exiting.\n", teptr->tag);
      exit(1);
    }
  }
}

/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2011 by Paolo Lucente
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
#define __NFV9_TEMPLATE_C

/* includes */
#include "pmacct.h"
#include "nfacctd.h"
#include "pmacct-data.h"

void handle_template_v9(struct template_hdr_v9 *hdr, struct packet_ptrs *pptrs, u_int16_t tpl_type, u_int32_t sid)
{
  struct template_cache_entry *tpl;

  /* 0 NetFlow v9, 2 IPFIX */
  if (tpl_type == 0 || tpl_type == 2) {
    if (tpl = find_template_v9(hdr->template_id, pptrs, tpl_type, sid))
      refresh_template_v9(hdr, tpl, pptrs, tpl_type, sid);
    else insert_template_v9(hdr, pptrs, tpl_type, sid);
  }
  /* 1 NetFlow v9, 3 IPFIX */
  else if (tpl_type == 1 || tpl_type == 3) {
    if (tpl = find_template_v9(hdr->template_id, pptrs, tpl_type, sid))
      refresh_opt_template_v9(hdr, tpl, pptrs, tpl_type, sid);
    else insert_opt_template_v9(hdr, pptrs, tpl_type, sid);
  }
}

struct template_cache_entry *find_template_v9(u_int16_t id, struct packet_ptrs *pptrs, u_int16_t tpl_type, u_int32_t sid)
{
  struct template_cache_entry *ptr;
  u_int16_t modulo = (ntohs(id)%tpl_cache.num);

  ptr = tpl_cache.c[modulo];

  while (ptr) {
    if ((ptr->template_id == id) && (!sa_addr_cmp((struct sockaddr *)pptrs->f_agent, &ptr->agent)) &&
	(ptr->source_id == sid))
      return ptr;
    else ptr = ptr->next;
  }

  return NULL;
}

struct template_cache_entry *insert_template_v9(struct template_hdr_v9 *hdr, struct packet_ptrs *pptrs, u_int16_t tpl_type, u_int32_t sid)
{
  struct template_cache_entry *ptr, *prevptr = NULL;
  struct template_field_v9 *field;
  u_int16_t modulo = (ntohs(hdr->template_id)%tpl_cache.num), count;
  u_int16_t num = ntohs(hdr->num), type, port;
  u_char *tpl;

  ptr = tpl_cache.c[modulo];

  while (ptr) {
    prevptr = ptr;
    ptr = ptr->next;
  }

  ptr = malloc(sizeof(struct template_cache_entry));
  if (!ptr) {
    Log(LOG_ERR, "ERROR ( default/core ): Unable to allocate enough memory for a new Template Cache Entry.\n");
    return NULL;
  }

  memset(ptr, 0, sizeof(struct template_cache_entry));
  sa_to_addr((struct sockaddr *)pptrs->f_agent, &ptr->agent, &port);
  ptr->source_id = sid;
  ptr->template_id = hdr->template_id;
  ptr->template_type = 0;
  ptr->num = num;

  log_template_v9_header(ptr, pptrs, tpl_type, sid);

  count = num;
  tpl = (u_char *) hdr;
  tpl += NfTplHdrV9Sz;
  field = (struct template_field_v9 *)tpl;
  while (count) {
    type = ntohs(field->type);
    log_template_v9_field(type, ptr->len, ntohs(field->len));

    /* Cisco ASA hack */
    switch (type) {
    case NF9_ASA_XLATE_IPV4_SRC_ADDR:
      type = NF9_XLATE_IPV4_SRC_ADDR;
      break;
    case NF9_ASA_XLATE_IPV4_DST_ADDR:
      type = NF9_XLATE_IPV4_DST_ADDR;
      break;
    case NF9_ASA_XLATE_L4_SRC_PORT:
      type = NF9_XLATE_L4_SRC_PORT;
      break;
    case NF9_ASA_XLATE_L4_DST_PORT:
      type = NF9_XLATE_L4_DST_PORT;
      break;
    default:
      break;
    }

    if (type < NF9_MAX_DEFINED_FIELD) {
      ptr->tpl[type].off = ptr->len; 
      ptr->tpl[type].len = ntohs(field->len);
      ptr->len += ptr->tpl[type].len;
    }
    else ptr->len += ntohs(field->len);

    count--;
    field++;
  }

  if (prevptr) prevptr->next = ptr;
  else tpl_cache.c[modulo] = ptr;

  log_template_v9_footer(ptr->len);

  return ptr;
}

void refresh_template_v9(struct template_hdr_v9 *hdr, struct template_cache_entry *tpl, struct packet_ptrs *pptrs, u_int16_t tpl_type, u_int32_t sid)
{
  struct template_cache_entry *next;
  struct template_field_v9 *field;
  u_int16_t count, num = ntohs(hdr->num), type, port;
  u_char *ptr;

  next = tpl->next;
  memset(tpl, 0, sizeof(struct template_cache_entry));
  sa_to_addr((struct sockaddr *)pptrs->f_agent, &tpl->agent, &port);
  tpl->source_id = sid;
  tpl->template_id = hdr->template_id;
  tpl->template_type = 0;
  tpl->num = num;
  tpl->next = next;

  log_template_v9_header(tpl, pptrs, tpl_type, sid);

  count = num;
  ptr = (u_char *) hdr;
  ptr += NfTplHdrV9Sz;
  field = (struct template_field_v9 *)ptr;
  while (count) {
    type = ntohs(field->type);
    log_template_v9_field(type, tpl->len, ntohs(field->len));

    /* Cisco ASA hack */
    switch (type) {
    case NF9_ASA_XLATE_IPV4_SRC_ADDR:
      type = NF9_XLATE_IPV4_SRC_ADDR;
      break;
    case NF9_ASA_XLATE_IPV4_DST_ADDR:
      type = NF9_XLATE_IPV4_DST_ADDR;
      break;
    case NF9_ASA_XLATE_L4_SRC_PORT:
      type = NF9_XLATE_L4_SRC_PORT;
      break;
    case NF9_ASA_XLATE_L4_DST_PORT:
      type = NF9_XLATE_L4_DST_PORT;
      break;
    default:
      break;
    }

    if (type < NF9_MAX_DEFINED_FIELD) {
      tpl->tpl[type].off = tpl->len;
      tpl->tpl[type].len = ntohs(field->len);
      tpl->len += tpl->tpl[type].len;
    }
    else tpl->len += ntohs(field->len);

    count--;
    field++;
  }

  log_template_v9_footer(tpl->len);
}

void log_template_v9_header(struct template_cache_entry *tpl, struct packet_ptrs *pptrs, u_int16_t tpl_type, u_int32_t sid)
{
  struct host_addr a;
  u_char agent_addr[50];
  u_int16_t agent_port, count, size;

  sa_to_addr((struct sockaddr *)pptrs->f_agent, &a, &agent_port);
  addr_to_str(agent_addr, &a);

  Log(LOG_DEBUG, "DEBUG ( default/core ): NfV9 agent         : %s:%u\n", agent_addr, sid);
  Log(LOG_DEBUG, "DEBUG ( default/core ): NfV9 template type : %s\n", ( tpl->template_type == 0 || tpl->template_type == 2 ) ? "flow" : "options");
  Log(LOG_DEBUG, "DEBUG ( default/core ): NfV9 template ID   : %u\n", ntohs(tpl->template_id));
  Log(LOG_DEBUG, "DEBUG ( default/core ): ----------------------------------------\n");
  Log(LOG_DEBUG, "DEBUG ( default/core ): |     field type     | offset |  size  |\n");
}

void log_template_v9_field(u_int16_t type, u_int16_t off, u_int16_t len)
{
  if (type <= MAX_TPL_DESC_LIST && strlen(tpl_desc_list[type])) 
    Log(LOG_DEBUG, "DEBUG ( default/core ): | %-18s | %6u | %6u |\n", tpl_desc_list[type], off, len);
  else
    Log(LOG_DEBUG, "DEBUG ( default/core ): | %-18u | %6u | %6u |\n", type, off, len);
}

void log_opt_template_v9_field(u_int16_t type, u_int16_t off, u_int16_t len)
{
  if (type <= MAX_OPT_TPL_DESC_LIST && strlen(opt_tpl_desc_list[type]))
    Log(LOG_DEBUG, "DEBUG ( default/core ): | %-18s | %6u | %6u |\n", opt_tpl_desc_list[type], off, len);
  else
    Log(LOG_DEBUG, "DEBUG ( default/core ): | %-18u | %6u | %6u |\n", type, off, len);
}

void log_template_v9_footer(u_int16_t size)
{
  Log(LOG_DEBUG, "DEBUG ( default/core ): ----------------------------------------\n");
  Log(LOG_DEBUG, "DEBUG ( default/core ): NfV9 record size : %u\n", size);
  Log(LOG_DEBUG, "DEBUG ( default/core ): \n");
}

struct template_cache_entry *insert_opt_template_v9(void *hdr, struct packet_ptrs *pptrs, u_int16_t tpl_type, u_int32_t sid)
{
  struct options_template_hdr_v9 *hdr_v9 = (struct options_template_hdr_v9 *) hdr;
  struct options_template_hdr_ipfix *hdr_v10 = (struct options_template_hdr_ipfix *) hdr;
  struct template_cache_entry *ptr, *prevptr = NULL;
  struct template_field_v9 *field;
  u_int16_t modulo, count, slen, olen, type, port, tid;
  u_char *tpl;

  /* NetFlow v9 */
  if (tpl_type == 1) {
    modulo = ntohs(hdr_v9->template_id)%tpl_cache.num;
    tid = hdr_v9->template_id;
    slen = ntohs(hdr_v9->scope_len)/sizeof(struct template_field_v9);
    olen = ntohs(hdr_v9->option_len)/sizeof(struct template_field_v9);
  }
  /* IPFIX */
  else if (tpl_type == 3) {
    modulo = ntohs(hdr_v10->template_id)%tpl_cache.num;
    tid = hdr_v10->template_id;
    slen = ntohs(hdr_v10->scope_count);
    olen = ntohs(hdr_v10->option_count)-slen;
  }

  ptr = tpl_cache.c[modulo];

  while (ptr) {
    prevptr = ptr;
    ptr = ptr->next;
  }

  ptr = malloc(sizeof(struct template_cache_entry));
  if (!ptr) {
    Log(LOG_ERR, "ERROR ( default/core ): Unable to allocate enough memory for a new Options Template Cache Entry.\n");
    return NULL;
  }

  memset(ptr, 0, sizeof(struct template_cache_entry));
  sa_to_addr((struct sockaddr *)pptrs->f_agent, &ptr->agent, &port);
  ptr->source_id = sid; 
  ptr->template_id = tid;
  ptr->template_type = 1;
  ptr->num = olen+slen;

  log_template_v9_header(ptr, pptrs, tpl_type, sid);

  count = ptr->num;
  tpl = (u_char *) hdr;
  tpl += NfOptTplHdrV9Sz;
  field = (struct template_field_v9 *)tpl;
  while (count) {
    type = ntohs(field->type);
    log_opt_template_v9_field(type, ptr->len, ntohs(field->len));
    if (type < NF9_MAX_DEFINED_FIELD) { 
      ptr->tpl[type].off = ptr->len;
      ptr->tpl[type].len = ntohs(field->len);
      ptr->len += ptr->tpl[type].len;
    }
    else ptr->len += ntohs(field->len);

    count--;
    field++;
  }

  if (prevptr) prevptr->next = ptr;
  else tpl_cache.c[modulo] = ptr;

  log_template_v9_footer(ptr->len);

  return ptr;
}

void refresh_opt_template_v9(void *hdr, struct template_cache_entry *tpl, struct packet_ptrs *pptrs, u_int16_t tpl_type, u_int32_t sid)
{
  struct options_template_hdr_v9 *hdr_v9 = (struct options_template_hdr_v9 *) hdr;
  struct options_template_hdr_ipfix *hdr_v10 = (struct options_template_hdr_ipfix *) hdr;
  struct template_cache_entry *next;
  struct template_field_v9 *field;
  u_int16_t slen, olen, count, type, port, tid;
  u_char *ptr;

  /* NetFlow v9 */
  if (tpl_type == 1) {
    tid = hdr_v9->template_id;
    slen = ntohs(hdr_v9->scope_len)/sizeof(struct template_field_v9);
    olen = ntohs(hdr_v9->option_len)/sizeof(struct template_field_v9);
  }
  /* IPFIX */
  else if (tpl_type == 3) {
    tid = hdr_v10->template_id;
    slen = ntohs(hdr_v10->scope_count);
    olen = ntohs(hdr_v10->option_count)-slen;
  }

  next = tpl->next;
  memset(tpl, 0, sizeof(struct template_cache_entry));
  sa_to_addr((struct sockaddr *)pptrs->f_agent, &tpl->agent, &port);
  tpl->source_id = sid;
  tpl->template_id = tid;
  tpl->template_type = 1;
  tpl->num = olen+slen;
  tpl->next = next;

  log_template_v9_header(tpl, pptrs, tpl_type, sid);  

  count = tpl->num;
  ptr = (u_char *) hdr;
  ptr += NfOptTplHdrV9Sz;
  field = (struct template_field_v9 *)ptr;
  while (count) {
    type = ntohs(field->type);
    log_opt_template_v9_field(type, tpl->len, ntohs(field->len));
    if (type < NF9_MAX_DEFINED_FIELD) {
      tpl->tpl[type].off = tpl->len;
      tpl->tpl[type].len = ntohs(field->len);
      tpl->len += tpl->tpl[type].len;
    }
    else tpl->len += ntohs(field->len);

    count--;
    field++;
  }

  log_template_v9_footer(tpl->len);
}

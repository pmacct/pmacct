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

/* defines */
#define __NFV9_TEMPLATE_C

/* includes */
#include "pmacct.h"
#include "nfacctd.h"
#include "pmacct-data.h"

void handle_template_v9(struct template_hdr_v9 *hdr, struct packet_ptrs *pptrs)
{
  struct template_cache_entry *tpl;

  if (tpl = find_template_v9(hdr->template_id, pptrs))
    refresh_template_v9(hdr, tpl, pptrs);
  else insert_template_v9(hdr, pptrs);
}

struct template_cache_entry *find_template_v9(u_int16_t id, struct packet_ptrs *pptrs)
{
  struct template_cache_entry *ptr;
  u_int16_t modulo = (ntohs(id)%tpl_cache.num);

  ptr = tpl_cache.c[modulo];

  while (ptr) {
    if ((ptr->template_id == id) && (!sa_addr_cmp((struct sockaddr *)pptrs->f_agent, &ptr->agent)) &&
	(ptr->source_id == ((struct struct_header_v9 *)pptrs->f_header)->source_id))
      return ptr;
    else ptr = ptr->next;
  }

  return NULL;
}

struct template_cache_entry *insert_template_v9(struct template_hdr_v9 *hdr, struct packet_ptrs *pptrs)
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
  ptr->source_id = ((struct struct_header_v9 *)pptrs->f_header)->source_id;
  ptr->template_id = hdr->template_id;
  ptr->num = num;

  count = num;
  tpl = (u_char *) hdr;
  tpl += NfTplHdrV9Sz;
  field = (struct template_field_v9 *)tpl;
  while (count) {
    type = ntohs(field->type);
    ptr->tpl[type].off = ptr->len; 
    ptr->tpl[type].len = ntohs(field->len);
    ptr->len += ptr->tpl[type].len;
    count--;
    field++;
  }

  if (prevptr) prevptr->next = ptr;
  else tpl_cache.c[modulo] = ptr;

  return ptr;
}

void refresh_template_v9(struct template_hdr_v9 *hdr, struct template_cache_entry *tpl, struct packet_ptrs *pptrs)
{
  struct template_cache_entry *next;
  struct template_field_v9 *field;
  u_int16_t count, num = ntohs(hdr->num), type, port;
  u_char *ptr;

  next = tpl->next;
  memset(tpl, 0, sizeof(struct template_cache_entry));
  sa_to_addr((struct sockaddr *)pptrs->f_agent, &tpl->agent, &port);
  tpl->source_id = ((struct struct_header_v9 *)pptrs->f_header)->source_id;
  tpl->template_id = hdr->template_id;
  tpl->num = num;
  tpl->next = next;

  count = num;
  ptr = (u_char *) hdr;
  ptr += NfTplHdrV9Sz;
  field = (struct template_field_v9 *)ptr;
  while (count) {
    type = ntohs(field->type);
    tpl->tpl[type].off = tpl->len;
    tpl->tpl[type].len = ntohs(field->len);
    tpl->len += tpl->tpl[type].len;
    count--;
    field++;
  }
}

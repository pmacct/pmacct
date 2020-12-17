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
#include "bgp/bgp.h"
#include "bmp.h"

int bmp_tlv_handle_ebit(u_int16_t *type)
{
  if ((*type) & BMP_TLV_EBIT) {
    (*type) ^= BMP_TLV_EBIT;
    return TRUE;
  }
  else {
    return FALSE;
  }
}

int bmp_tlv_get_pen(char **bmp_packet_ptr, u_int32_t *pkt_size, u_int16_t *len, u_int32_t *pen)
{
  char *pen_ptr = NULL;

  if (((*pkt_size) < (*len)) || ((*len) < 4)) return FALSE;

  pen_ptr = bmp_get_and_check_length(bmp_packet_ptr, pkt_size, 4);
  if (pen_ptr) {
    (*len) -= 4;
    memcpy(pen, pen_ptr, 4);
    (*pen) = ntohl((*pen));

    return TRUE;
  }

  return FALSE;
}

char *bmp_tlv_type_print(struct bmp_log_tlv *tlv, const char *prefix, const struct bmp_tlv_def *registry, int max_registry_entries)
{
  char *out = NULL;
  int prefix_len, value_len;
  u_int16_t idx;

  if (!tlv) return out;

  idx = tlv->type;
  prefix_len = strlen(prefix);

  if (registry && (max_registry_entries >= 0)) {
    if (idx <= max_registry_entries) {
      value_len = strlen(registry[idx].name);
      out = malloc(prefix_len + value_len + 1 /* sep */ + 1 /* null */);
      sprintf(out, "%s_%s", prefix, registry[idx].name);

      return out;
    }
  }

  if (!tlv->pen) {
    out = malloc(prefix_len + 5 /* value len */ + 1 /* sep */ + 1 /* null */);
    sprintf(out, "%s_%u", prefix, idx);
  }
  else {
    out = malloc(prefix_len + 10 /* PEN */ + 5 /* value len */ + 2 /* seps */ + 1 /* null */);
    sprintf(out, "%s_%u_%u", prefix, tlv->pen, idx);
  }

  return out;
}

char *bmp_tlv_value_print(struct bmp_log_tlv *tlv, const struct bmp_tlv_def *registry, int max_registry_entries)
{
  u_int16_t idx = tlv->type;
  char *value = NULL;

  if (tlv->len) {
    if (registry && (max_registry_entries >= 0)) {
      if (idx <= max_registry_entries) {
	switch (registry[idx].semantics) {
	case BMP_TLV_SEM_STRING:
	  value = null_terminate(tlv->val, tlv->len);
	  return value;
	case BMP_TLV_SEM_UINT:
	  value = uint_print(tlv->val, tlv->len, TRUE);
	  return value;
	default:
	  break;
	}
      }
    }

    value = malloc(tlv->len * 3); /* 2 bytes hex + 1 byte '-' separator + 1 byte null */
    serialize_hex(tlv->val, (u_char *) value, tlv->len);
  }

  return value;
}

struct pm_list *bmp_tlv_list_new(int (*cmp)(void *val1, void *val2), void (*del)(void *val))
{
  struct pm_list *tlvs = NULL;
  
  tlvs = pm_list_new();
  if (tlvs) {
    tlvs->cmp = cmp;
    tlvs->del = del;
  }

  return tlvs;
}

int bmp_tlv_list_add(struct pm_list *tlvs, u_int32_t pen, u_int16_t type, u_int16_t len, char *val) 
{
  struct bmp_log_tlv *tlv;

  if (!tlvs || (len && !val)) return ERR;

  tlv = malloc(sizeof(struct bmp_log_tlv));
  if (!tlv) return ERR;

  memset(tlv, 0, sizeof(struct bmp_log_tlv));

  tlv->pen = pen;
  tlv->type = type;
  tlv->len = len;

  if (len) {

    tlv->val = malloc(len);
    if (!tlv->val) {
      free(tlv);
      return ERR;
      };

    memcpy(tlv->val, val, len);
  }
  else {
    tlv->val = NULL;
  }

  pm_listnode_add(tlvs, tlv);

  return SUCCESS;
}

void bmp_tlv_list_node_del(void *node)
{
  struct bmp_log_tlv *tlv = NULL;

  tlv = (struct bmp_log_tlv *) node;

  if (tlv) {
    if (tlv->val) free(tlv->val);

    tlv->len = 0;
    tlv->val = NULL;
    free(tlv);
  }
}

struct pm_list *bmp_tlv_list_copy(struct pm_list *src)
{
  struct pm_listnode *node = NULL;
  struct bmp_log_tlv *tlv = NULL;
  struct pm_list *dst = NULL;
  int ret;

  dst = bmp_tlv_list_new(NULL, bmp_tlv_list_node_del);
  for (PM_ALL_LIST_ELEMENTS_RO(src, node, tlv)) {
    ret = bmp_tlv_list_add(dst, tlv->pen, tlv->type, tlv->len, tlv->val);
    if (ret == ERR) {
      bmp_tlv_list_destroy(dst);
      dst = NULL;
      break;
    }
  }

  return dst;
}

void *bmp_tlv_list_find(struct pm_list *tlvs, struct pm_listnode *next_node, u_int16_t type)
{
  struct pm_listnode *node = NULL;
  struct bmp_log_tlv *tlv = NULL;

  for (PM_ALL_LIST_ELEMENTS(tlvs, node, next_node, tlv)) {
    if (tlv->type == type) {
      return tlv;
    }
  }

  return NULL;
}

void bmp_tlv_list_destroy(struct pm_list *tlvs)
{
  if (!tlvs) return;

  pm_list_delete(tlvs);
}

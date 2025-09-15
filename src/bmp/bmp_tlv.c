/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2025 by Paolo Lucente
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

cdada_list_t *bmp_tlv_list_new_v2(void)
{
  return cdada_list_create(char *);
}

int bmp_tlv_list_add_v2(cdada_list_t *tlvs, u_int32_t pen, u_int16_t type, u_int16_t len, u_int16_t index, char *val)
{
  if (!tlvs || (len && !val)) {
    return ERR;
  }

  struct bmp_log_tlv *tlv = malloc(sizeof(struct bmp_log_tlv));
  if (!tlv) {
    return ERR;
  } 

  tlv->pen = pen;
  tlv->type = type;
  tlv->len = len;
  tlv->index = index;
  if (len) {
    tlv->val = malloc(len);
    if (!tlv->val) {
      free(tlv);
      return ERR;
    }
    memcpy(tlv->val, val, len);
  } 
  else {
    tlv->val = NULL;
  }

  int ret = cdada_list_push_back(tlvs, &tlv);
  if (ret != CDADA_SUCCESS) {
    if (tlv->val) {
      free(tlv->val);
    }
    free(tlv);
    return ERR;
  }

  return SUCCESS;
}

cdada_list_t *bmp_tlv_list_copy_v2(cdada_list_t *src)
{
  if (!src) {
    return NULL;
  }

  cdada_list_t *dst = bmp_tlv_list_new_v2();
  if (!dst) {
    return NULL;
  }

  uint32_t size = cdada_list_size(src);
  struct bmp_log_tlv *tlv_ptr = NULL;

  for (uint32_t i = 0; i < size; i++) {
    int ret = cdada_list_get(src, i, &tlv_ptr);
    if (ret != CDADA_SUCCESS || !tlv_ptr) {
      continue;
    }

    int add_ret = bmp_tlv_list_add_v2(dst, tlv_ptr->pen, tlv_ptr->type, tlv_ptr->len, tlv_ptr->index, tlv_ptr->val);
    if (add_ret != CDADA_SUCCESS) {
      bmp_tlv_list_destroy_v2(dst);
      return NULL;
    }
  }

  return dst;
}

void bmp_tlv_list_find_callback_v2(const cdada_list_t *list, const void *val, void *opaque)
{
  struct bmp_log_tlv *current = *(struct bmp_log_tlv **)val;
  struct bmp_tlv_list_result *ctx = opaque;

  if (current && current->type == ctx->type) {
    /* XXX: in case of repeated TLVs, honor the first one */
    if (!ctx->found) {
      ctx->found = current;
    }
  }
}

struct bmp_log_tlv *bmp_tlv_list_find_v2(cdada_list_t *tlvs, u_int16_t type)
{
  // Use the type as opaque data pointer replacement:
  // store input type in 'search_type' and result in 'result'
  struct bmp_tlv_list_result ctx = { type, NULL };

  if (!tlvs) {
    return NULL;
  }

  cdada_list_traverse(tlvs, bmp_tlv_list_find_callback_v2, &ctx);

  return ctx.found;
}

void bmp_tlv_list_destroy_v2(cdada_list_t *tlvs)
{
  struct bmp_log_tlv *tlv = NULL;
  int rc, idx, size;

  if (!tlvs) {
    return;
  }

  size = cdada_list_size(tlvs);
  for (idx = 0; idx < size; idx++) {
    rc = cdada_list_get(tlvs, idx, &tlv);

    if (rc != CDADA_SUCCESS || !tlv) {
      continue;
    }

    if (tlv->val) {
      free(tlv->val);
    }

    free(tlv);
  }

  cdada_list_destroy(tlvs);
}

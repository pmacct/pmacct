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

#ifndef BMP_TLV_H
#define BMP_TLV_H

/* includes */

/* defines */

/* prototypes */
extern int bmp_tlv_handle_ebit(u_int16_t *);
extern int bmp_tlv_get_pen(char **, u_int32_t *, u_int16_t *, u_int32_t *);
extern char *bmp_tlv_type_print(struct bmp_log_tlv *, const char *, const struct bmp_tlv_def *, int);
extern char *bmp_tlv_value_print(struct bmp_log_tlv *, const struct bmp_tlv_def *, int);
extern struct pm_list *bmp_tlv_list_new(int (*cmp)(void *val1, void *val2), void (*del)(void *val));
extern int bmp_tlv_list_add(struct pm_list *, u_int32_t, u_int16_t, u_int16_t, char *);
extern void bmp_tlv_list_node_del(void *node);
extern struct pm_list *bmp_tlv_list_copy(struct pm_list *);
extern void *bmp_tlv_list_find(struct pm_list *, struct pm_listnode *, u_int16_t);
extern void bmp_tlv_list_destroy(struct pm_list *);
#endif //BMP_TLV_H

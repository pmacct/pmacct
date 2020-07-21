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

#ifndef BMP_RPAT_H
#define BMP_RPAT_H

/* defines */
struct bmp_rpat_common_hdr {
  u_char        flags;
  u_char        rd[RD_LEN];
  u_char	prefix_len;
  u_int32_t     prefix[4];
  u_int32_t     bgp_id;
  u_char	events_count;
  u_int16_t	events_length;
} __attribute__ ((packed));

struct bmp_rpat_event_hdr {
  u_int16_t	len;
  u_int8_t	idx;
  u_int32_t     tstamp_sec;
  u_int32_t     tstamp_usec;
  u_int32_t	path_id;
  u_int16_t	afi;
  u_int8_t	safi;
} __attribute__ ((packed));

struct bmp_log_rpat {
  struct host_addr prefix;
  u_int8_t prefix_len;
  u_int8_t event_idx;
  u_int32_t path_id;
  afi_t afi;
  safi_t safi;
};

static const struct bmp_tlv_def __attribute__((unused)) bmp_rpat_info_types[] = {
  { "vrf", BMP_TLV_SEM_COMPLEX },
  { "policy", BMP_TLV_SEM_COMPLEX },
  { "pre_policy_attr", BMP_TLV_SEM_COMPLEX },
  { "post_policy_attr", BMP_TLV_SEM_COMPLEX },
  { "string", BMP_TLV_SEM_STRING }
};

#define BMP_RPAT_INFO_VRF		0
#define BMP_RPAT_INFO_POLICY		1
#define BMP_RPAT_INFO_PRE_POLICY_ATTR	2
#define BMP_RPAT_INFO_POST_POLICY_ATTR	3
#define BMP_RPAT_INFO_STRING		4
#define BMP_RPAT_INFO_MAX		4
#define BMP_RPAT_INFO_ENTRIES		8

/* prototypes */
extern void bmp_process_msg_rpat(char **, u_int32_t *, struct bmp_peer *);

extern void bmp_rpat_common_hdr_get_v_flag(struct bmp_rpat_common_hdr *, u_int8_t *);
extern void bmp_rpat_common_hdr_get_bgp_id(struct bmp_rpat_common_hdr *, struct host_addr *);
extern void bmp_rpat_common_hdr_get_rd(struct bmp_rpat_common_hdr *, rd_t *);
extern void bmp_rpat_common_hdr_get_prefix(struct bmp_rpat_common_hdr *, struct host_addr *, u_int8_t *);
extern void bmp_rpat_common_hdr_get_prefix_len(struct bmp_rpat_common_hdr *, u_int8_t *);

extern void bmp_rpat_event_hdr_get_index(struct bmp_rpat_event_hdr *, u_int8_t *);
extern void bmp_rpat_event_hdr_get_tstamp(struct bmp_rpat_event_hdr *, struct timeval *tv);
extern void bmp_rpat_event_hdr_get_path_id(struct bmp_rpat_event_hdr *, u_int32_t *);
extern void bmp_rpat_event_hdr_get_afi_safi(struct bmp_rpat_event_hdr *, afi_t *, safi_t *);

extern int bmp_log_msg_rpat(struct bgp_peer *, struct bmp_data *, struct pm_list *, struct bmp_log_rpat *, char *, int, void *);
#endif //BMP_RPAT_H

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

struct bmp_rpat_vrf_tlv_hdr {
  u_int32_t	id;
} __attribute__ ((packed));

struct bmp_rpat_policy_tlv_hdr {
  u_int8_t	flag;
  u_int8_t	count;
  u_int8_t	class;
  u_int32_t     peer_ip[4];
  u_int32_t     peer_bgp_id;
  u_int32_t     peer_asn;
} __attribute__ ((packed));

struct bmp_rpat_policy_hdr {
  u_int16_t	name_len;
  u_int16_t	id_len;
} __attribute__ ((packed));

#define BMP_RPAT_POLICY_CLASS_INBOUND		0
#define BMP_RPAT_POLICY_CLASS_OUTBOUND		1
#define BMP_RPAT_POLICY_CLASS_MP_REDISTRIBUTE	2
#define BMP_RPAT_POLICY_CLASS_VRF_REDISTRIBUTE	3
#define BMP_RPAT_POLICY_CLASS_VRF_IMPORT	4
#define BMP_RPAT_POLICY_CLASS_VRF_EXPORT	5
#define BMP_RPAT_POLICY_CLASS_NETWORK		6
#define BMP_RPAT_POLICY_CLASS_AGGREGATION	7
#define BMP_RPAT_POLICY_CLASS_ROUTE_WITHDRAW	8
#define BMP_RPAT_POLICY_CLASS_MAX 		8

static const char __attribute__((unused)) *bmp_rpat_class_types[] = {
  "Inbound policy",
  "Outbound policy",
  "Multi-protocol Redistribute",
  "Cross-VRF Redistribute",
  "VRF import",
  "VRF export",
  "Network",
  "Aggregation",
  "Route Withdraw"
};

#define BMP_RPAT_POLICY_FLAG_M		0x80
#define BMP_RPAT_POLICY_FLAG_P		0x40
#define BMP_RPAT_POLICY_FLAG_D		0x20

#define BMP_RPAT_POLICY_NP_FLAG_C	0x80
#define BMP_RPAT_POLICY_NP_FLAG_R	0x40

struct bmp_log_rpat {
  struct host_addr prefix;
  u_int8_t prefix_len;
  u_int8_t event_idx;
  u_int32_t path_id;
  afi_t afi;
  safi_t safi;
};

/* prototypes needed for bmp_tlv_def */
extern int bmp_log_msg_rpat_vrf(struct bgp_peer *, struct bmp_data *, void *, void *, char *, int, void *);
extern int bmp_log_msg_rpat_policy(struct bgp_peer *, struct bmp_data *, void *, void *, char *, int, void *);

static const struct bmp_tlv_def __attribute__((unused)) bmp_rpat_info_types[] = {
  { "vrf", BMP_TLV_SEM_COMPLEX, bmp_log_msg_rpat_vrf },
  { "policy", BMP_TLV_SEM_COMPLEX, bmp_log_msg_rpat_policy },
  { "pre_policy_attr", BMP_TLV_SEM_COMPLEX, NULL },
  { "post_policy_attr", BMP_TLV_SEM_COMPLEX, NULL },
  { "string", BMP_TLV_SEM_STRING, NULL }
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

extern void bmp_rpat_policy_tlv_get_m_flag(struct bmp_rpat_policy_tlv_hdr *, u_int8_t *);
extern void bmp_rpat_policy_tlv_get_p_flag(struct bmp_rpat_policy_tlv_hdr *, u_int8_t *);
extern void bmp_rpat_policy_tlv_get_d_flag(struct bmp_rpat_policy_tlv_hdr *, u_int8_t *);
extern void bmp_rpat_policy_tlv_get_bgp_id(struct bmp_rpat_policy_tlv_hdr *, struct host_addr *);
extern void bmp_rpat_policy_tlv_get_peer_ip(struct bmp_rpat_policy_tlv_hdr *, struct host_addr *, u_int8_t *);
extern void bmp_rpat_policy_tlv_np_get_c_flag(u_int8_t *, u_int8_t *);
extern void bmp_rpat_policy_tlv_np_get_r_flag(u_int8_t *, u_int8_t *);

extern int bmp_log_msg_rpat(struct bgp_peer *, struct bmp_data *, struct pm_list *, struct bmp_log_rpat *, char *, int, void *);

#ifdef WITH_AVRO
extern avro_schema_t p_avro_schema_build_bmp_rpat(char *);
#endif
#endif //BMP_RPAT_H

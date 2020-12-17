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

#ifndef BMP_MSG_H
#define BMP_MSG_H

/* includes */

/* defines */

/* prototypes */
extern u_int32_t bmp_process_packet(char *, u_int32_t, struct bmp_peer *, int *);
extern void bmp_process_msg_init(char **, u_int32_t *, struct bmp_peer *);
extern void bmp_process_msg_term(char **, u_int32_t *, struct bmp_peer *);
extern void bmp_process_msg_peer_up(char **, u_int32_t *, struct bmp_peer *);
extern void bmp_process_msg_peer_down(char **, u_int32_t *, struct bmp_peer *);
extern void bmp_process_msg_stats(char **, u_int32_t *, struct bmp_peer *);
extern void bmp_process_msg_route_monitor(char **, u_int32_t *, struct bmp_peer *);
extern void bmp_process_msg_route_mirror(char **, u_int32_t *, struct bmp_peer *);

extern void bmp_common_hdr_get_len(struct bmp_common_hdr *, u_int32_t *);
extern void bmp_tlv_hdr_get_type(struct bmp_tlv_hdr *, u_int16_t *);
extern void bmp_tlv_hdr_get_len(struct bmp_tlv_hdr *, u_int16_t *);
extern void bmp_term_hdr_get_reason_type(char **, u_int32_t *, u_int16_t *);
extern void bmp_peer_hdr_get_v_flag(struct bmp_peer_hdr *, u_int8_t *);
extern void bmp_peer_hdr_get_l_flag(struct bmp_peer_hdr *, u_int8_t *);
extern void bmp_peer_hdr_get_a_flag(struct bmp_peer_hdr *, u_int8_t *);
extern void bmp_peer_hdr_get_f_flag(struct bmp_peer_hdr *, u_int8_t *);
extern void bmp_peer_hdr_get_o_flag(struct bmp_peer_hdr *, u_int8_t *);
extern void bmp_peer_hdr_get_peer_ip(struct bmp_peer_hdr *, struct host_addr *, u_int8_t *);
extern void bmp_peer_hdr_get_bgp_id(struct bmp_peer_hdr *, struct host_addr *);
extern void bmp_peer_hdr_get_rd(struct bmp_peer_hdr *, rd_t *);
extern void bmp_peer_hdr_get_tstamp(struct bmp_peer_hdr *, struct timeval *);
extern void bmp_peer_hdr_get_peer_asn(struct bmp_peer_hdr *, u_int32_t *);
extern void bmp_peer_hdr_get_peer_type(struct bmp_peer_hdr *, u_int8_t *);
extern void bmp_peer_up_hdr_get_local_ip(struct bmp_peer_up_hdr *, struct host_addr *, u_int8_t);
extern void bmp_peer_up_hdr_get_loc_port(struct bmp_peer_up_hdr *, u_int16_t *);
extern void bmp_peer_up_hdr_get_rem_port(struct bmp_peer_up_hdr *, u_int16_t *);
extern void bmp_peer_down_hdr_get_reason(struct bmp_peer_down_hdr *, u_char *);
extern void bmp_peer_down_hdr_get_loc_code(char **, u_int32_t *, u_int16_t *);
extern void bmp_stats_hdr_get_count(struct bmp_stats_hdr *, u_int32_t *);
extern void bmp_stats_cnt_hdr_get_type(struct bmp_stats_cnt_hdr *, u_int16_t *);
extern void bmp_stats_cnt_hdr_get_len(struct bmp_stats_cnt_hdr *, u_int16_t *);
extern void bmp_stats_cnt_get_data32(char **, u_int32_t *, u_int32_t *);
extern void bmp_stats_cnt_get_data64(char **, u_int32_t *, u_int64_t *);
extern void bmp_stats_cnt_get_afi_safi_data64(char **, u_int32_t *, afi_t *, safi_t *, u_int64_t *);

#endif //BMP_MSG_H

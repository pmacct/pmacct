/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2021 by Paolo Lucente
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

#ifndef BMP_UTIL_H
#define BMP_UTIL_H

/* includes */

/* defines */

/* prototypes */
extern char *bmp_get_and_check_length(char **, u_int32_t *, u_int32_t);
extern int bmp_jump_offset(char **, u_int32_t *, u_int32_t);
extern void bmp_link_misc_structs(struct bgp_misc_structs *);
extern struct bgp_peer *bmp_sync_loc_rem_peers(struct bgp_peer *, struct bgp_peer *);
extern int bmp_peer_init(struct bmp_peer *, int);
extern void bmp_peer_close(struct bmp_peer *, int);

extern char *bmp_term_reason_print(u_int16_t);

extern void bgp_peer_log_msg_extras_bmp(struct bgp_peer *, int, int, int, void *);

extern void bgp_msg_data_set_data_bmp(struct bmp_chars *, struct bmp_data *);
extern int bgp_extra_data_cmp_bmp(struct bgp_msg_extra_data *, struct bgp_msg_extra_data *);
extern int bgp_extra_data_process_bmp(struct bgp_msg_extra_data *, struct bgp_info *, int, int);
extern void bgp_extra_data_free_bmp(struct bgp_msg_extra_data *);
extern void bgp_extra_data_print_bmp(struct bgp_msg_extra_data *, int, void *);

extern void encode_tstamp_arrival(char *, int, struct timeval *, int);
extern char *decode_tstamp_arrival(char *);
#endif //BMP_UTIL_H

/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2015 by Paolo Lucente
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
#define BMP_TCP_PORT		1790
#define BMP_MAX_PACKET_SIZE	4096
#define BMP_MAX_PEERS_DEFAULT	4

/* definitions based on draft-ietf-grow-bmp-07 */

/* BMP message types */
#define BMP_MSG_ROUTE		0	
#define	BMP_MSG_STATS		1
#define BMP_MSG_PEER_DOWN	2
#define BMP_MSG_PEER_UP		3
#define	BMP_MSG_INIT		4
#define BMP_MSG_TERM		5

struct bmp_common_hdr {
  u_int8_t	version;
  u_int32_t	len;
  u_int8_t	type;
};

#define BMP_PEER_GLOBAL		0
#define BMP_PEER_L3VPN		1

/*
struct bmp_peer_flags {
  XXX
};
*/

struct bmp_peer_hdr {
  u_int8_t	type;
  u_int8_t	flags;
  u_int8_t	rd[RD_LEN];
  u_int8_t	addr[16];
  u_int32_t	asn;
  u_int32_t	bgp_id;
  u_int32_t	tstamp_secs;
  u_int32_t	tstamp_residual;
};

#define BMP_INIT_INFO_STRING	0
#define BMP_INIT_INFO_SYSDESCR	1
#define BMP_INIT_INFO_SYSNAME	2

struct bmp_init_hdr {
  u_int16_t	type;
  u_int16_t	len;
};

#define BMP_TERM_INFO_STRING    0
#define BMP_TERM_INFO_REASON	1

#define BMP_TERM_REASON_ADM	0
#define BMP_TERM_REASON_UNK	1
#define BMP_TERM_REASON_OOR	2
#define BMP_TERM_REASON_DUP	3

struct bmp_term_hdr {
  u_int16_t     type;
  u_int16_t     len;
};

struct bmp_stats_hdr {
  u_int32_t	count;
};

#define BMP_STATS_TYPE0		0 /* (32-bit Counter) Number of prefixes rejected by inbound policy */
#define BMP_STATS_TYPE1		1 /* (32-bit Counter) Number of (known) duplicate prefix advertisements */
#define BMP_STATS_TYPE2		2 /* (32-bit Counter) Number of (known) duplicate withdraws */
#define BMP_STATS_TYPE3		3 /* (32-bit Counter) Number of updates invalidated due to CLUSTER_LIST loop */
#define BMP_STATS_TYPE4		4 /* (32-bit Counter) Number of updates invalidated due to AS_PATH loop */
#define BMP_STATS_TYPE5		5 /* (32-bit Counter) Number of updates invalidated due to ORIGINATOR_ID */ 
#define BMP_STATS_TYPE6		6 /* (32-bit Counter) Number of updates invalidated due to AS_CONFED loop */
#define BMP_STATS_TYPE7		7 /* (64-bit Gauge) Number of routes in Adj-RIBs-In */
#define BMP_STATS_TYPE8		8 /* (64-bit Gauge) Number of routes in Loc-RIB */

struct bmp_stats_cnt_hdr {
  u_int16_t	type;
  u_int16_t	len;
};

#define BMP_PEER_DOWN_LOC_NOT_MSG	1
#define BMP_PEER_DOWN_LOC_CODE		2
#define BMP_PEER_DOWN_REM_NOT_MSG	3
#define BMP_PEER_DOWN_REM_CODE		4

struct bmp_peer_down_hdr {
  u_int8_t	reason;
};

struct bmp_peer_up_hdr {
  u_int8_t	addr[16];
  u_int16_t	loc_port;
  u_int16_t	rem_port;
  /* Sent OPEN Message */
  /* Received OPEN Message */
};

/* prototypes */
#if (!defined __BMP_C)
#define EXT extern
#else
#define EXT
#endif
EXT void nfacctd_bmp_wrapper();
EXT void skinny_bmp_daemon();
EXT void bmp_attr_init();

/* global variables */
EXT struct bgp_peer *bmp_peers; // XXX
EXT struct hash *bmp_attrhash;
EXT struct hash *bmp_ashash;
EXT struct hash *bmp_comhash;
EXT struct hash *bmp_ecomhash;
EXT struct bgp_table *bmp_rib[AFI_MAX][SAFI_MAX];
EXT u_int32_t (*bmp_route_info_modulo)(struct bgp_peer *, path_id_t *);
#undef EXT

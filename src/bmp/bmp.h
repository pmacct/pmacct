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

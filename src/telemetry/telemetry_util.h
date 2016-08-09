/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2016 by Paolo Lucente
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

/* defines */

/* prototypes */
#if (!defined __TELEMETRY_UTIL_C)
#define EXT extern
#else
#define EXT
#endif
EXT int telemetry_peer_init(telemetry_peer *, int);
EXT int telemetry_peer_z_init(telemetry_peer_z *);
EXT void telemetry_peer_close(telemetry_peer *, int);
EXT void telemetry_peer_z_close(telemetry_peer_z *);
EXT u_int32_t telemetry_cisco_hdr_get_len(telemetry_peer *);
EXT u_int32_t telemetry_cisco_hdr_get_type(telemetry_peer *);
EXT int telemetry_is_zjson(int);
EXT void telemetry_link_misc_structs(telemetry_misc_structs *);
EXT int telemetry_tpuc_addr_cmp(const void *, const void *);
EXT int telemetry_validate_input_output_decoders(int, int);
EXT void telemetry_log_peer_stats(telemetry_peer *, struct telemetry_data *);
EXT void telemetry_log_global_stats(struct telemetry_data *);
#undef EXT

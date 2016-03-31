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
#if (!defined __TELEMETRY_MSG_C)
#define EXT extern
#else
#define EXT
#endif
EXT void telemetry_process_data(telemetry_peer *, struct telemetry_data *);

EXT int telemetry_recv_generic(telemetry_peer *, u_int32_t);
EXT int telemetry_recv_json(telemetry_peer *, u_int32_t, int *);
EXT int telemetry_recv_zjson(telemetry_peer *, telemetry_peer_z *, u_int32_t, int *);
EXT int telemetry_recv_cisco_json(telemetry_peer *, int *);
EXT int telemetry_recv_cisco_zjson(telemetry_peer *, telemetry_peer_z *, int *);
EXT void telemetry_basic_process_json(telemetry_peer *);
EXT int telemetry_basic_validate_json(telemetry_peer *);
#undef EXT

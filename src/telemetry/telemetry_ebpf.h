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

#ifndef TELEMETRY_EBPF_H
#define TELEMETRY_EBPF_H

/* includes */

/* defines */

/* prototypes */
#ifdef WITH_UNYTE_UDP_NOTIF
#ifdef WITH_EBPF
extern int attach_ebpf_unyte_udp_notif(int, char *, u_int32_t);
#endif
#endif

#endif //TELEMETRY_EBPF_H

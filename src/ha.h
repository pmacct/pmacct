/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2024 by Paolo Lucente
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

#ifndef HA_H
#define HA_H

#if defined WITH_REDIS

/*Linked list (LL) node to store a queue entry*/
typedef struct QNode {
    void *buf;
    size_t buf_len;
    long long timestamp;
} nodestruct;

/*Global Functions*/
extern void bmp_bgp_ha_enqueue(void *, size_t);
extern void p_redis_thread_bmp_bgp_ha_handler(void *);
extern void bmp_bgp_ha_main(void);

/*Signal handlers*/
extern void bmp_bgp_ha_regenerate_timestamp(int);
extern void bmp_bgp_ha_set_to_active(int);
extern void bmp_bgp_ha_set_to_standby(int);
extern void bmp_bgp_ha_set_to_normal(int);

#endif
#endif

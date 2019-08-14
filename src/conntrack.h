/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2019 by Paolo Lucente
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

#ifndef CONNTRACK_H
#define CONNTRACK_H

/* defines */
#define CONNTRACK_GENERIC_LIFETIME 20 
#define DEFAULT_CONNTRACK_BUFFER_SIZE 8192000 /* 8 Mb */
#define MAX_CONNTRACKS 256

/* structures */
typedef void (*conntrack_helper)(time_t, struct packet_ptrs *);

struct conntrack_helper_entry {
  char protocol[MAX_PROTOCOL_LEN];
  conntrack_helper ct_helper;
};

struct conntrack_ipv4 {
  u_int32_t ip_src;
  u_int32_t ip_dst;
  u_int16_t port_src;
  u_int16_t port_dst;
  u_int8_t proto;
  pm_class_t class;
  /* timestamp renewal flag ? */
  time_t stamp;
  time_t expiration;
  conntrack_helper helper;
  struct conntrack_ipv4 *next;
};

struct conntrack_ipv6 {
  u_int32_t ip_src[4];
  u_int32_t ip_dst[4];
  u_int16_t port_src;
  u_int16_t port_dst;
  u_int8_t proto;
  pm_class_t class;
  /* timestamp renewal flag ? */
  time_t stamp;
  time_t expiration;
  conntrack_helper helper;
  struct conntrack_ipv6 *next;
};

extern void init_conntrack_table();
extern void conntrack_ftp_helper(time_t, struct packet_ptrs *);
extern void conntrack_sip_helper(time_t, struct packet_ptrs *);
extern void conntrack_rtsp_helper(time_t, struct packet_ptrs *);
extern void search_conntrack(struct ip_flow_common *, struct packet_ptrs *, unsigned int);
extern void search_conntrack_ipv4(struct ip_flow_common *, struct packet_ptrs *, unsigned int);
extern void insert_conntrack_ipv4(time_t, u_int32_t, u_int32_t, u_int16_t, u_int16_t, u_int8_t, pm_class_t, conntrack_helper, time_t);
extern void search_conntrack_ipv6(struct ip_flow_common *, struct packet_ptrs *, unsigned int);
extern void insert_conntrack_ipv6(time_t, struct in6_addr *, struct in6_addr *, u_int16_t, u_int16_t, u_int8_t, pm_class_t, conntrack_helper, time_t);


extern struct conntrack_ipv4 *conntrack_ipv4_table;
extern struct conntrack_ipv6 *conntrack_ipv6_table;
extern struct conntrack_helper_entry __attribute__((unused)) conntrack_helper_list[4];

#endif //CONNTRACK_H

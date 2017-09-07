/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2017 by Paolo Lucente
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
#if defined IM_LITTLE_ENDIAN
#define IS_IPV4_MULTICAST(a) ((((u_int32_t)(a)) & 0x000000f0) == 0x000000e0)
#else
#define IS_IPV4_MULTICAST(a) ((((u_int32_t)(a)) & 0xf0000000) == 0xe0000000)
#endif
#define IS_IPV6_MULTICAST(a) (((const uint8_t *) (a))[0] == 0xff)

/* prototypes */
#if (!defined __ADDR_C)
#define EXT extern
#else
#define EXT
#endif
EXT unsigned int str_to_addr(const char *, struct host_addr *);
EXT unsigned int addr_to_str(char *, const struct host_addr *);
EXT unsigned int str_to_addr_mask(const char *, struct host_addr *, struct host_mask *);
EXT unsigned int addr_to_sa(struct sockaddr *, struct host_addr *, u_int16_t);
EXT unsigned int sa_to_addr(struct sockaddr *, struct host_addr *, u_int16_t *);
EXT int sa_addr_cmp(struct sockaddr *, struct host_addr *);
EXT int sa_port_cmp(struct sockaddr *, u_int16_t);
EXT int host_addr_mask_sa_cmp(struct host_addr *, struct host_mask *, struct sockaddr *);
EXT unsigned int raw_to_sa(struct sockaddr *, char *, u_int16_t port, u_int8_t);
EXT unsigned int sa_to_str(char *, const struct sockaddr *);
EXT void *pm_htonl6(void *);
EXT void *pm_ntohl6(void *);
EXT u_int64_t pm_htonll(u_int64_t);
EXT u_int64_t pm_ntohll(u_int64_t);
EXT int ip6_addr_cmp(void *, void *);
EXT void ip6_addr_cpy(void *, void *);
EXT void ip6_addr_32bit_cpy(void *, void *, int, int, int);
EXT void etheraddr_string(const u_char *, char *);
EXT int string_etheraddr(const u_char *, char *);
EXT int is_multicast(struct host_addr *);
EXT int is_any(struct host_addr *);
EXT void clean_sin_addr(struct sockaddr *);
EXT unsigned int label_to_addr(const char *, struct host_addr *, int);
EXT u_int8_t etype_to_af(u_int16_t);
EXT u_int16_t af_to_etype(u_int8_t);

#if defined ENABLE_IPV6
EXT void ipv4_mapped_to_ipv4(struct sockaddr_storage *);
EXT void ipv4_to_mapped_ipv4(struct sockaddr_storage *);
#endif

#undef EXT

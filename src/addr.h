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

#ifndef ADDR_H
#define ADDR_H

/* defines */
#if defined IM_LITTLE_ENDIAN
#define IS_IPV4_MULTICAST(a) ((((u_int32_t)(a)) & 0x000000f0) == 0x000000e0)
#else
#define IS_IPV4_MULTICAST(a) ((((u_int32_t)(a)) & 0xf0000000) == 0xe0000000)
#endif
#define IS_IPV6_MULTICAST(a) (((const uint8_t *) (a))[0] == 0xff)
#define IS_MAC_MULTICAST(a) (((const uint8_t *) (a))[0] == 0x01)

static const char __attribute__((unused)) *ip_version_string[] = {
  "v4",
  "v6"
};

static const u_int8_t __attribute__((unused)) ip_version_num[] = {
  4,
  6
};

/* prototypes */
extern unsigned int str_to_addr(const char *, struct host_addr *);
extern unsigned int addr_to_str(char *, const struct host_addr *);
extern unsigned int addr_to_str2(char *, const struct host_addr *, int);
extern unsigned int addr_mask_to_str(char *, int, const struct host_addr *, const struct host_mask *);
extern unsigned int str_to_addr_mask(const char *, struct host_addr *, struct host_mask *);
extern unsigned int addr_to_sa(struct sockaddr *, struct host_addr *, u_int16_t);
extern unsigned int sa_to_addr(struct sockaddr *, struct host_addr *, u_int16_t *);
extern int sa_addr_cmp(struct sockaddr *, struct host_addr *);
extern int sa_port_cmp(struct sockaddr *, u_int16_t);
extern int host_addr_cmp(struct host_addr *, struct host_addr *);
extern int host_addr_cmp2(struct host_addr *, struct host_addr *);
extern int host_addr_mask_sa_cmp(struct host_addr *, struct host_mask *, struct sockaddr *);
extern int host_addr_mask_cmp(struct host_addr *, struct host_mask *, struct host_addr *);
extern unsigned int raw_to_sa(struct sockaddr *, u_char *, u_int16_t port, u_int8_t);
extern unsigned int raw_to_addr(struct host_addr *, u_char *, u_int8_t);
extern unsigned int sa_to_str(char *, int, const struct sockaddr *);
extern unsigned int sa_to_port(int *, const struct sockaddr *);
extern void *pm_htonl6(void *);
extern void *pm_ntohl6(void *);
extern u_int64_t pm_htonll(u_int64_t);
extern u_int64_t pm_ntohll(u_int64_t);
extern int ip6_addr_cmp(void *, void *);
extern void ip6_addr_cpy(void *, void *);
extern void ip6_addr_32bit_cpy(void *, void *, int, int, int);
extern void etheraddr_string(const u_char *, char *);
extern int string_etheraddr(const char *, u_char *);
extern int is_multicast(struct host_addr *);
extern int is_any(struct host_addr *);
extern void clean_sin_addr(struct sockaddr *);
extern u_int8_t etype_to_af(u_int16_t);
extern u_int16_t af_to_etype(u_int8_t);
extern const char *af_to_version_str(u_int8_t);
extern u_int8_t af_to_version(u_int8_t);
extern const char *etype_to_version_str(u_int16_t);
extern u_int8_t etype_to_version(u_int16_t);
extern u_int32_t addr_hash(struct host_addr *, u_int32_t);
extern u_int32_t addr_port_hash(struct host_addr *, u_int16_t, u_int32_t);
extern u_int32_t sa_hash(struct sockaddr *, u_int32_t);
extern u_int16_t sa_has_family(struct sockaddr *);
extern socklen_t sa_len(struct sockaddr_storage *);

extern void ipv4_to_ipv4_mapped(struct sockaddr_storage *);
extern void ipv4_mapped_to_ipv4(struct sockaddr_storage *);

#endif //ADDR_H

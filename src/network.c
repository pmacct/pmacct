/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2020 by Paolo Lucente
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
    along with this program; if no, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include "pmacct.h"
#include "addr.h"
#include "network.h"

struct tunnel_handler tunnel_registry[TUNNEL_REGISTRY_STACKS][TUNNEL_REGISTRY_ENTRIES];

int parse_proxy_header(int fd, struct host_addr *addr, u_int16_t *port)
{
  const char v2sig[12] = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";
  char ip_address[INET6_ADDRSTRLEN];
  size_t size = 0;
  proxy_protocol_header hdr;

  addr_to_str(ip_address, addr);

  int ret = recv(fd, &hdr, sizeof(hdr), MSG_PEEK);

  /* 16 bytes can detect both V1 and V2 protocols */
  if (ret < 16) {
    return ERR;
  }

  if (memcmp(hdr.v1.line, "PROXY", 5) == 0) {
    Log(LOG_DEBUG, "DEBUG ( %s/%s ): Proxy Protocol V1\n", config.name, config.type);

    char *end = memchr(hdr.v1.line, '\r', ret - 1);
    if (!end || end[1] != '\n')  {
      return ERR;
    }

    (*end) = '\0';

    /* V1 Header contains string: PROXY TCP4 <src ip> <dst ip> <src port> <dst port>\r\n */
    Log(LOG_INFO, "INFO ( %s/%s ): Replacing: %s:%u\n", config.name, config.type, ip_address, *port);

    /* Find the Source IP Address */
    char *s = &hdr.v1.line[11];
    char *e = strchr(s, ' ');
    snprintf(ip_address, (e - s + 1), "%s", s);

    /* Find the Source TCP Port */
    s = e + 1;
    e = strchr(s, ' ');
    s = e + 1;
    *port = strtoul(s, 0, 10);

    Log(LOG_INFO, "INFO ( %s/%s ):            with Proxy Protocol V1 containing: %s:%u\n", config.name, config.type, ip_address, *port);
    str_to_addr(ip_address, addr);

    /* Consume the proxy protocol header for real, skip header + CRLF */
    size = (end + 2 - hdr.v1.line);
  }
  else if (memcmp(&hdr.v2, v2sig, 12) == 0) {
    Log(LOG_DEBUG, "DEBUG ( %s/%s ): Proxy Protocol V2\n", config.name, config.type);

    size = (16 + ntohs(hdr.v2.len));
    if (ret < size) {
      return ERR;
    }

    if (((hdr.v2.ver_cmd & 0xF0) == 0x20) && ((hdr.v2.ver_cmd & 0x0F) == 0x01)) {
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): Proxy Protocol PROXY command\n", config.name, config.type);

      if (hdr.v2.fam == 0x11) {
        Log(LOG_DEBUG, "DEBUG ( %s/%s ): Proxy Protocol TCP/IPv4\n", config.name, config.type);

        /* Replace IP address string originally obtained from socket */
        Log(LOG_INFO, "INFO ( %s/%s ): Replacing: %s:%u\n", config.name, config.type, ip_address, *port);
        addr->family = AF_INET;
        memcpy(&addr->address.ipv4.s_addr, &hdr.v2.addr.ip4.src_addr, sizeof(hdr.v2.addr.ip4.src_addr));
        *port = ntohs(hdr.v2.addr.ip4.src_port);

        addr_to_str(ip_address, addr);
        Log(LOG_INFO, "INFO ( %s/%s ):            with Proxy Protocol V2 containing: %s:%u\n", config.name, config.type, ip_address, *port);
      }
      else {
        Log(LOG_DEBUG, "DEBUG ( %s/%s ): Proxy Protocol (TODO) Unsupported family: %u\n", config.name, config.type, hdr.v2.fam);
      }
    }
    else if (((hdr.v2.ver_cmd & 0xF0) == 0x20) && ((hdr.v2.ver_cmd & 0x0F) == 0x00)) {
      /* LOCAL Command. Health Check. Use real conection endpoints. */
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): Proxy Protocol LOCAL command\n", config.name, config.type);
    }
  }
  else {
    Log(LOG_DEBUG, "DEBUG ( %s/%s ): Not Proxy Protocol\n", config.name, config.type);
  }

  if (size > 0) {
    /* Consume the proxy protocol header for real */
    ret = recv(fd, &hdr, size, 0);
  }

  return 0;
}

/* Computing the internet checksum (RFC 1071) */
u_int16_t pm_checksum(u_int16_t *addr, int len, u_int32_t *prev_sum, int last)
{
  int count = len;
  u_int32_t sum = 0;
  u_int16_t answer = 0;

  if (prev_sum) {
    sum = (*prev_sum);
  }

  /* Sum up 2-byte values until none or only one byte left */
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  /* Add left-over byte, if any */
  if (count > 0) {
    sum += *(u_int8_t *) addr;
  }

  if (last) {
    /* Fold 32-bit sum into 16 bits; we lose information by doing this
       sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits) */
    while (sum >> 16) {
      sum = (sum & 0xffff) + (sum >> 16);
    }

    /* Making one-complement of it */
    answer = ~sum;
  }

  if (prev_sum) {
    (*prev_sum) = sum;
  }

  return (answer);
}

/* Build IPv6 UDP pseudo-header and call checksum function (Section 8.1 of RFC 2460). */
u_int16_t pm_udp6_checksum(struct ip6_hdr *ip6hdr, struct pm_udphdr *udphdr, u_char *payload, int payload_len)
{
  u_char buf[2];
  u_int32_t sum = 0;
  u_int16_t answer = 0;

  /* Copy source IP address into buf (128 bits) */
  pm_checksum ((u_int16_t *)&ip6hdr->ip6_src.s6_addr, sizeof (ip6hdr->ip6_src.s6_addr), &sum, FALSE);

  /* Seed destination IP address (128 bits) */
  pm_checksum ((u_int16_t *)&ip6hdr->ip6_dst.s6_addr, sizeof (ip6hdr->ip6_dst.s6_addr), &sum, FALSE);

  /* Seed UDP length (32 bits) */
  pm_checksum ((u_int16_t *)&udphdr->uh_ulen, sizeof (udphdr->uh_ulen), &sum, FALSE);

  /* Seed next header field (8 + 8 bits) */
  memset(buf, 0, sizeof(buf));
  buf[1] = ip6hdr->ip6_nxt;
  pm_checksum ((u_int16_t *)buf, 2, &sum, FALSE);

  /* Seed CUDP source port (16 bits) */
  pm_checksum ((u_int16_t *)&udphdr->uh_sport, sizeof (udphdr->uh_sport), &sum, FALSE);

  /* Seed UDP destination port (16 bits) */
  pm_checksum ((u_int16_t *)&udphdr->uh_dport, sizeof (udphdr->uh_dport), &sum, FALSE);

  /* Seed UDP length again (16 bits) */
  pm_checksum ((u_int16_t *)&udphdr->uh_ulen, sizeof (udphdr->uh_ulen), &sum, FALSE);

  /* Seed payload and take into account padding (16-bit boundary) */
  if (payload_len % 2) {
    pm_checksum ((u_int16_t *)payload, (payload_len - 1), &sum, FALSE);

    buf[0] = payload[payload_len];
    buf[1] = '\0';
    answer = pm_checksum ((u_int16_t *) buf, 2, &sum, TRUE);
  }
  else {
    answer = pm_checksum ((u_int16_t *)payload, payload_len, &sum, TRUE);
  }

  return answer;
}

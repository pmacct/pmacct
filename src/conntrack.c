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

#include "pmacct.h"
#include "addr.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "ip_flow.h"
#include "classifier.h"
#include "jhash.h"


/* Global variables */
struct conntrack_ipv4 *conntrack_ipv4_table;
struct conntrack_ipv6 *conntrack_ipv6_table;
u_int32_t conntrack_total_nodes_v4;
u_int32_t conntrack_total_nodes_v6;
struct conntrack_helper_entry __attribute__((unused)) conntrack_helper_list[4] = {
  { "ftp", conntrack_ftp_helper },
  { "sip", conntrack_sip_helper },
//  { "irc", conntrack_irc_helper },
  { "rtsp", conntrack_rtsp_helper },
  { "", NULL },
};

void init_conntrack_table()
{
  if (config.conntrack_bufsz) conntrack_total_nodes_v4 = config.conntrack_bufsz / sizeof(struct conntrack_ipv4);
  else conntrack_total_nodes_v4 = DEFAULT_CONNTRACK_BUFFER_SIZE / sizeof(struct conntrack_ipv4);
  conntrack_ipv4_table = NULL;

  if (config.conntrack_bufsz) conntrack_total_nodes_v6 = config.conntrack_bufsz / sizeof(struct conntrack_ipv6);
  else conntrack_total_nodes_v6 = DEFAULT_CONNTRACK_BUFFER_SIZE / sizeof(struct conntrack_ipv6);
  conntrack_ipv6_table = NULL;
}

void conntrack_ftp_helper(time_t now, struct packet_ptrs *pptrs)
{
  char *start = NULL, *end = NULL, *ptr;
  u_int16_t port[2];
  int len;

  if (!pptrs->payload_ptr) return;
  len = strlen((char *)pptrs->payload_ptr); 
 
  /* truncated payload */
  if (len < 4) return;

  /*  XXX: is it correct to assume that the commands are in the first 4 bytes of the payload ? */ 
  /* PORT/LPRT command, active FTP */
  if ((pptrs->payload_ptr[0] == 'P' && pptrs->payload_ptr[1] == 'O' &&
       pptrs->payload_ptr[2] == 'R' && pptrs->payload_ptr[3] == 'T') ||
      (pptrs->payload_ptr[0] == 'L' && pptrs->payload_ptr[1] == 'P' &&
       pptrs->payload_ptr[2] == 'R' && pptrs->payload_ptr[3] == 'T')) { 
    start = strchr((char *)pptrs->payload_ptr, ' ');
    end = strchr((char *)pptrs->payload_ptr, '\r'); 
    if (start && end) { 
      /* getting the port number */
      ptr = end;
      *end = '\0';
      while (*ptr != ',' && ptr > start) ptr--;
      port[1] = atoi(ptr+1);
      *end = '\r';

      end = ptr;
      *end = '\0';
      while (*ptr != ',' && ptr > start) ptr--;
      port[0] = atoi(ptr+1);
      *end = ',';

      if (pptrs->l3_proto == ETHERTYPE_IP) insert_conntrack_ipv4(now,
			((struct pm_iphdr *) pptrs->iph_ptr)->ip_src.s_addr,
                        ((struct pm_iphdr *) pptrs->iph_ptr)->ip_dst.s_addr,
                        port[0]*256+port[1], 0, IPPROTO_TCP, pptrs->class,
			NULL, CONNTRACK_GENERIC_LIFETIME);
      else if (pptrs->l3_proto == ETHERTYPE_IPV6) insert_conntrack_ipv6(now,
                        &((struct ip6_hdr *) pptrs->iph_ptr)->ip6_src,
                        &((struct ip6_hdr *) pptrs->iph_ptr)->ip6_dst,
                        port[0]*256+port[1], 0, IPPROTO_TCP, pptrs->class,
			NULL, CONNTRACK_GENERIC_LIFETIME);
    }
  }
  /* 227/228 reply, passive (PASV/LPASV) FTP */
  else if ((pptrs->payload_ptr[0] == '2' && pptrs->payload_ptr[1] == '2' &&
	    pptrs->payload_ptr[2] == '7' && pptrs->payload_ptr[3] == ' ') ||
	   (pptrs->payload_ptr[0] == '2' && pptrs->payload_ptr[1] == '2' &&
            pptrs->payload_ptr[2] == '8' && pptrs->payload_ptr[3] == ' ')) {
    start = strchr((char *)pptrs->payload_ptr, '(');
    end = strchr((char *)pptrs->payload_ptr, ')'); 
    if (start && end) { 
      /* getting the port number */
      ptr = end;
      *end = '\0';
      while (*ptr != ',' && ptr > start) ptr--; 
      port[1] = atoi(ptr+1);
      *end = ')';

      end = ptr;
      *end = '\0';
      while (*ptr != ',' && ptr > start) ptr--; 
      port[0] = atoi(ptr+1);
      *end = ',';

      if (pptrs->l3_proto == ETHERTYPE_IP) insert_conntrack_ipv4(now,
			((struct pm_iphdr *) pptrs->iph_ptr)->ip_src.s_addr,
			((struct pm_iphdr *) pptrs->iph_ptr)->ip_dst.s_addr,
			port[0]*256+port[1], 0, IPPROTO_TCP, pptrs->class,
			NULL, CONNTRACK_GENERIC_LIFETIME);
      else if (pptrs->l3_proto == ETHERTYPE_IPV6) insert_conntrack_ipv6(now,
                        &((struct ip6_hdr *) pptrs->iph_ptr)->ip6_src,
                        &((struct ip6_hdr *) pptrs->iph_ptr)->ip6_dst,
                        port[0]*256+port[1], 0, IPPROTO_TCP, pptrs->class,
			NULL, CONNTRACK_GENERIC_LIFETIME);
    }
  }
  /* EPRT command, Extended data port */
  else if (pptrs->payload_ptr[0] == 'E' && pptrs->payload_ptr[1] == 'P' &&
	pptrs->payload_ptr[2] == 'R' && pptrs->payload_ptr[3] == 'T') {
    start = strchr((char *)pptrs->payload_ptr, ' ');
    end = strchr((char *)pptrs->payload_ptr, '\r');
    if (start && end) {
      /* getting the port number */
      while (*end != '|' && end >= start) end--;
      if (*end != '|') return;

      ptr = end;
      *end = '\0';

      while (*ptr != '|' && ptr >= start) ptr--;
      if (*ptr != '|') return;

      port[0] = atoi(ptr+1);
      *end = '|';

      if (pptrs->l3_proto == ETHERTYPE_IP) insert_conntrack_ipv4(now,
			((struct pm_iphdr *) pptrs->iph_ptr)->ip_src.s_addr,
                        ((struct pm_iphdr *) pptrs->iph_ptr)->ip_dst.s_addr,
                        port[0], 0, IPPROTO_TCP, pptrs->class, NULL,
			CONNTRACK_GENERIC_LIFETIME);
      else if (pptrs->l3_proto == ETHERTYPE_IPV6) insert_conntrack_ipv6(now,
                        &((struct ip6_hdr *) pptrs->iph_ptr)->ip6_src,
                        &((struct ip6_hdr *) pptrs->iph_ptr)->ip6_dst,
                        port[0], 0, IPPROTO_TCP, pptrs->class, NULL,
			CONNTRACK_GENERIC_LIFETIME);
    }
  }
  /* 229 reply, extended passive (EPASV) FTP */
  else if (pptrs->payload_ptr[0] == '2' && pptrs->payload_ptr[1] == '2' &&
	pptrs->payload_ptr[2] == '9' && pptrs->payload_ptr[3] == ' ') {
    start = strchr((char *)pptrs->payload_ptr, '(');
    end = strchr((char *)pptrs->payload_ptr, ')');
    if (start && end) {
      /* getting the port number */
      while (*end != '|' && end >= start) end--;
      if (*end != '|') return;

      ptr = end;
      *end = '\0';

      while (*ptr != '|' && ptr >= start) ptr--;
      if (*ptr != '|') return;

      port[0] = atoi(ptr+1);
      *end = '|';

      if (pptrs->l3_proto == ETHERTYPE_IP) insert_conntrack_ipv4(now,
		        ((struct pm_iphdr *) pptrs->iph_ptr)->ip_src.s_addr,
                        ((struct pm_iphdr *) pptrs->iph_ptr)->ip_dst.s_addr,
                        port[0], 0, IPPROTO_TCP, pptrs->class, NULL,
			CONNTRACK_GENERIC_LIFETIME);
      else if (pptrs->l3_proto == ETHERTYPE_IPV6) insert_conntrack_ipv6(now,
                        &((struct ip6_hdr *) pptrs->iph_ptr)->ip6_src,
                        &((struct ip6_hdr *) pptrs->iph_ptr)->ip6_dst,
                        port[0], 0, IPPROTO_TCP, pptrs->class, NULL,
			CONNTRACK_GENERIC_LIFETIME);
    }
  }
}

void conntrack_rtsp_helper(time_t now, struct packet_ptrs *pptrs)
{
  char *start = NULL, *end = NULL, *ptr;
  u_int16_t port[2];
  int x = 0, len;

  port[0] = 0;
  port[1] = 0;

  if (!pptrs->payload_ptr) return;
  len = strlen((char *)pptrs->payload_ptr);

  /* truncated payload */
  if (len < 6) return;

  /* We need to look into RTSP SETUP messages */ 
  if ( !strncmp((char *)pptrs->payload_ptr, "SETUP ", 6) ) {
    start = strchr((char *)pptrs->payload_ptr, '\n');
    end = (char *)(pptrs->payload_ptr + len);

    while (start && start < end) { 
      start++;

      /* Then, we need to look into the Transport: line */
      if ( !strncmp(start, "Transport:", 10) ) {
	if ((ptr = strchr(start, '\r'))) end = ptr;
	ptr = strchr(start, ':');
	ptr++;

	while (ptr && ptr < end) {
	  ptr++;

	  /* Then, we need to search for the client_port= key */ 
	  if ( !strncmp(ptr, "client_port=", 12) ) {
	    char *ss_start, *ss_sep, *ss_end;

	    ss_end = strchr(ptr, ';');
	    /* If we are unable to find the trailing separator, lets return */
	    if (!ss_end) return;
	    ss_start = strchr(ptr, '='); 
	    ss_start++;
	    *ss_end = '\0';

	    /* We have reached the client_port info; let's handle it meaningfully:
	       we expect either a single port or a range of ports (lo-hi) */ 
	    if ((ss_sep = strchr(ss_start, '-'))) {
	      *ss_sep = '\0'; 
	      port[0] = atoi(ss_start);
	      *ss_sep = '-';
	      port[1] = atoi(ss_sep+1); 
	    }
	    else {
	      port[0] = atoi(ss_start);
	      port[1] = port[0];
	    }
	    *ss_end = ';';

	    for (x = port[0]; x <= port[1]; x++) { 
	      if (pptrs->l3_proto == ETHERTYPE_IP) insert_conntrack_ipv4(now,
			((struct pm_iphdr *) pptrs->iph_ptr)->ip_src.s_addr,
			((struct pm_iphdr *) pptrs->iph_ptr)->ip_dst.s_addr,
			x, 0, IPPROTO_UDP, pptrs->class, NULL, CONNTRACK_GENERIC_LIFETIME);
	      else if (pptrs->l3_proto == ETHERTYPE_IPV6) insert_conntrack_ipv6(now,
			&((struct ip6_hdr *) pptrs->iph_ptr)->ip6_src,
			&((struct ip6_hdr *) pptrs->iph_ptr)->ip6_dst,
			x, 0, IPPROTO_UDP, pptrs->class, NULL, CONNTRACK_GENERIC_LIFETIME);
	    }
	  } 
	  else ptr = strchr(ptr, ';');
	}
      }
      else start = strchr(start, '\n'); 
    }
  }
}

void conntrack_sip_helper(time_t now, struct packet_ptrs *pptrs)
{
  char *start = NULL, *end = NULL, *ptr;
  u_int16_t port;
  int len;

  if (!pptrs->payload_ptr) return;
  len = strlen((char *)pptrs->payload_ptr);

  /* truncated payload */
  if (len < 11) return;

  /* We need to look into SIP INVITE messages */
  if ( !strncmp((char *)pptrs->payload_ptr, "INVITE ", 7) || 
       !strncmp((char *)pptrs->payload_ptr, "SIP/2.0 200", 11) ) {
    /* We are searching for the m= line */
    for ( start = (char *)pptrs->payload_ptr, end = (char *)(pptrs->payload_ptr + len);
	  start && start < end; start = strchr(start, '\n') ) { 
      start++;
      if ( !strncmp(start, "m=", 2) ) {
	end = strchr(start, '\r');
	break;
      }
    }
    if (!start || !end) return;
    
    ptr = start;
    while (*ptr != ' ' && ptr < end) ptr++; 
    if (*ptr != ' ') return;
    while (*ptr == ' ' && ptr < end) ptr++;
    if (ptr == end) return;
    start = ptr;
    while (*ptr != ' ' && ptr < end) ptr++;
    if (ptr == end) return;
    *ptr = '\0';
    port = atoi(start);
    *ptr = ' ';

    if (pptrs->l3_proto == ETHERTYPE_IP) insert_conntrack_ipv4(now,
			((struct pm_iphdr *) pptrs->iph_ptr)->ip_src.s_addr,
			((struct pm_iphdr *) pptrs->iph_ptr)->ip_dst.s_addr,
			port, 0, IPPROTO_UDP, pptrs->class, NULL,
			CONNTRACK_GENERIC_LIFETIME);
    else if (pptrs->l3_proto == ETHERTYPE_IPV6) insert_conntrack_ipv6(now,
			&((struct ip6_hdr *) pptrs->iph_ptr)->ip6_src,
			&((struct ip6_hdr *) pptrs->iph_ptr)->ip6_dst,
			port, 0, IPPROTO_UDP, pptrs->class, NULL,
			CONNTRACK_GENERIC_LIFETIME);
  }
}

void conntrack_irc_helper(time_t now, struct packet_ptrs *pptrs)
{
/*
  while (isprint(pptrs->payload_ptr[x]) || isspace(pptrs->payload_ptr[x])) {
    printf("%c", pptrs->payload_ptr[x]);
    x++;
  }
  printf("\n\n");
*/
}

void insert_conntrack_ipv4(time_t now, u_int32_t ip_src, u_int32_t ip_dst,
			   u_int16_t port_src, u_int16_t port_dst, u_int8_t proto,
			   pm_class_t class, conntrack_helper helper, time_t exp)
{
  int size = sizeof(struct conntrack_ipv4);
  struct conntrack_ipv4 *ct_elem;

  if (conntrack_ipv4_table) {
    ct_elem = conntrack_ipv4_table;
    while (ct_elem->next && now < ct_elem->stamp+ct_elem->expiration)
      ct_elem = ct_elem->next;

    /* no entry expired and we reached the tail: let's allocate a new one */ 
    if (now < ct_elem->stamp+ct_elem->expiration && !ct_elem->next) {
      if (conntrack_total_nodes_v4) {
        ct_elem->next = malloc(size);
        ct_elem->next->next = NULL;
        ct_elem = ct_elem->next;
	conntrack_total_nodes_v4--;
      }
      else {
	Log(LOG_INFO, "INFO ( %s/core ): Conntrack/4 buffer full. Skipping packet.\n", config.name);
	return;
      }
    }
  }
  /* let's allocate our first element */
  else {
    conntrack_ipv4_table = malloc(size);
    ct_elem = conntrack_ipv4_table;
    ct_elem->next = NULL;
  }

  ct_elem->ip_src = ip_src;
  ct_elem->ip_dst = ip_dst;
  ct_elem->port_src = port_src;
  ct_elem->port_dst = port_dst;
  ct_elem->proto = proto;
  ct_elem->class = class;
  ct_elem->stamp = now;
  ct_elem->helper = helper;
  ct_elem->expiration = exp;
}

void search_conntrack(struct ip_flow_common *fp, struct packet_ptrs *pptrs, unsigned int idx)
{
  if (pptrs->l3_proto == ETHERTYPE_IP) search_conntrack_ipv4(fp, pptrs, idx); 
  else if (pptrs->l3_proto == ETHERTYPE_IPV6) search_conntrack_ipv6(fp, pptrs, idx); 
}

void search_conntrack_ipv4(struct ip_flow_common *fp, struct packet_ptrs *pptrs, unsigned int idx)
{
  struct conntrack_ipv4 *ct_elem = conntrack_ipv4_table, *aux = NULL;
  struct pm_iphdr *iphp = (struct pm_iphdr *)pptrs->iph_ptr;
  struct pm_tlhdr *tlhp = (struct pm_tlhdr *)pptrs->tlh_ptr;

  if (!conntrack_ipv4_table) return;

  while (ct_elem) {
/*
    if (fp->last[idx] < ct_elem->stamp+CONNTRACK_GENERIC_LIFETIME) {
      printf("IP SRC: %x %x\n", iphp->ip_src.s_addr, ct_elem->ip_src);
      printf("IP DST: %x %x\n", iphp->ip_dst.s_addr, ct_elem->ip_dst);
      printf("SRC PORT: %u %u\n", ntohs(tlhp->src_port), ct_elem->port_src);
      printf("DST PORT: %u %u\n", ntohs(tlhp->dst_port), ct_elem->port_dst);
      printf("IP PROTO: %u %u\n", pptrs->l4_proto, ct_elem->proto);
    }
*/

    /* conntrack entries usually have incomplete informations about the upcoming
       data channels; missing primitives are to be considered always true; then,
       we assure a) full match on the remaining primitives and b) our conntrack
       entry has not been aged out. */
    if (fp->last[idx].tv_sec < ct_elem->stamp+ct_elem->expiration &&
	(ct_elem->ip_src ? iphp->ip_src.s_addr == ct_elem->ip_src : 1) &&
	(ct_elem->ip_dst ? iphp->ip_dst.s_addr == ct_elem->ip_dst : 1) &&
	(ct_elem->proto ? pptrs->l4_proto == ct_elem->proto : 1) && 
	(ct_elem->port_src ? ntohs(tlhp->src_port) == ct_elem->port_src : 1) &&
	(ct_elem->port_dst ? ntohs(tlhp->dst_port) == ct_elem->port_dst : 1)) {

      fp->class[0] = ct_elem->class;
      fp->class[1] = ct_elem->class;
      fp->conntrack_helper = ct_elem->helper;
      ct_elem->stamp = 0;

      /* no aux means we are facing the first element in the chain */
      if (aux) aux->next = ct_elem->next;
      else conntrack_ipv4_table = ct_elem->next;
      free(ct_elem);

      return;
    }

    aux = ct_elem;
    ct_elem = ct_elem->next;
  }
}

void insert_conntrack_ipv6(time_t now, struct in6_addr *ip_src, struct in6_addr *ip_dst,
                           u_int16_t port_src, u_int16_t port_dst, u_int8_t proto,
                           pm_class_t class, conntrack_helper helper, time_t exp)
{
  int size = sizeof(struct conntrack_ipv4);
  struct conntrack_ipv6 *ct_elem;

  if (conntrack_ipv6_table) {
    ct_elem = conntrack_ipv6_table;
    while (ct_elem->next && now < ct_elem->stamp+ct_elem->expiration)
      ct_elem = ct_elem->next;

    /* no entry expired and we reached the tail: let's allocate a new one */
    if (now < ct_elem->stamp+ct_elem->expiration && !ct_elem->next) {
      if (conntrack_total_nodes_v6) {
	ct_elem->next = malloc(size);
	ct_elem->next->next = NULL;
	ct_elem = ct_elem->next;
	conntrack_total_nodes_v6--;
      }
      else {
        Log(LOG_INFO, "INFO ( %s/core ): Conntrack/6 buffer full. Skipping packet.\n", config.name);
        return;
      }
    }
  }
  /* let's allocate our first element */
  else {
    conntrack_ipv6_table = malloc(size);
    ct_elem = conntrack_ipv6_table;
    ct_elem->next = NULL;
  }

  memcpy(&ct_elem->ip_src, ip_src, IP6AddrSz);
  memcpy(&ct_elem->ip_dst, ip_dst, IP6AddrSz);
  ct_elem->port_src = port_src;
  ct_elem->port_dst = port_dst;
  ct_elem->proto = proto;
  ct_elem->class = class;
  ct_elem->stamp = now;
  ct_elem->helper = helper;
  ct_elem->expiration = exp;
}

void search_conntrack_ipv6(struct ip_flow_common *fp, struct packet_ptrs *pptrs, unsigned int idx)
{
  struct conntrack_ipv6 *ct_elem = conntrack_ipv6_table, *aux = NULL;
  struct ip6_hdr *iphp = (struct ip6_hdr *)pptrs->iph_ptr;
  struct pm_tlhdr *tlhp = (struct pm_tlhdr *)pptrs->tlh_ptr;

  if (!conntrack_ipv6_table) return;

  while (ct_elem) {
    /* conntrack entries usually have incomplete informations about the upcoming
       data channels; missing primitives are to be considered always true; then,
       we assure a) full match on the remaining primitives and b) our conntrack
       entry has not been aged out. */
    if (fp->last[idx].tv_sec < ct_elem->stamp+ct_elem->expiration &&
        (ct_elem->ip_src[0] ? !ip6_addr_cmp(&iphp->ip6_src, &ct_elem->ip_src) : 1) &&
        (ct_elem->ip_dst[0] ? !ip6_addr_cmp(&iphp->ip6_dst, &ct_elem->ip_dst) : 1) &&
        (ct_elem->proto ? pptrs->l4_proto == ct_elem->proto : 1) &&
        (ct_elem->port_src ? ntohs(tlhp->src_port) == ct_elem->port_src : 1) &&
        (ct_elem->port_dst ? ntohs(tlhp->dst_port) == ct_elem->port_dst : 1)) {

      fp->class[0] = ct_elem->class;
      fp->class[1] = ct_elem->class;
      fp->conntrack_helper = ct_elem->helper;
      ct_elem->stamp = 0;

      /* no aux means we are facing the first element in the chain */
      if (aux) aux->next = ct_elem->next;
      else conntrack_ipv6_table = ct_elem->next;
      free(ct_elem);

      return;
    }

    aux = ct_elem;
    ct_elem = ct_elem->next;
  }
}

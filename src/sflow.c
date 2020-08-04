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
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* 
    sflow v2/v4/v5 routines are based on sFlow toolkit 3.8 and later which
    is Copyright (C) InMon Corporation 2001 ALL RIGHTS RESERVED
*/

/* includes */
#include "pmacct.h"
#include "addr.h"
#include "sflow.h"
#include "bgp/bgp.h"
#include "sfacctd.h"
#include "sfv5_module.h"
#include "ip_flow.h"
#include "ip_frag.h"
#include "classifier.h"
#include "pmacct-data.h"
#include "crc32.h"

/*_________________---------------------------__________________
  _________________    lengthCheck            __________________
  -----------------___________________________------------------
*/

int lengthCheck(SFSample *sample, u_char *start, u_int32_t len)
{
  u_int32_t actualLen = (u_char *)sample->datap - start;
  if (actualLen != len) {
    /* XXX: notify length mismatch */ 
    return ERR;
  }

  return FALSE;
}

/*_________________---------------------------__________________
  _________________     decodeLinkLayer       __________________
  -----------------___________________________------------------
  store the offset to the start of the ipv4 header in the sequence_number field
  or -1 if not found. Decode the 802.1d if it's there.
*/

#define NFT_ETHHDR_SIZ 14
#define NFT_8022_SIZ 3
#define NFT_MAX_8023_LEN 1500

void decodeLinkLayer(SFSample *sample)
{
  u_char *start = (u_char *)sample->header;
  u_char *end = start + sample->headerLen;
  u_char *ptr = start;
  u_int16_t caplen = end - (u_char *)sample->datap;

  /* assume not found */
  sample->gotIPV4 = FALSE;
  sample->gotIPV6 = FALSE;

  if (caplen < NFT_ETHHDR_SIZ) return; /* not enough for an Ethernet header */
  caplen -= NFT_ETHHDR_SIZ;

  memcpy(sample->eth_dst, ptr, 6);
  ptr += 6;

  memcpy(sample->eth_src, ptr, 6);
  ptr += 6;
  sample->eth_type = (ptr[0] << 8) + ptr[1];
  ptr += 2;

  if (sample->eth_type == ETHERTYPE_8021Q) {
    /* VLAN  - next two bytes */
    u_int32_t vlanData = (ptr[0] << 8) + ptr[1];
    u_int32_t vlan = vlanData & 0x0fff;
    u_int32_t priority = vlanData >> 13;

    if (caplen < 2) return;

    ptr += 2;
    /*  _____________________________________ */
    /* |   pri  | c |         vlan-id        | */
    /*  ------------------------------------- */
    /* [priority = 3bits] [Canonical Format Flag = 1bit] [vlan-id = 12 bits] */
    if (!sample->in_vlan && !sample->out_vlan) sample->in_vlan = vlan;
    if (!sample->in_priority && !sample->out_priority) sample->in_priority = priority;
    sample->eth_type = (ptr[0] << 8) + ptr[1];

    ptr += 2;
    caplen -= 2;
  }

  if (sample->eth_type <= NFT_MAX_8023_LEN) {
    /* assume 802.3+802.2 header */
    if (caplen < 8) return;

    /* check for SNAP */
    if(ptr[0] == 0xAA &&
       ptr[1] == 0xAA &&
       ptr[2] == 0x03) {
      ptr += 3;
      if(ptr[0] != 0 ||
	 ptr[1] != 0 ||
	 ptr[2] != 0) {
	return; /* no further decode for vendor-specific protocol */
      }
      ptr += 3;
      /* OUI == 00-00-00 means the next two bytes are the ethernet type (RFC 2895) */
      sample->eth_type = (ptr[0] << 8) + ptr[1];
      ptr += 2;
      caplen -= 8;
    }
    else {
      if (ptr[0] == 0x06 &&
	  ptr[1] == 0x06 &&
	  (ptr[2] & 0x01)) {
	/* IP over 8022 */
	ptr += 3;
	/* force the eth_type to be IP so we can inline the IP decode below */
	sample->eth_type = ETHERTYPE_IP;
	caplen -= 3;
      }
      else return;
    }
  }

  if (sample->eth_type == ETHERTYPE_MPLS || sample->eth_type == ETHERTYPE_MPLS_MULTI) {
    decodeMpls(sample, &ptr);
    caplen -= sample->lstk.depth * 4;
  }

  if (sample->eth_type == ETHERTYPE_IP) {
    sample->gotIPV4 = TRUE;
    sample->offsetToIPV4 = (ptr - start);
  }

  if (sample->eth_type == ETHERTYPE_IPV6) {
    sample->gotIPV6 = TRUE;
    sample->offsetToIPV6 = (ptr - start);
  }
}


/*_________________---------------------------__________________
  _________________     decodeIPLayer4        __________________
  -----------------___________________________------------------
*/

void decodeIPLayer4(SFSample *sample, u_char *ptr, u_int32_t ipProtocol)
{
  u_char *end = sample->header + sample->headerLen;
  if(ptr > (end - 8)) return; // not enough header bytes left
  switch(ipProtocol) {
  case 1: /* ICMP */
    {
      struct SF_icmphdr icmp;
      memcpy(&icmp, ptr, sizeof(icmp));
      sample->dcd_sport = icmp.type;
      sample->dcd_dport = icmp.code;
    }
    break;
  case 6: /* TCP */
    {
      struct SF_tcphdr tcp;
      memcpy(&tcp, ptr, sizeof(tcp));
      sample->dcd_sport = ntohs(tcp.th_sport);
      sample->dcd_dport = ntohs(tcp.th_dport);
      sample->dcd_tcpFlags = tcp.th_flags;
      if(sample->dcd_dport == 80) {
	int headerBytes = (tcp.th_off_and_unused >> 4) * 4;
	ptr += headerBytes;
      }
    }
    break;
  case 17: /* UDP */
    {
      struct SF_udphdr udp;
      memcpy(&udp, ptr, sizeof(udp));
      sample->dcd_sport = ntohs(udp.uh_sport);
      sample->dcd_dport = ntohs(udp.uh_dport);
      sample->udp_pduLen = ntohs(udp.uh_ulen);

      if (sample->dcd_dport == UDP_PORT_VXLAN) {
	ptr += sizeof(udp);
	decodeVXLAN(sample, ptr);
      }
    }
    break;
  default: /* some other protcol */
    break;
  }
}

void decodeVXLAN(SFSample *sample, u_char *ptr)
{
  struct vxlan_hdr *hdr = NULL;
  u_char *vni_ptr = NULL;
  u_int32_t vni;
  u_char *end = sample->header + sample->headerLen;

  if (ptr > (end - 8)) return;

  hdr = (struct vxlan_hdr *) ptr;

  if (hdr->flags & VXLAN_FLAG_I) {
    vni_ptr = hdr->vni;

    /* decode 24-bit label */
    vni = *vni_ptr++;
    vni <<= 8;
    vni += *vni_ptr++;
    vni <<= 8;
    vni += *vni_ptr++;

    sample->vni = vni;
    ptr += sizeof(struct vxlan_hdr);

    if (sample->sppi) {
      SFSample *sppi = (SFSample *) sample->sppi;

      /* preps */
      sppi->datap = (u_int32_t *) ptr;
      sppi->header = ptr;
      sppi->headerLen = (end - ptr);

      /* decoding inner packet */
      decodeLinkLayer(sppi);
      if (sppi->gotIPV4) decodeIPV4(sppi);
      else if (sppi->gotIPV6) decodeIPV6(sppi);
    }
  }
}

/*_________________---------------------------__________________
  _________________     decodeIPV4            __________________
  -----------------___________________________------------------
*/

void decodeIPV4(SFSample *sample)
{
  if (sample->gotIPV4) {
    u_char *end = sample->header + sample->headerLen;
    u_char *ptr = sample->header + sample->offsetToIPV4;
    u_int16_t caplen = end - ptr;

    /* Create a local copy of the IP header (cannot overlay structure in case it is not quad-aligned...some
       platforms would core-dump if we tried that).  It's OK coz this probably performs just as well anyway. */
    struct SF_iphdr ip;

    if (caplen < IP4HdrSz) return; 

    memcpy(&ip, ptr, sizeof(ip));
    /* Value copy all ip elements into sample */
    sample->dcd_srcIP.s_addr = ip.saddr;
    sample->dcd_dstIP.s_addr = ip.daddr;
    sample->dcd_ipProtocol = ip.protocol;
    sample->dcd_ipTos = ip.tos;
    sample->dcd_ipTTL = ip.ttl;
    /* check for fragments */
    sample->ip_fragmentOffset = ntohs(ip.frag_off) & 0x1FFF;
    if (sample->ip_fragmentOffset == 0) {
      /* advance the pointer to the next protocol layer */
      /* ip headerLen is expressed as a number of quads */
      ptr += (ip.version_and_headerLen & 0x0f) * 4;

      if (ip.protocol == 4 /* ipencap */ || ip.protocol == 94 /* ipip */) {
	if (sample->sppi) {
	  SFSample *sppi = (SFSample *) sample->sppi;

	  /* preps */
	  sppi->datap = (u_int32_t *) ptr;
	  sppi->header = ptr;
	  sppi->headerLen = (end - ptr);
	  sppi->offsetToIPV4 = 0;
	  sppi->gotIPV4 = TRUE;

	  decodeIPV4(sppi);
	}
      }
      else decodeIPLayer4(sample, ptr, ip.protocol);
    }
  }
}

/*_________________---------------------------__________________
  _________________     decodeIPV6            __________________
  -----------------___________________________------------------
*/

void decodeIPV6(SFSample *sample)
{
  u_int32_t label;
  u_int32_t nextHeader;
  u_char *end = sample->header + sample->headerLen;

  if(sample->gotIPV6) {
    u_char *ptr = sample->header + sample->offsetToIPV6;
    u_int16_t caplen = end - ptr;

    if (caplen < IP6HdrSz) return;
    
    // check the version
    {
      int ipVersion = (*ptr >> 4);
      if(ipVersion != 6) return;
    }

    // get the tos (priority)
    sample->dcd_ipTos = *ptr++ & 15;
    // 24-bit label
    label = *ptr++;
    label <<= 8;
    label += *ptr++;
    label <<= 8;
    label += *ptr++;
    // payload
    ptr += 2;
    // if payload is zero, that implies a jumbo payload

    // next header
    nextHeader = *ptr++;

    // TTL
    sample->dcd_ipTTL = *ptr++;

    {// src and dst address
      sample->ipsrc.type = SFLADDRESSTYPE_IP_V6;
      memcpy(&sample->ipsrc.address, ptr, 16);
      ptr +=16;
      sample->ipdst.type = SFLADDRESSTYPE_IP_V6;
      memcpy(&sample->ipdst.address, ptr, 16);
      ptr +=16;
    }

    // skip over some common header extensions...
    // http://searchnetworking.techtarget.com/originalContent/0,289142,sid7_gci870277,00.html
    while(nextHeader == 0 ||  // hop
	  nextHeader == 43 || // routing
	  nextHeader == 44 || // fragment
	  // nextHeader == 50 || // encryption - don't bother coz we'll not be able to read any further
	  nextHeader == 51 || // auth
	  nextHeader == 60) { // destination options
      u_int32_t optionLen, skip;
      nextHeader = ptr[0];
      optionLen = 8 * (ptr[1] + 1);  // second byte gives option len in 8-byte chunks, not counting first 8
      skip = optionLen - 2;
      ptr += skip;
      if(ptr > end) return; // ran off the end of the header
    }
    
    // now that we have eliminated the extension headers, nextHeader should have what we want to
    // remember as the ip protocol...
    sample->dcd_ipProtocol = nextHeader;

    if (sample->dcd_ipProtocol == 4 /* ipencap */ || sample->dcd_ipProtocol == 94 /* ipip */) {
      if (sample->sppi) {
	SFSample *sppi = (SFSample *) sample->sppi;

	/* preps */
	sppi->datap = (u_int32_t *) ptr;
	sppi->header = ptr;
	sppi->headerLen = (end - ptr);
	sppi->offsetToIPV4 = 0;
	sppi->gotIPV4 = TRUE;

	decodeIPV4(sppi);
      }
    }
    else decodeIPLayer4(sample, ptr, sample->dcd_ipProtocol);
  }
}

/*_________________---------------------------__________________
  _________________   read data fns           __________________
  -----------------___________________________------------------
*/

char *getPointer(SFSample *sample)
{
  if ((u_char *)sample->datap > sample->endp) return NULL;
  return (char *)sample->datap;
}

u_int32_t getData32(SFSample *sample) 
{
  if ((u_char *)sample->datap > sample->endp) return 0; 
  return ntohl(*(sample->datap)++);
}

u_int32_t getData32_nobswap(SFSample *sample) 
{
  if ((u_char *)sample->datap > sample->endp) return 0;
  return *(sample->datap)++;
}

u_int64_t getData64(SFSample *sample)
{
  u_int64_t tmpLo, tmpHi;
  tmpHi = getData32(sample);
  tmpLo = getData32(sample);
  return (tmpHi << 32) + tmpLo;
}

void skipBytes(SFSample *sample, int skip)
{
  int quads = (skip + 3) / 4;

  sample->datap += quads;
  // if((u_char *)sample->datap > sample->endp) return 0; 
}

int skipBytesAndCheck(SFSample *sample, int skip)
{
  int quads = (skip + 3) / 4;

  if ((u_char *)(sample->datap + quads) <= sample->endp) {
    sample->datap += quads;
    return quads;
  }
  else return ERR;
}

u_int32_t getString(SFSample *sample, char *buf, u_int32_t bufLen)
{
  u_int32_t len, read_len;
  len = getData32(sample);
  // truncate if too long
  read_len = (len >= bufLen) ? (bufLen - 1) : len;
  memcpy(buf, sample->datap, read_len);
  buf[read_len] = '\0';   // null terminate
  skipBytes(sample, len);
  return len;
}

u_int32_t getAddress(SFSample *sample, SFLAddress *address)
{
  address->type = getData32(sample);
  if(address->type == SFLADDRESSTYPE_IP_V4)
    address->address.ip_v4.s_addr = getData32_nobswap(sample);
  else {
    memcpy(address->address.ip_v6.s6_addr, sample->datap, 16);
    skipBytes(sample, 16);
  }
  return address->type;
}

char *printTag(u_int32_t tag, char *buf, int bufLen) {
  // should really be: snprintf(buf, buflen,...) but snprintf() is not always available
  sprintf(buf, "%lu:%lu", (unsigned long)(tag >> 12), (unsigned long)(tag & 0x00000FFF));
  return buf;
}

/*_________________---------------------------__________________
  _________________    readExtendedSwitch     __________________
  -----------------___________________________------------------
*/

void readExtendedSwitch(SFSample *sample)
{
  sample->in_vlan = getData32(sample);
  sample->in_priority = getData32(sample);
  sample->out_vlan = getData32(sample);
  sample->out_priority = getData32(sample);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_SWITCH;
}

/*_________________---------------------------__________________
  _________________    readExtendedRouter     __________________
  -----------------___________________________------------------
*/

void readExtendedRouter(SFSample *sample)
{
  getAddress(sample, &sample->nextHop);
  sample->srcMask = getData32(sample);
  sample->dstMask = getData32(sample);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_ROUTER;
}

/*_________________---------------------------__________________
  _________________  readExtendedGateway_v2   __________________
  -----------------___________________________------------------
*/

void readExtendedGateway_v2(SFSample *sample)
{
  sample->my_as = getData32(sample);
  sample->src_as = getData32(sample);
  sample->src_peer_as = getData32(sample);
  sample->dst_as_path_len = getData32(sample);
  /* just point at the dst_as_path array */
  if(sample->dst_as_path_len > 0) {
    // sample->dst_as_path = sample->datap;
    /* and skip over it in the input */
    skipBytes(sample, sample->dst_as_path_len * 4);
    // fill in the dst and dst_peer fields too
    sample->dst_peer_as = ntohl(sample->dst_as_path[0]);
    sample->dst_as = ntohl(sample->dst_as_path[sample->dst_as_path_len - 1]);
  }
  
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_GATEWAY;
}

/*_________________---------------------------__________________
  _________________  readExtendedGateway      __________________
  -----------------___________________________------------------
*/

void readExtendedGateway(SFSample *sample)
{
  u_int32_t len_tot, len_asn, len_comm, idx;
  char asn_str[MAX_BGP_ASPATH], comm_str[MAX_BGP_STD_COMMS], space[] = " ";

  if(sample->datagramVersion >= 5) getAddress(sample, &sample->bgp_nextHop);

  sample->my_as = getData32(sample);
  sample->src_as = getData32(sample);
  sample->src_peer_as = getData32(sample);
  sample->dst_as_path_len = getData32(sample);
  if (sample->dst_as_path_len > 0) {
    for (idx = 0, len_tot = 0; idx < sample->dst_as_path_len; idx++) {
      u_int32_t seg_len, i;

      getData32(sample); /* seg_type */
      seg_len = getData32(sample);

      for (i = 0; i < seg_len; i++) {
	u_int32_t asNumber;

	asNumber = getData32(sample);
	snprintf(asn_str, MAX_BGP_ASPATH-1, "%u", asNumber);
        len_asn = strlen(asn_str);
	len_tot = strlen(sample->dst_as_path);

        if ((len_tot+len_asn) < LARGEBUFLEN) {
          strncat(sample->dst_as_path, asn_str, (sizeof(sample->dst_as_path) - len_tot));
        }
        else {
          sample->dst_as_path[LARGEBUFLEN-2] = '+';
          sample->dst_as_path[LARGEBUFLEN-1] = '\0';
        }

	/* mark the first one as the dst_peer_as */
	if(i == 0 && idx == 0) sample->dst_peer_as = asNumber;

	/* mark the last one as the dst_as */
	if (idx == (sample->dst_as_path_len - 1) && i == (seg_len - 1)) sample->dst_as = asNumber;
        else {
          if (strlen(sample->dst_as_path) < (LARGEBUFLEN-1))
            strncat(sample->dst_as_path, space, 1);
        }
      }
    }
  }
  else sample->dst_as_path[0] = '\0';

  sample->communities_len = getData32(sample);
  /* just point at the communities array */
  if (sample->communities_len > 0) {
    for (idx = 0, len_tot = 0; idx < sample->communities_len; idx++) {
      u_int32_t comm, as, val;

      comm = getData32(sample);
      switch (comm) {
      case COMMUNITY_INTERNET:
        strcpy(comm_str, "internet");
        break;
      case COMMUNITY_NO_EXPORT:
        strcpy(comm_str, "no-export");
        break;
      case COMMUNITY_NO_ADVERTISE:
        strcpy (comm_str, "no-advertise");
        break;
      case COMMUNITY_LOCAL_AS:
        strcpy (comm_str, "local-AS");
        break;
      default:
        as = (comm >> 16) & 0xFFFF;
        val = comm & 0xFFFF;
        sprintf(comm_str, "%d:%d", as, val);
        break;
      }
      len_comm = strlen(comm_str);
      len_tot = strlen(sample->comms);

      if ((len_tot+len_comm) < LARGEBUFLEN) {
        strncat(sample->comms, comm_str, (sizeof(sample->comms) - len_tot));
      }
      else {
        sample->comms[LARGEBUFLEN-2] = '+';
        sample->comms[LARGEBUFLEN-1] = '\0';
      }

      if (idx < (sample->communities_len - 1)) {
        if (strlen(sample->comms) < (LARGEBUFLEN-1))
          strncat(sample->comms, space, 1);
      }
    }
  }
  else sample->comms[0] = '\0';

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_GATEWAY;
  sample->localpref = getData32(sample);
}

/*_________________---------------------------__________________
  _________________    readExtendedUser       __________________
  -----------------___________________________------------------
*/

void readExtendedUser(SFSample *sample)
{
  if(sample->datagramVersion >= 5) sample->src_user_charset = getData32(sample);
  sample->src_user_len = getString(sample, sample->src_user, SA_MAX_EXTENDED_USER_LEN);
  if(sample->datagramVersion >= 5) sample->dst_user_charset = getData32(sample);
  sample->dst_user_len = getString(sample, sample->dst_user, SA_MAX_EXTENDED_USER_LEN);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_USER;
}

/*_________________---------------------------__________________
  _________________    readExtendedUrl        __________________
  -----------------___________________________------------------
*/

void readExtendedUrl(SFSample *sample)
{
  sample->url_direction = getData32(sample);
  sample->url_len = getString(sample, sample->url, SA_MAX_EXTENDED_URL_LEN);
  if(sample->datagramVersion >= 5) sample->host_len = getString(sample, sample->host, SA_MAX_EXTENDED_HOST_LEN);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_URL;
}


/*_________________---------------------------__________________
  _________________       mplsLabelStack      __________________
  -----------------___________________________------------------
*/

void mplsLabelStack(SFSample *sample, u_int8_t direction)
{
  if (direction == DIRECTION_IN) {
    sample->lstk.depth = getData32(sample);
    /* just point at the lablelstack array */
    if (sample->lstk.depth > 0) sample->lstk.stack = (u_int32_t *)sample->datap;
    /* and skip over it in the input */
    skipBytes(sample, sample->lstk.depth * 4);
  }
  else if (direction == DIRECTION_OUT) {
    sample->lstk_out.depth = getData32(sample);
    if (sample->lstk_out.depth > 0) sample->lstk_out.stack = (u_int32_t *)sample->datap;
    skipBytes(sample, sample->lstk_out.depth * 4);
  }
}

/*_________________---------------------------__________________
  _________________    readExtendedMpls       __________________
  -----------------___________________________------------------
*/

void readExtendedMpls(SFSample *sample)
{
  getAddress(sample, &sample->mpls_nextHop);

  mplsLabelStack(sample, DIRECTION_IN);
  mplsLabelStack(sample, DIRECTION_OUT);
  
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS;
}

/*_________________---------------------------__________________
  _________________    readExtendedNat        __________________
  -----------------___________________________------------------
*/

void readExtendedNat(SFSample *sample)
{
  getAddress(sample, &sample->nat_src);
  getAddress(sample, &sample->nat_dst);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_NAT;
}


/*_________________---------------------------__________________
  _________________    readExtendedMplsTunnel __________________
  -----------------___________________________------------------
*/

void readExtendedMplsTunnel(SFSample *sample)
{
#define SA_MAX_TUNNELNAME_LEN 100
  char tunnel_name[SA_MAX_TUNNELNAME_LEN+1];
  
  getString(sample, tunnel_name, SA_MAX_TUNNELNAME_LEN); 
  sample->mpls_tunnel_id = getData32(sample);
  getData32(sample); /* tunnel_cos */

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_TUNNEL;
}

/*_________________---------------------------__________________
  _________________    readExtendedMplsVC     __________________
  -----------------___________________________------------------
*/

void readExtendedMplsVC(SFSample *sample)
{
#define SA_MAX_VCNAME_LEN 100
  char vc_name[SA_MAX_VCNAME_LEN+1];

  getString(sample, vc_name, SA_MAX_VCNAME_LEN); 
  sample->mpls_vll_vc_id = getData32(sample);
  getData32(sample); /* vc_cos */

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_VC;
}

/*_________________---------------------------__________________
  _________________    readExtendedMplsFTN    __________________
  -----------------___________________________------------------
*/

void readExtendedMplsFTN(SFSample *sample)
{
#define SA_MAX_FTN_LEN 100
  char ftn_descr[SA_MAX_FTN_LEN+1];

  getString(sample, ftn_descr, SA_MAX_FTN_LEN);
  getData32(sample); /* ftn_mask */

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_FTN;
}

/*_________________---------------------------__________________
  _________________  readExtendedMplsLDP_FEC  __________________
  -----------------___________________________------------------
*/

void readExtendedMplsLDP_FEC(SFSample *sample)
{
  getData32(sample); /* fec_addr_prefix_len */
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_LDP_FEC;
}

/*_________________---------------------------__________________
  _________________  readExtendedVlanTunnel   __________________
  -----------------___________________________------------------
*/

void readExtendedVlanTunnel(SFSample *sample)
{
  SFLLabelStack lstk;

  lstk.depth = getData32(sample);
  /* just point at the lablelstack array */
  if(lstk.depth > 0) lstk.stack = (u_int32_t *)sample->datap;
  /* and skip over it in the input */
  skipBytes(sample, lstk.depth * 4);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_VLAN_TUNNEL;
}

/*_________________---------------------------__________________
  _________________    readExtendedProcess    __________________
  -----------------___________________________------------------
*/

void readExtendedProcess(SFSample *sample)
{
  u_int32_t num_processes, i;

  num_processes = getData32(sample);
  for (i = 0; i < num_processes; i++) skipBytes(sample, 4);
}

void readExtendedClass(SFSample *sample)
{
  u_int32_t ret;
  char buf[MAX_PROTOCOL_LEN+1], *bufptr = buf;

  if (config.classifiers_path) {
    ret = getData32_nobswap(sample);
    memcpy(bufptr, &ret, 4);
    bufptr += 4;
    ret = getData32_nobswap(sample);
    memcpy(bufptr, &ret, 4);
    bufptr += 4;
    ret = getData32_nobswap(sample);
    memcpy(bufptr, &ret, 4);
    bufptr += 4;
    ret = getData32_nobswap(sample);
    memcpy(bufptr, &ret, 4);
    bufptr += 4;

    sample->class = SF_evaluate_classifiers(buf);
  }
  else skipBytes(sample, MAX_PROTOCOL_LEN);
}

void readExtendedClass2(SFSample *sample)
{
  if (config.classifier_ndpi) {
#if defined (WITH_NDPI)
    sample->ndpi_class.master_protocol = getData32(sample);
    sample->ndpi_class.app_protocol = getData32(sample);
#endif
  }
  else skipBytes(sample, 8);
}

void readExtendedTag(SFSample *sample)
{
  sample->tag = getData64(sample);
  sample->tag2 = getData64(sample);
}

void decodeMpls(SFSample *sample, u_char **bp)
{
  struct packet_ptrs dummy_pptrs;
  u_char *ptr, *end = sample->header + sample->headerLen;
  u_int16_t nl = 0, caplen;

  if (bp) ptr = (*bp);
  else ptr = (u_char *)sample->datap;
  caplen = end - ptr;

  memset(&dummy_pptrs, 0, sizeof(dummy_pptrs));
  sample->eth_type = mpls_handler(ptr, &caplen, &nl, &dummy_pptrs);

  if (sample->eth_type == ETHERTYPE_IP) {
    sample->gotIPV4 = TRUE;
    sample->offsetToIPV4 = nl+(ptr-sample->header);
  } 
  else if (sample->eth_type == ETHERTYPE_IPV6) {
    sample->gotIPV6 = TRUE;
    sample->offsetToIPV6 = nl+(ptr-sample->header);
  }

  if (nl) {
    sample->lstk.depth = nl / 4; 
    sample->lstk.stack = (u_int32_t *) dummy_pptrs.mpls_ptr;
    if (bp) (*bp) += nl;
  }
}

void decodePPP(SFSample *sample)
{
  struct packet_ptrs dummy_pptrs;
  struct pcap_pkthdr h;
  u_char *ptr = (u_char *)sample->datap, *end = sample->header + sample->headerLen;
  u_int16_t nl = 0;

  memset(&dummy_pptrs, 0, sizeof(dummy_pptrs));
  h.caplen = end - ptr; 
  dummy_pptrs.packet_ptr = ptr;
  ppp_handler(&h, &dummy_pptrs);
  sample->eth_type = dummy_pptrs.l3_proto;
  
  if (dummy_pptrs.mpls_ptr) {
    if (dummy_pptrs.iph_ptr) nl = dummy_pptrs.iph_ptr - dummy_pptrs.mpls_ptr;
    if (nl) {
      sample->lstk.depth = nl / 4;
      sample->lstk.stack = (u_int32_t *) dummy_pptrs.mpls_ptr;
    }
  }
  if (sample->eth_type == ETHERTYPE_IP) {
    sample->gotIPV4 = TRUE;
    sample->offsetToIPV4 = dummy_pptrs.iph_ptr - sample->header;
  }
  else if (sample->eth_type == ETHERTYPE_IPV6) {
    sample->gotIPV6 = TRUE;
    sample->offsetToIPV6 = dummy_pptrs.iph_ptr - sample->header;
  }
}

/*_________________---------------------------__________________
  _________________  readFlowSample_header    __________________
  -----------------___________________________------------------
*/

void readFlowSample_header(SFSample *sample)
{
  sample->headerProtocol = getData32(sample);
  sample->sampledPacketSize = getData32(sample);
  if(sample->datagramVersion > 4) sample->stripped = getData32(sample);
  sample->headerLen = getData32(sample);
  
  sample->header = (u_char *)sample->datap; /* just point at the header */
  
  switch(sample->headerProtocol) {
    /* the header protocol tells us where to jump into the decode */
  case SFLHEADER_ETHERNET_ISO8023:
    decodeLinkLayer(sample);
    break;
  case SFLHEADER_IPv4: 
    sample->gotIPV4 = TRUE;
    sample->offsetToIPV4 = 0;
    break;
  case SFLHEADER_IPv6:
    sample->gotIPV6 = TRUE;
    sample->offsetToIPV6 = 0;
    break;
  case SFLHEADER_MPLS:
    decodeMpls(sample, NULL);
    break;
  case SFLHEADER_PPP:
    decodePPP(sample);
    break;
  case SFLHEADER_ISO88024_TOKENBUS:
  case SFLHEADER_ISO88025_TOKENRING:
  case SFLHEADER_FDDI:
  case SFLHEADER_FRAME_RELAY:
  case SFLHEADER_X25:
  case SFLHEADER_SMDS:
  case SFLHEADER_AAL5:
  case SFLHEADER_AAL5_IP:
  default:
    /* XXX: nofity error */ 
    break;
  }
  
  if (sample->gotIPV4) decodeIPV4(sample);
  else if (sample->gotIPV6) decodeIPV6(sample);

  skipBytes(sample, sample->headerLen);
}

/*_________________---------------------------__________________
  _________________  readFlowSample_ethernet  __________________
  -----------------___________________________------------------
*/

void readFlowSample_ethernet(SFSample *sample)
{
  sample->eth_len = getData32(sample);
  memcpy(sample->eth_src, sample->datap, 6);
  skipBytes(sample, 6);
  memcpy(sample->eth_dst, sample->datap, 6);
  skipBytes(sample, 6);
  sample->eth_type = getData32(sample);

  if (sample->eth_type == ETHERTYPE_IP) sample->gotIPV4 = TRUE;
  else if (sample->eth_type == ETHERTYPE_IPV6) sample->gotIPV6 = TRUE;

  /* Commit eth_len to packet length: will be overwritten if we get
     SFLFLOW_IPV4 or SFLFLOW_IPV6; otherwise will get along as the
     best information we have */ 
  if (!sample->sampledPacketSize) sample->sampledPacketSize = sample->eth_len;
}


/*_________________---------------------------__________________
  _________________    readFlowSample_IPv4    __________________
  -----------------___________________________------------------
*/

void readFlowSample_IPv4(SFSample *sample)
{
  sample->headerLen = sizeof(SFLSampled_ipv4);
  sample->header = (u_char *)sample->datap; /* just point at the header */
  skipBytes(sample, sample->headerLen);
  {
    SFLSampled_ipv4 nfKey;

    memcpy(&nfKey, sample->header, sizeof(nfKey));
    sample->sampledPacketSize = ntohl(nfKey.length);
    sample->dcd_srcIP = nfKey.src_ip;
    sample->dcd_dstIP = nfKey.dst_ip;
    sample->dcd_ipProtocol = ntohl(nfKey.protocol);
    sample->dcd_ipTos = ntohl(nfKey.tos);
    sample->dcd_sport = ntohl(nfKey.src_port);
    sample->dcd_dport = ntohl(nfKey.dst_port);
  }

  sample->gotIPV4 = TRUE;
}

/*_________________---------------------------__________________
  _________________    readFlowSample_IPv6    __________________
  -----------------___________________________------------------
*/

void readFlowSample_IPv6(SFSample *sample)
{
  sample->header = (u_char *)sample->datap; /* just point at the header */
  sample->headerLen = sizeof(SFLSampled_ipv6);
  skipBytes(sample, sample->headerLen);

  {
    SFLSampled_ipv6 nfKey6;

    memcpy(&nfKey6, sample->header, sizeof(nfKey6));
    sample->sampledPacketSize = ntohl(nfKey6.length);
    sample->ipsrc.type = SFLADDRESSTYPE_IP_V6;
    memcpy(&sample->ipsrc.address, &nfKey6.src_ip, IP6AddrSz);
    sample->ipdst.type = SFLADDRESSTYPE_IP_V6;
    memcpy(&sample->ipdst.address, &nfKey6.dst_ip, IP6AddrSz);
    sample->dcd_ipProtocol = ntohl(nfKey6.protocol);
    sample->dcd_ipTos = ntohl(nfKey6.priority);
    sample->dcd_sport = ntohl(nfKey6.src_port);
    sample->dcd_dport = ntohl(nfKey6.dst_port);
  }

  sample->gotIPV6 = TRUE;
}

/*_________________---------------------------__________________
  _________________    readv2v4FlowSample    __________________
  -----------------___________________________------------------
*/

void readv2v4FlowSample(SFSample *sample, struct packet_ptrs_vector *pptrsv, struct plugin_requests *req)
{
  sample->samplesGenerated = getData32(sample);
  {
    u_int32_t samplerId = getData32(sample);
    sample->ds_class = samplerId >> 24;
    sample->ds_index = samplerId & 0x00ffffff;
  }
  
  sample->meanSkipCount = getData32(sample);
  sample->samplePool = getData32(sample);
  sample->dropEvents = getData32(sample);
  sample->inputPort = getData32(sample);
  sample->outputPort = getData32(sample);
  sample->packet_data_tag = getData32(sample);
  
  switch(sample->packet_data_tag) {
    
  case INMPACKETTYPE_HEADER: readFlowSample_header(sample); break;
  case INMPACKETTYPE_IPV4: readFlowSample_IPv4(sample); break;
  case INMPACKETTYPE_IPV6: readFlowSample_IPv6(sample); break;
  default: 
    SF_notify_malf_packet(LOG_INFO, "INFO", "discarding unknown v2/v4 Data Tag", (struct sockaddr *) pptrsv->v4.f_agent);
    xflow_status_table.tot_bad_datagrams++;
    break;
  }

  sample->extended_data_tag = 0;
  {
    u_int32_t x;
    sample->num_extended = getData32(sample);
    for(x = 0; x < sample->num_extended; x++) {
      u_int32_t extended_tag;
      extended_tag = getData32(sample);
      switch(extended_tag) {
      case INMEXTENDED_SWITCH: readExtendedSwitch(sample); break;
      case INMEXTENDED_ROUTER: readExtendedRouter(sample); break;
      case INMEXTENDED_GATEWAY:
	if(sample->datagramVersion == 2) readExtendedGateway_v2(sample);
	else readExtendedGateway(sample);
	break;
      case INMEXTENDED_USER: readExtendedUser(sample); break;
      case INMEXTENDED_URL: readExtendedUrl(sample); break;
      default: 
	SF_notify_malf_packet(LOG_INFO, "INFO", "discarding unknown v2/v4 Extended Data Tag", (struct sockaddr *) pptrsv->v4.f_agent);
	xflow_status_table.tot_bad_datagrams++;
	break;
      }
    }
  }

  finalizeSample(sample, pptrsv, req);
}

/*_________________---------------------------__________________
  _________________    readv5FlowSample         __________________
  -----------------___________________________------------------
*/

void readv5FlowSample(SFSample *sample, int expanded, struct packet_ptrs_vector *pptrsv, struct plugin_requests *req, int finalize)
{
  struct sfv5_modules_db_field *db_field = NULL;
  u_int32_t num_elements, sampleLength;
  u_char *sampleStart;

  sampleLength = getData32(sample);
  sampleStart = (u_char *)sample->datap;
  sample->samplesGenerated = getData32(sample);
  if(expanded) {
    sample->ds_class = getData32(sample);
    sample->ds_index = getData32(sample);
  }
  else {
    u_int32_t samplerId = getData32(sample);
    sample->ds_class = samplerId >> 24;
    sample->ds_index = samplerId & 0x00ffffff;
  }

  sample->meanSkipCount = getData32(sample);
  sample->samplePool = getData32(sample);
  sample->dropEvents = getData32(sample);
  if(expanded) {
    sample->inputPortFormat = getData32(sample);
    sample->inputPort = getData32(sample);
    sample->outputPortFormat = getData32(sample);
    sample->outputPort = getData32(sample);
  }
  else {
    u_int32_t inp, outp;
    inp = getData32(sample);
    outp = getData32(sample);
    sample->inputPortFormat = inp >> 30;
    sample->outputPortFormat = outp >> 30;
    sample->inputPort = inp; // skip 0x3fffffff mask
    sample->outputPort = outp; // skip 0x3fffffff mask
  }

  num_elements = getData32(sample);

  {
    u_int32_t el;

    for (el = 0; el < num_elements; el++) {
      u_int32_t tag, length;
      u_char *start;
      tag = getData32(sample);
      length = getData32(sample);
      start = (u_char *)sample->datap;

      switch(tag) {
      case SFLFLOW_HEADER:     readFlowSample_header(sample); break;
      case SFLFLOW_ETHERNET:   readFlowSample_ethernet(sample); break;
      case SFLFLOW_IPV4:       readFlowSample_IPv4(sample); break;
      case SFLFLOW_IPV6:       readFlowSample_IPv6(sample); break;
      case SFLFLOW_EX_SWITCH:  readExtendedSwitch(sample); break;
      case SFLFLOW_EX_ROUTER:  readExtendedRouter(sample); break;
      case SFLFLOW_EX_GATEWAY: readExtendedGateway(sample); break;
      case SFLFLOW_EX_USER:    readExtendedUser(sample); break;
      case SFLFLOW_EX_URL:     readExtendedUrl(sample); break;
      case SFLFLOW_EX_MPLS:    readExtendedMpls(sample); break;
      case SFLFLOW_EX_NAT:     readExtendedNat(sample); break;
      case SFLFLOW_EX_MPLS_TUNNEL:  readExtendedMplsTunnel(sample); break;
      case SFLFLOW_EX_MPLS_VC:      readExtendedMplsVC(sample); break;
      case SFLFLOW_EX_MPLS_FTN:     readExtendedMplsFTN(sample); break;
      case SFLFLOW_EX_MPLS_LDP_FEC: readExtendedMplsLDP_FEC(sample); break;
      case SFLFLOW_EX_VLAN_TUNNEL:  readExtendedVlanTunnel(sample); break;
      case SFLFLOW_EX_PROCESS:      readExtendedProcess(sample); break;
      case SFLFLOW_EX_CLASS:	    readExtendedClass(sample); break;
      case SFLFLOW_EX_CLASS2:	    readExtendedClass2(sample); break;
      case SFLFLOW_EX_TAG:	    readExtendedTag(sample); break;
      default:
	if (skipBytesAndCheck(sample, length) == ERR) return;
	break;
      }

      db_field = sfv5_modules_db_get_next_ie(tag);
      if (db_field) {
	db_field->type = tag;
	db_field->ptr = start;
	db_field->len = length;
      }
      else Log(LOG_WARNING, "WARN ( %s/core ): readv5FlowSample(): no IEs available in SFv5 modules DB.\n", config.name);

      if (lengthCheck(sample, start, length) == ERR) return;
    }
  }

  if (lengthCheck(sample, sampleStart, sampleLength) == ERR) return;

  if (finalize) finalizeSample(sample, pptrsv, req);
}

void readv5CountersSample(SFSample *sample, int expanded, struct packet_ptrs_vector *pptrsv)
{
  struct sfv5_modules_db_field *db_field = NULL;
  struct xflow_status_entry *xse = NULL;
  struct bgp_peer *peer = NULL;
  u_int32_t sampleLength, num_elements, idx;
  u_char *sampleStart;

  if (sfacctd_counter_backend_methods) {
    if (pptrsv) xse = (struct xflow_status_entry *) pptrsv->v4.f_status;
    if (xse) peer = (struct bgp_peer *) xse->sf_cnt; 
  }

  sampleLength = getData32(sample);
  sampleStart = (u_char *)sample->datap;
  sample->cntSequenceNo = getData32(sample);

  if (expanded) {
    sample->ds_class = getData32(sample);
    sample->ds_index = getData32(sample);
  }
  else {
    u_int32_t samplerId = getData32(sample);
    sample->ds_class = samplerId >> 24;
    sample->ds_index = samplerId & 0x00ffffff;
  }

  num_elements = getData32(sample);

  for (idx = 0; idx < num_elements; idx++) {
    u_int32_t tag, length;
    u_char *start;
    char buf[51];

    tag = getData32(sample);
    length = getData32(sample);
    start = (u_char *)sample->datap;
    Log(LOG_DEBUG, "DEBUG ( %s/core ): readv5CountersSample(): element tag %s.\n", config.name, printTag(tag, buf, 50));

    db_field = sfv5_modules_db_get_next_ie(tag); 
    if (db_field) {
      db_field->type = tag;
      db_field->ptr = start;
      db_field->len = length;
    }
    else Log(LOG_WARNING, "WARN ( %s/core ): readv5CountersSample(): no IEs available in SFv5 modules DB.\n", config.name);

    if (sfacctd_counter_backend_methods) sf_cnt_log_msg(peer, sample, sample->datagramVersion, length, "log", config.sfacctd_counter_output, tag);
    else skipBytes(sample, length);
  }

  if (lengthCheck(sample, sampleStart, sampleLength) == ERR) return;
}

/*
   seems like sFlow v2/v4 does not supply any meaningful information
   about the length of current sample. This is because we still need
   to parse the very first part of the sample
*/ 
void readv2v4CountersSample(SFSample *sample, struct packet_ptrs_vector *pptrsv)
{
  struct xflow_status_entry *xse = NULL;
  struct bgp_peer *peer = NULL;
  int have_sample = FALSE;
  u_int32_t length = 0;

  if (sfacctd_counter_backend_methods) {
    if (pptrsv) xse = (struct xflow_status_entry *) pptrsv->v4.f_status;
    if (xse) peer = (struct bgp_peer *) xse->sf_cnt;
  }

  sample->cntSequenceNo = getData32(sample);

  {
    uint32_t samplerId = getData32(sample);
    sample->ds_class = samplerId >> 24;
    sample->ds_index = samplerId & 0x00ffffff;
  }

  sample->statsSamplingInterval = getData32(sample);
  sample->counterBlockVersion = getData32(sample);

  switch(sample->counterBlockVersion) {
  case INMCOUNTERSVERSION_GENERIC:
  case INMCOUNTERSVERSION_ETHERNET:
  case INMCOUNTERSVERSION_TOKENRING:
  case INMCOUNTERSVERSION_FDDI:
  case INMCOUNTERSVERSION_VG:
  case INMCOUNTERSVERSION_WAN: length += 88; break;
  case INMCOUNTERSVERSION_VLAN: break;
  default: return; 
  }

  /* now see if there are any specific counter blocks to add */
  switch(sample->counterBlockVersion) {
  case INMCOUNTERSVERSION_GENERIC: have_sample = TRUE; break;
  case INMCOUNTERSVERSION_ETHERNET: have_sample = TRUE; length += 52; break;
  case INMCOUNTERSVERSION_TOKENRING: length += 72; break;
  case INMCOUNTERSVERSION_FDDI: break;
  case INMCOUNTERSVERSION_VG: length += 80; break;
  case INMCOUNTERSVERSION_WAN: break;
  case INMCOUNTERSVERSION_VLAN: have_sample = TRUE; length += 28; break;
  default: return; 
  }

  if (sfacctd_counter_backend_methods && have_sample)
    sf_cnt_log_msg(peer, sample, sample->datagramVersion, length, "log", config.sfacctd_counter_output, sample->counterBlockVersion);
  else
    skipBytes(sample, length);
}

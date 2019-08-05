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

/* 
    much of the sflow v2/v4/v5 definitions are based on sFlow toolkit 3.8 and
    later which is Copyright (C) InMon Corporation 2001 ALL RIGHTS RESERVED
*/

#ifndef SFACCTD_H
#define SFACCTD_H

/* defines */
#define DEFAULT_SFACCTD_PORT 6343 
#define SFLOW_MIN_MSG_SIZE 200 
#define SFLOW_MAX_MSG_SIZE 65536 /* inflated ? */
#define MAX_SF_CNT_LOG_ENTRIES 1024

enum INMPacket_information_type {
  INMPACKETTYPE_HEADER  = 1,      /* Packet headers are sampled */
  INMPACKETTYPE_IPV4    = 2,      /* IP version 4 data */
  INMPACKETTYPE_IPV6    = 3       /* IP version 4 data */
};

enum INMExtended_information_type {
  INMEXTENDED_SWITCH    = 1,      /* Extended switch information */
  INMEXTENDED_ROUTER    = 2,      /* Extended router information */
  INMEXTENDED_GATEWAY   = 3,      /* Extended gateway router information */
  INMEXTENDED_USER      = 4,      /* Extended TACAS/RADIUS user information */
  INMEXTENDED_URL       = 5       /* Extended URL information */
};

enum INMCounters_version {
  INMCOUNTERSVERSION_GENERIC      = 1,
  INMCOUNTERSVERSION_ETHERNET     = 2,
  INMCOUNTERSVERSION_TOKENRING    = 3,
  INMCOUNTERSVERSION_FDDI         = 4,
  INMCOUNTERSVERSION_VG           = 5,
  INMCOUNTERSVERSION_WAN          = 6,
  INMCOUNTERSVERSION_VLAN         = 7
};

typedef struct _SFSample {
  struct timeval *ts;
  struct in_addr sourceIP;
  SFLAddress agent_addr;
  u_int32_t agentSubId;

  /* the raw pdu */
  u_char *rawSample;
  u_int32_t rawSampleLen;
  u_char *endp;
  u_int32_t *datap;

  u_int32_t datagramVersion;
  u_int32_t sampleType;
  u_int32_t ds_class;
  u_int32_t ds_index;

  /* generic interface counter sample */
  SFLIf_counters ifCounters;

  /* sample stream info */
  u_int32_t sysUpTime;
  u_int32_t sequenceNo;
  u_int32_t cntSequenceNo;
  u_int32_t sampledPacketSize;
  u_int32_t samplesGenerated;
  u_int32_t meanSkipCount;
  u_int32_t samplePool;
  u_int32_t dropEvents;

  /* the sampled header */
  u_int32_t packet_data_tag;
  u_int32_t headerProtocol;
  u_char *header;
  int headerLen;
  u_int32_t stripped;

  /* header decode */
  int gotIPV4;
  int offsetToIPV4;
  int gotIPV6;
  int offsetToIPV6;
  struct in_addr dcd_srcIP;
  struct in_addr dcd_dstIP;
  u_int32_t dcd_ipProtocol;
  u_int32_t dcd_ipTos;
  u_int32_t dcd_ipTTL;
  u_int32_t dcd_sport;
  u_int32_t dcd_dport;
  u_int32_t dcd_tcpFlags;
  u_int32_t ip_fragmentOffset;
  u_int32_t udp_pduLen;

  /* ports */
  u_int32_t inputPortFormat;
  u_int32_t outputPortFormat;
  u_int32_t inputPort;
  u_int32_t outputPort;

  /* ethernet */
  u_int32_t eth_type;
  u_int32_t eth_len;
  u_char eth_src[8];
  u_char eth_dst[8];

  /* vlan */
  u_int32_t in_vlan;
  u_int32_t in_priority;
  u_int32_t internalPriority;
  u_int32_t out_vlan;
  u_int32_t out_priority;

  /* MPLS hack */
  SFLLabelStack lstk;
  SFLLabelStack lstk_out;

  /* extended data fields */
  u_int32_t num_extended;
  u_int32_t extended_data_tag;
#define SASAMPLE_EXTENDED_DATA_SWITCH 1
#define SASAMPLE_EXTENDED_DATA_ROUTER 4
#define SASAMPLE_EXTENDED_DATA_GATEWAY 8
#define SASAMPLE_EXTENDED_DATA_USER 16
#define SASAMPLE_EXTENDED_DATA_URL 32
#define SASAMPLE_EXTENDED_DATA_MPLS 64
#define SASAMPLE_EXTENDED_DATA_NAT 128
#define SASAMPLE_EXTENDED_DATA_MPLS_TUNNEL 256
#define SASAMPLE_EXTENDED_DATA_MPLS_VC 512
#define SASAMPLE_EXTENDED_DATA_MPLS_FTN 1024
#define SASAMPLE_EXTENDED_DATA_MPLS_LDP_FEC 2048
#define SASAMPLE_EXTENDED_DATA_VLAN_TUNNEL 4096

  /* IP forwarding info */
  SFLAddress nextHop;
  u_int32_t srcMask;
  u_int32_t dstMask;

  /* BGP info */
  SFLAddress bgp_nextHop;
  u_int32_t my_as;
  u_int32_t src_as;
  u_int32_t src_peer_as;

  u_int32_t dst_as_path_len;
  char dst_as_path[LARGEBUFLEN];

  u_int32_t dst_peer_as;
  u_int32_t dst_as;

  u_int32_t communities_len;
  char comms[LARGEBUFLEN];
  u_int32_t localpref;

  /* user id */
#define SA_MAX_EXTENDED_USER_LEN 200
  u_int32_t src_user_charset;
  u_int32_t src_user_len;
  char src_user[SA_MAX_EXTENDED_USER_LEN+1];
  u_int32_t dst_user_charset;
  u_int32_t dst_user_len;
  char dst_user[SA_MAX_EXTENDED_USER_LEN+1];

  /* url */
#define SA_MAX_EXTENDED_URL_LEN 200
#define SA_MAX_EXTENDED_HOST_LEN 200
  u_int32_t url_direction;
  u_int32_t url_len;
  char url[SA_MAX_EXTENDED_URL_LEN+1];
  u_int32_t host_len;
  char host[SA_MAX_EXTENDED_HOST_LEN+1];

  /* mpls */
  SFLAddress mpls_nextHop;
  u_int32_t mpls_vll_vc_id;
  u_int32_t mpls_tunnel_id;

  /* nat */
  SFLAddress nat_src;
  SFLAddress nat_dst;

  /* vxlan */
  u_int32_t vni;

  /* counter blocks */
  u_int32_t statsSamplingInterval;
  u_int32_t counterBlockVersion;

  /* classification */
  pm_class_t class;
#if defined (WITH_NDPI)
  pm_class2_t ndpi_class;
#endif 

  pm_id_t tag;
  pm_id_t tag2;

  SFLAddress ipsrc;
  SFLAddress ipdst;

  struct packet_ptrs hdr_ptrs;
  struct pcap_pkthdr hdr_pcap;

  void *sppi;
} SFSample;

/* define my own IP header struct - to ease portability */
struct SF_iphdr
{
  u_int8_t version_and_headerLen;
  u_int8_t tos;
  u_int16_t tot_len;
  u_int16_t id;
  u_int16_t frag_off;
  u_int8_t ttl;
  u_int8_t protocol;
  u_int16_t check;
  u_int32_t saddr;
  u_int32_t daddr;
};

/* same for tcp */
struct SF_tcphdr
{
  u_int16_t th_sport;
  u_int16_t th_dport;
  u_int32_t th_seq;
  u_int32_t th_ack;
  u_int8_t th_off_and_unused;
  u_int8_t th_flags;
  u_int16_t th_win;
  u_int16_t th_sum;
  u_int16_t th_urp;
};

/* and UDP */
struct SF_udphdr {
  u_int16_t uh_sport;
  u_int16_t uh_dport;
  u_int16_t uh_ulen;
  u_int16_t uh_sum;
};

/* and ICMP */
struct SF_icmphdr
{
  u_int8_t type;
  u_int8_t code;
  /* ignore the rest */
};

struct SF_dissect {
  u_char *hdrBasePtr;
  u_char *hdrEndPtr;
  u_int32_t hdrLen;
  u_char *flowBasePtr;
  u_char *flowEndPtr;
  u_int32_t flowLen;
  u_int32_t *samplesInPkt;
};

extern u_int8_t SF_evaluate_flow_type(struct packet_ptrs *);
extern void set_vector_sample_type(struct packet_ptrs_vector *, u_int32_t);
extern void reset_mac(struct packet_ptrs *);
extern void reset_mac_vlan(struct packet_ptrs *);
extern void reset_ip4(struct packet_ptrs *);
extern void reset_ip6(struct packet_ptrs *);
extern void SF_notify_malf_packet(short int, char *, char *, struct sockaddr *);
extern int SF_find_id(struct id_table *, struct packet_ptrs *, pm_id_t *, pm_id_t *);
extern void SF_compute_once();

extern char *getPointer(SFSample *);
extern u_int32_t getData32(SFSample *);
extern u_int32_t getData32_nobswap(SFSample *);
extern u_int64_t getData64(SFSample *);
extern u_int32_t getAddress(SFSample *, SFLAddress *);
extern void skipBytes(SFSample *, int);
extern int skipBytesAndCheck(SFSample *, int);
extern int lengthCheck(SFSample *, u_char *, u_int32_t);
extern u_int32_t getString(SFSample *, char *, u_int32_t);

extern void process_SFv2v4_packet(SFSample *, struct packet_ptrs_vector *, struct plugin_requests *, struct sockaddr *);
extern void process_SFv5_packet(SFSample *, struct packet_ptrs_vector *, struct plugin_requests *, struct sockaddr *);
extern void process_SF_raw_packet(SFSample *, struct packet_ptrs_vector *, struct plugin_requests *, struct sockaddr *);
extern void readv2v4FlowSample(SFSample *, struct packet_ptrs_vector *, struct plugin_requests *);
extern void readv5FlowSample(SFSample *, int, struct packet_ptrs_vector *, struct plugin_requests *, int);
extern void readv2v4CountersSample(SFSample *, struct packet_ptrs_vector *);
extern void readv5CountersSample(SFSample *, int, struct packet_ptrs_vector *);
extern void finalizeSample(SFSample *, struct packet_ptrs_vector *, struct plugin_requests *);
extern void InterSampleCleanup(SFSample *);
extern void decodeMpls(SFSample *, u_char **);
extern void decodePPP(SFSample *);
extern void decodeLinkLayer(SFSample *);
extern void decodeIPLayer4(SFSample *, u_char *, u_int32_t);
extern void decodeIPV4(SFSample *);
extern void decodeIPV6(SFSample *);
extern void decodeVXLAN(SFSample *, u_char *);
extern void readExtendedSwitch(SFSample *);
extern void readExtendedRouter(SFSample *);
extern void readExtendedGateway_v2(SFSample *);
extern void readExtendedGateway(SFSample *);
extern void readExtendedUser(SFSample *);
extern void readExtendedUrl(SFSample *);
extern void mplsLabelStack(SFSample *, u_int8_t);
extern void readExtendedMpls(SFSample *);
extern void readExtendedNat(SFSample *);
extern void readExtendedMplsTunnel(SFSample *);
extern void readExtendedMplsVC(SFSample *);
extern void readExtendedMplsFTN(SFSample *);
extern void readExtendedMplsLDP_FEC(SFSample *);
extern void readExtendedVlanTunnel(SFSample *);
extern void readExtendedProcess(SFSample *);
extern void readFlowSample_header(SFSample *);
extern void readFlowSample_ethernet(SFSample *);
extern void readFlowSample_IPv4(SFSample *);
extern void readFlowSample_IPv6(SFSample *);

extern int sf_cnt_log_msg(struct bgp_peer *, SFSample *, int, u_int32_t, char *, int, u_int32_t);
extern int readCounters_generic(struct bgp_peer *, SFSample *, char *, int, void *);
extern int readCounters_ethernet(struct bgp_peer *, SFSample *, char *, int, void *);
extern int readCounters_vlan(struct bgp_peer *, SFSample *, char *, int, void *);
extern void sfacctd_counter_init_amqp_host();
extern int sfacctd_counter_init_kafka_host();
extern void sf_cnt_link_misc_structs(struct bgp_misc_structs *);
extern void sf_flow_sample_hdr_decode(SFSample *);

extern struct xflow_status_entry *sfv245_check_status(SFSample *spp, struct packet_ptrs *, struct sockaddr *);
extern void sfv245_check_counter_log_init(struct packet_ptrs *);

extern void usage_daemon(char *);
extern void compute_once();

#ifdef WITH_KAFKA
extern void SF_init_kafka_host(void *);
#endif

#ifdef WITH_ZMQ
extern void SF_init_zmq_host(void *, int *);
#endif

/* global variables */
extern int sfacctd_counter_backend_methods;
extern struct bgp_misc_structs *sf_cnt_misc_db;
extern struct host_addr debug_a;
extern char debug_agent_addr[50];
extern u_int16_t debug_agent_port;

#endif //SFACCTD_H

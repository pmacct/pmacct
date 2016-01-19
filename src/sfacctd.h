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

/* 
    much of the sflow v2/v4/v5 definitions are based on sFlow toolkit 3.8 and
    later which is Copyright (C) InMon Corporation 2001 ALL RIGHTS RESERVED
*/

/* defines */
#define DEFAULT_SFACCTD_PORT 6343 
#define SFLOW_MIN_MSG_SIZE 200 
#define SFLOW_MAX_MSG_SIZE 65536 /* inflated ? */

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
  char dst_as_path[MAX_BGP_ASPATH];

  u_int32_t dst_peer_as;
  u_int32_t dst_as;

  u_int32_t communities_len;
  char comms[MAX_BGP_STD_COMMS];
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

  /* nat */
  SFLAddress nat_src;
  SFLAddress nat_dst;

  /* counter blocks */
  u_int32_t statsSamplingInterval;
  u_int32_t counterBlockVersion;

  /* classification */
  pm_class_t class;
  pm_id_t tag;
  pm_id_t tag2;

  SFLAddress ipsrc;
  SFLAddress ipdst;
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

#if (!defined __SFACCTD_C)
#define EXT extern
#else
#define EXT
#endif
EXT u_int16_t SF_evaluate_flow_type(struct packet_ptrs *);
EXT void set_vector_sample_type(struct packet_ptrs_vector *, u_int32_t);
EXT void reset_mac(struct packet_ptrs *);
EXT void reset_mac_vlan(struct packet_ptrs *);
EXT void reset_ip4(struct packet_ptrs *);
EXT void reset_ip6(struct packet_ptrs *);
EXT void SF_notify_malf_packet(short int, char *, struct sockaddr *);
EXT int SF_find_id(struct id_table *, struct packet_ptrs *, pm_id_t *, pm_id_t *);

EXT u_int32_t getData32(SFSample *);
EXT u_int32_t getData32_nobswap(SFSample *);
EXT u_int64_t getData64(SFSample *);
EXT u_int32_t getAddress(SFSample *, SFLAddress *);
EXT void skipBytes(SFSample *, int);
EXT int lengthCheck(SFSample *, u_char *, int);

EXT void process_SFv2v4_packet(SFSample *, struct packet_ptrs_vector *, struct plugin_requests *, struct sockaddr *);
EXT void process_SFv5_packet(SFSample *, struct packet_ptrs_vector *, struct plugin_requests *, struct sockaddr *);
EXT void process_SF_raw_packet(SFSample *, struct packet_ptrs_vector *, struct plugin_requests *, struct sockaddr *);
EXT void readv2v4FlowSample(SFSample *, struct packet_ptrs_vector *, struct plugin_requests *);
EXT void readv5FlowSample(SFSample *, int, struct packet_ptrs_vector *, struct plugin_requests *);
EXT void readv2v4CountersSample(SFSample *);
EXT void readv5CountersSample(SFSample *, int, struct packet_ptrs_vector *, struct plugin_requests *);
EXT void finalizeSample(SFSample *, struct packet_ptrs_vector *, struct plugin_requests *);
EXT void InterSampleCleanup(SFSample *);
EXT void decodeMpls(SFSample *);
EXT void decodePPP(SFSample *);
EXT void decodeLinkLayer(SFSample *);
EXT void decodeIPLayer4(SFSample *, u_char *, u_int32_t);
EXT void decodeIPV4(SFSample *);
EXT void decodeIPV6(SFSample *);
EXT void readExtendedSwitch(SFSample *);
EXT void readExtendedRouter(SFSample *);
EXT void readExtendedGateway_v2(SFSample *);
EXT void readExtendedGateway(SFSample *);
EXT void readExtendedUser(SFSample *);
EXT void readExtendedUrl(SFSample *);
EXT void mplsLabelStack(SFSample *, char *);
EXT void readExtendedMpls(SFSample *);
EXT void readExtendedNat(SFSample *);
EXT void readExtendedMplsTunnel(SFSample *);
EXT void readExtendedMplsVC(SFSample *);
EXT void readExtendedMplsFTN(SFSample *);
EXT void readExtendedMplsLDP_FEC(SFSample *);
EXT void readExtendedVlanTunnel(SFSample *);
EXT void readExtendedProcess(SFSample *);
EXT void readFlowSample_header(SFSample *);
EXT void readFlowSample_ethernet(SFSample *);
EXT void readFlowSample_IPv4(SFSample *);
EXT void readFlowSample_IPv6(SFSample *);

EXT int sf_cnt_log_msg(struct bgp_peer *, SFSample *, u_int32_t, char *, int, u_int32_t);
EXT int readCounters_generic(struct bgp_peer *, SFSample *, char *, int, void *);
EXT int readCounters_ethernet(struct bgp_peer *, SFSample *, char *, int, void *);
EXT int readCounters_vlan(struct bgp_peer *, SFSample *, char *, int, void *);
EXT void sfacctd_counter_init_amqp_host();
EXT int sfacctd_counter_init_kafka_host();

EXT char *sfv245_check_status(SFSample *spp, struct sockaddr *);
EXT void sfv245_check_counter_log_init(struct packet_ptrs *);

EXT void usage_daemon(char *);
EXT void compute_once();

/* global variables */
EXT struct bgp_peer_log *sf_cnt_log;
EXT u_int64_t sf_cnt_log_seq;
EXT struct timeval sf_cnt_log_tstamp;
EXT char sf_cnt_log_tstamp_str[SRVBUFLEN];
EXT int sfacctd_counter_backend_methods;

EXT struct host_addr debug_a;
EXT u_char debug_agent_addr[50];
EXT u_int16_t debug_agent_port;
#undef EXT

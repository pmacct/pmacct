/* Copyright (c) 2002-2006 InMon Corp. Licensed under the terms of the InMon sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

/////////////////////////////////////////////////////////////////////////////////
/////////////////////// sFlow Sampling Packet Data Types ////////////////////////
/////////////////////////////////////////////////////////////////////////////////

#ifndef SFLOW_H
#define SFLOW_H 1

#if defined(__cplusplus)
extern "C" {
#endif

enum SFLAddress_type {
  SFLADDRESSTYPE_IP_V4 = 1,
  SFLADDRESSTYPE_IP_V6 = 2
};

typedef union _SFLAddress_value {
  struct in_addr ip_v4;
  struct in6_addr ip_v6;
} SFLAddress_value;

typedef struct _SFLAddress {
  u_int32_t type;           /* enum SFLAddress_type */
  SFLAddress_value address;
} SFLAddress;

/* Packet header data */

#define SFL_DEFAULT_HEADER_SIZE DEFAULT_SNAPLEN
#define SFL_DEFAULT_COLLECTOR_PORT 6343
#define SFL_DEFAULT_COUNTER_INTERVAL_RATE 20
#define SFL_DEFAULT_FLOW_SAMPLING_RATE 1

/* The header protocol describes the format of the sampled header */
enum SFLHeader_protocol {
  SFLHEADER_ETHERNET_ISO8023     = 1,
  SFLHEADER_ISO88024_TOKENBUS    = 2,
  SFLHEADER_ISO88025_TOKENRING   = 3,
  SFLHEADER_FDDI                 = 4,
  SFLHEADER_FRAME_RELAY          = 5,
  SFLHEADER_X25                  = 6,
  SFLHEADER_PPP                  = 7,
  SFLHEADER_SMDS                 = 8,
  SFLHEADER_AAL5                 = 9,
  SFLHEADER_AAL5_IP              = 10, /* e.g. Cisco AAL5 mux */
  SFLHEADER_IPv4                 = 11,
  SFLHEADER_IPv6                 = 12,
  SFLHEADER_MPLS                 = 13
};

/* raw sampled header */

typedef struct _SFLSampled_header {
  u_int32_t header_protocol;            /* (enum SFLHeader_protocol) */
  u_int32_t frame_length;               /* Original length of packet before sampling */
  u_int32_t stripped;                   /* header/trailer bytes stripped by sender */
  u_int32_t header_length;              /* length of sampled header bytes to follow */
  u_int8_t *header_bytes;               /* Header bytes */
} SFLSampled_header;

/* decoded ethernet header */

typedef struct _SFLSampled_ethernet {
  u_int32_t eth_len;       /* The length of the MAC packet excluding 
                             lower layer encapsulations */
  u_int8_t src_mac[8];    /* 6 bytes + 2 pad */
  u_int8_t dst_mac[8];
  u_int32_t eth_type;
} SFLSampled_ethernet;

/* decoded IP version 4 header */

typedef struct _SFLSampled_ipv4 {
  u_int32_t length;      /* The length of the IP packet
			    excluding lower layer encapsulations */
  u_int32_t protocol;    /* IP Protocol type (for example, TCP = 6, UDP = 17) */
  struct in_addr src_ip; /* Source IP Address */
  struct in_addr dst_ip; /* Destination IP Address */
  u_int32_t src_port;    /* TCP/UDP source port number or equivalent */
  u_int32_t dst_port;    /* TCP/UDP destination port number or equivalent */
  u_int32_t tcp_flags;   /* TCP flags */
  u_int32_t tos;         /* IP type of service */
} SFLSampled_ipv4;

/* decoded IP version 6 data */

typedef struct _SFLSampled_ipv6 {
  u_int32_t length;       /* The length of the IP packet
			     excluding lower layer encapsulations */
  u_int32_t protocol;     /* IP Protocol type (for example, TCP = 6, UDP = 17) */
  struct in6_addr src_ip; /* Source IP Address */
  struct in6_addr dst_ip; /* Destination IP Address */
  u_int32_t src_port;     /* TCP/UDP source port number or equivalent */
  u_int32_t dst_port;     /* TCP/UDP destination port number or equivalent */
  u_int32_t tcp_flags;    /* TCP flags */
  u_int32_t priority;     /* IP priority */
} SFLSampled_ipv6;

/* Extended data types */

/* Extended switch data */

typedef struct _SFLExtended_switch {
  u_int32_t src_vlan;       /* The 802.1Q VLAN id of incomming frame */
  u_int32_t src_priority;   /* The 802.1p priority */
  u_int32_t dst_vlan;       /* The 802.1Q VLAN id of outgoing frame */
  u_int32_t dst_priority;   /* The 802.1p priority */
} SFLExtended_switch;

/* Extended router data */

typedef struct _SFLExtended_router {
  SFLAddress nexthop;               /* IP address of next hop router */
  u_int32_t src_mask;               /* Source address prefix mask bits */
  u_int32_t dst_mask;               /* Destination address prefix mask bits */
} SFLExtended_router;

/* Extended gateway data */
enum SFLExtended_as_path_segment_type {
  SFLEXTENDED_AS_SET = 1,      /* Unordered set of ASs */
  SFLEXTENDED_AS_SEQUENCE = 2  /* Ordered sequence of ASs */
};
  
typedef struct _SFLExtended_as_path_segment {
  u_int32_t type;   /* enum SFLExtended_as_path_segment_type */
  u_int32_t length; /* number of AS numbers in set/sequence */
  union {
    u_int32_t *set;
    u_int32_t *seq;
  } as;
} SFLExtended_as_path_segment;

typedef struct _SFLExtended_gateway {
  SFLAddress nexthop;                       /* Address of the border router that should
                                               be used for the destination network */
  u_int32_t as;                             /* AS number for this gateway */
  u_int32_t src_as;                         /* AS number of source (origin) */
  u_int32_t src_peer_as;                    /* AS number of source peer */
  u_int32_t dst_as_path_segments;           /* number of segments in path */
  SFLExtended_as_path_segment *dst_as_path; /* list of seqs or sets */
  u_int32_t communities_length;             /* number of communities */
  u_int32_t *communities;                   /* set of communities */
  u_int32_t localpref;                      /* LocalPref associated with this route */
} SFLExtended_gateway;

typedef struct _SFLString {
  u_int32_t len;
  char *str;
} SFLString;

/* Extended user data */

typedef struct _SFLExtended_user {
  u_int32_t src_charset;  /* MIBEnum value of character set used to encode a string - See RFC 2978
			     Where possible UTF-8 encoding (MIBEnum=106) should be used. A value
			     of zero indicates an unknown encoding. */
  SFLString src_user;
  u_int32_t dst_charset;
  SFLString dst_user;
} SFLExtended_user;

/* Extended URL data */

enum SFLExtended_url_direction {
  SFLEXTENDED_URL_SRC = 1, /* URL is associated with source address */
  SFLEXTENDED_URL_DST = 2  /* URL is associated with destination address */
};

typedef struct _SFLExtended_url {
  u_int32_t direction;   /* enum SFLExtended_url_direction */
  SFLString url;         /* URL associated with the packet flow.
			    Must be URL encoded */
  SFLString host;        /* The host field from the HTTP header */
} SFLExtended_url;

/* Extended MPLS data */

typedef struct _SFLLabelStack {
  u_int32_t depth;
  u_int32_t *stack; /* first entry is top of stack - see RFC 3032 for encoding */
} SFLLabelStack;

typedef struct _SFLExtended_mpls {
  SFLAddress nextHop;        /* Address of the next hop */ 
  SFLLabelStack in_stack;
  SFLLabelStack out_stack;
} SFLExtended_mpls;

  /* Extended NAT data
     Packet header records report addresses as seen at the sFlowDataSource.
     The extended_nat structure reports on translated source and/or destination
     addesses for this packet. If an address was not translated it should 
     be equal to that reported for the header. */

typedef struct _SFLExtended_nat {
  SFLAddress src;    /* Source address */
  SFLAddress dst;    /* Destination address */
} SFLExtended_nat;

  /* additional Extended MPLS stucts */

typedef struct _SFLExtended_mpls_tunnel {
   SFLString tunnel_lsp_name;  /* Tunnel name */
   u_int32_t tunnel_id;        /* Tunnel ID */
   u_int32_t tunnel_cos;       /* Tunnel COS value */
} SFLExtended_mpls_tunnel;

typedef struct _SFLExtended_mpls_vc {
   SFLString vc_instance_name; /* VC instance name */
   u_int32_t vll_vc_id;        /* VLL/VC instance ID */
   u_int32_t vc_label_cos;     /* VC Label COS value */
} SFLExtended_mpls_vc;

/* Extended MPLS FEC
    - Definitions from MPLS-FTN-STD-MIB mplsFTNTable */

typedef struct _SFLExtended_mpls_FTN {
   SFLString mplsFTNDescr;
   u_int32_t mplsFTNMask;
} SFLExtended_mpls_FTN;

/* Extended MPLS LVP FEC
    - Definition from MPLS-LDP-STD-MIB mplsFecTable
    Note: mplsFecAddrType, mplsFecAddr information available
          from packet header */

typedef struct _SFLExtended_mpls_LDP_FEC {
   u_int32_t mplsFecAddrPrefixLength;
} SFLExtended_mpls_LDP_FEC;

/* Extended VLAN tunnel information 
   Record outer VLAN encapsulations that have 
   been stripped. extended_vlantunnel information 
   should only be reported if all the following conditions are satisfied: 
     1. The packet has nested vlan tags, AND 
     2. The reporting device is VLAN aware, AND 
     3. One or more VLAN tags have been stripped, either 
        because they represent proprietary encapsulations, or 
        because switch hardware automatically strips the outer VLAN 
        encapsulation. 
   Reporting extended_vlantunnel information is not a substitute for 
   reporting extended_switch information. extended_switch data must 
   always be reported to describe the ingress/egress VLAN information 
   for the packet. The extended_vlantunnel information only applies to 
   nested VLAN tags, and then only when one or more tags has been 
   stripped. */ 

typedef SFLLabelStack SFLVlanStack;
typedef struct _SFLExtended_vlan_tunnel { 
  SFLVlanStack stack;  /* List of stripped 802.1Q TPID/TCI layers. Each 
			  TPID,TCI pair is represented as a single 32 bit 
			  integer. Layers listed from outermost to 
			  innermost. */ 
} SFLExtended_vlan_tunnel;

typedef struct _SFLExtended_classification {
  pm_class_t class;
} SFLExtended_classification;

typedef struct _SFLExtended_classification2 {
#if defined (WITH_NDPI)
  pm_class2_t id;
#else
  u_int64_t id;
#endif
} SFLExtended_classification2;

typedef struct _SFLExtended_tag {
  pm_id_t tag;
  pm_id_t tag2;
} SFLExtended_tag;

enum SFLFlow_type_tag {
  /* enterprise = 0, format = ... */
  SFLFLOW_HEADER    = 1,      /* Packet headers are sampled */
  SFLFLOW_ETHERNET  = 2,      /* MAC layer information */
  SFLFLOW_IPV4      = 3,      /* IP version 4 data */
  SFLFLOW_IPV6      = 4,      /* IP version 6 data */
  SFLFLOW_EX_SWITCH    = 1001,      /* Extended switch information */
  SFLFLOW_EX_ROUTER    = 1002,      /* Extended router information */
  SFLFLOW_EX_GATEWAY   = 1003,      /* Extended gateway router information */
  SFLFLOW_EX_USER      = 1004,      /* Extended TACAS/RADIUS user information */
  SFLFLOW_EX_URL       = 1005,      /* Extended URL information */
  SFLFLOW_EX_MPLS      = 1006,      /* Extended MPLS information */
  SFLFLOW_EX_NAT       = 1007,      /* Extended NAT information */
  SFLFLOW_EX_MPLS_TUNNEL  = 1008,   /* additional MPLS information */
  SFLFLOW_EX_MPLS_VC      = 1009,
  SFLFLOW_EX_MPLS_FTN     = 1010,
  SFLFLOW_EX_MPLS_LDP_FEC = 1011,
  SFLFLOW_EX_VLAN_TUNNEL  = 1012,   /* VLAN stack */
  /* enterprise = 43874 pmacct */
  SFLFLOW_EX_CLASS        = (43874 << 12) + 1,
  SFLFLOW_EX_TAG	  = (43874 << 12) + 2,
  SFLFLOW_EX_CLASS2       = (43874 << 12) + 3,
};

typedef union _SFLFlow_type {
  SFLSampled_header header;
  SFLSampled_ethernet ethernet;
  SFLSampled_ipv4 ipv4;
  SFLSampled_ipv6 ipv6;
  SFLExtended_switch sw;
  SFLExtended_router router;
  SFLExtended_gateway gateway;
  SFLExtended_user user;
  SFLExtended_url url;
  SFLExtended_mpls mpls;
  SFLExtended_nat nat;
  SFLExtended_mpls_tunnel mpls_tunnel;
  SFLExtended_mpls_vc mpls_vc;
  SFLExtended_mpls_FTN mpls_ftn;
  SFLExtended_mpls_LDP_FEC mpls_ldp_fec;
  SFLExtended_vlan_tunnel vlan_tunnel;
  SFLExtended_classification class;
  SFLExtended_classification2 ndpi_class;
  SFLExtended_tag tag;
} SFLFlow_type;

typedef struct _SFLFlow_sample_element {
  struct _SFLFlow_sample_element *nxt;
  u_int32_t tag;  /* SFLFlow_type_tag */
  u_int32_t length;
  SFLFlow_type flowType;
} SFLFlow_sample_element;

enum SFL_sample_tag {
  SFLFLOW_SAMPLE = 1,              /* enterprise = 0 : format = 1 */
  SFLCOUNTERS_SAMPLE = 2,          /* enterprise = 0 : format = 2 */
  SFLFLOW_SAMPLE_EXPANDED = 3,     /* enterprise = 0 : format = 3 */
  SFLCOUNTERS_SAMPLE_EXPANDED = 4, /* enterprise = 0 : format = 4 */
  SFLFLOW_SAMPLE_DROPPED = 5,      /* enterprise = 0 : format = 5 */
  SFLACL_BROCADE_SAMPLE = 8155137  /* enterprise = 1991 : format = 1 */
};
  
/* Format of a single flow sample */

typedef struct _SFLFlow_sample {
  /* u_int32_t tag;    */         /* SFL_sample_tag -- enterprise = 0 : format = 1 */
  /* u_int32_t length; */
  u_int32_t sequence_number;      /* Incremented with each flow sample
				     generated */
  u_int32_t source_id;            /* fsSourceId */
  u_int32_t sampling_rate;        /* fsPacketSamplingRate */
  u_int32_t sample_pool;          /* Total number of packets that could have been
				     sampled (i.e. packets skipped by sampling
				     process + total number of samples) */
  u_int32_t drops;                /* Number of times a packet was dropped due to
				     lack of resources */
  u_int32_t input;                /* SNMP ifIndex of input interface.
				     0 if interface is not known. */
  u_int32_t output;               /* SNMP ifIndex of output interface,
				     0 if interface is not known.
				     Set most significant bit to indicate
				     multiple destination interfaces
				     (i.e. in case of broadcast or multicast)
				     and set lower order bits to indicate
				     number of destination interfaces.
				     Examples:
				     0x00000002  indicates ifIndex = 2
				     0x00000000  ifIndex unknown.
				     0x80000007  indicates a packet sent
				     to 7 interfaces.
				     0x80000000  indicates a packet sent to
				     an unknown number of
				     interfaces greater than 1.*/
  u_int32_t num_elements;
  SFLFlow_sample_element *elements;
} SFLFlow_sample;

  /* same thing, but the expanded version (for full 32-bit ifIndex numbers) */

typedef struct _SFLFlow_sample_expanded {
  /* u_int32_t tag;    */         /* SFL_sample_tag -- enterprise = 0 : format = 1 */
  /* u_int32_t length; */
  u_int32_t sequence_number;      /* Incremented with each flow sample
				     generated */
  u_int32_t ds_class;             /* EXPANDED */
  u_int32_t ds_index;             /* EXPANDED */
  u_int32_t sampling_rate;        /* fsPacketSamplingRate */
  u_int32_t sample_pool;          /* Total number of packets that could have been
				     sampled (i.e. packets skipped by sampling
				     process + total number of samples) */
  u_int32_t drops;                /* Number of times a packet was dropped due to
				     lack of resources */
  u_int32_t inputFormat;          /* EXPANDED */
  u_int32_t input;                /* SNMP ifIndex of input interface.
				     0 if interface is not known. */
  u_int32_t outputFormat;         /* EXPANDED */
  u_int32_t output;               /* SNMP ifIndex of output interface,
				     0 if interface is not known. */
  u_int32_t num_elements;
  SFLFlow_sample_element *elements;
} SFLFlow_sample_expanded;

/* Counter types */

/* Generic interface counters - see RFC 1573, 2233 */

typedef struct _SFLIf_counters {
  u_int32_t ifIndex;
  u_int32_t ifType;
  u_int64_t ifSpeed;
  u_int32_t ifDirection;        /* Derived from MAU MIB (RFC 2668)
				   0 = unknown, 1 = full-duplex,
				   2 = half-duplex, 3 = in, 4 = out */
  u_int32_t ifStatus;           /* bit field with the following bits assigned:
				   bit 0 = ifAdminStatus (0 = down, 1 = up)
				   bit 1 = ifOperStatus (0 = down, 1 = up) */
  u_int64_t ifInOctets;
  u_int32_t ifInUcastPkts;
  u_int32_t ifInMulticastPkts;
  u_int32_t ifInBroadcastPkts;
  u_int32_t ifInDiscards;
  u_int32_t ifInErrors;
  u_int32_t ifInUnknownProtos;
  u_int64_t ifOutOctets;
  u_int32_t ifOutUcastPkts;
  u_int32_t ifOutMulticastPkts;
  u_int32_t ifOutBroadcastPkts;
  u_int32_t ifOutDiscards;
  u_int32_t ifOutErrors;
  u_int32_t ifPromiscuousMode;
} SFLIf_counters;

/* Ethernet interface counters - see RFC 2358 */
typedef struct _SFLEthernet_counters {
  u_int32_t dot3StatsAlignmentErrors;
  u_int32_t dot3StatsFCSErrors;
  u_int32_t dot3StatsSingleCollisionFrames;
  u_int32_t dot3StatsMultipleCollisionFrames;
  u_int32_t dot3StatsSQETestErrors;
  u_int32_t dot3StatsDeferredTransmissions;
  u_int32_t dot3StatsLateCollisions;
  u_int32_t dot3StatsExcessiveCollisions;
  u_int32_t dot3StatsInternalMacTransmitErrors;
  u_int32_t dot3StatsCarrierSenseErrors;
  u_int32_t dot3StatsFrameTooLongs;
  u_int32_t dot3StatsInternalMacReceiveErrors;
  u_int32_t dot3StatsSymbolErrors;
} SFLEthernet_counters;

/* Token ring counters - see RFC 1748 */

typedef struct _SFLTokenring_counters {
  u_int32_t dot5StatsLineErrors;
  u_int32_t dot5StatsBurstErrors;
  u_int32_t dot5StatsACErrors;
  u_int32_t dot5StatsAbortTransErrors;
  u_int32_t dot5StatsInternalErrors;
  u_int32_t dot5StatsLostFrameErrors;
  u_int32_t dot5StatsReceiveCongestions;
  u_int32_t dot5StatsFrameCopiedErrors;
  u_int32_t dot5StatsTokenErrors;
  u_int32_t dot5StatsSoftErrors;
  u_int32_t dot5StatsHardErrors;
  u_int32_t dot5StatsSignalLoss;
  u_int32_t dot5StatsTransmitBeacons;
  u_int32_t dot5StatsRecoverys;
  u_int32_t dot5StatsLobeWires;
  u_int32_t dot5StatsRemoves;
  u_int32_t dot5StatsSingles;
  u_int32_t dot5StatsFreqErrors;
} SFLTokenring_counters;

/* 100 BaseVG interface counters - see RFC 2020 */

typedef struct _SFLVg_counters {
  u_int32_t dot12InHighPriorityFrames;
  u_int64_t dot12InHighPriorityOctets;
  u_int32_t dot12InNormPriorityFrames;
  u_int64_t dot12InNormPriorityOctets;
  u_int32_t dot12InIPMErrors;
  u_int32_t dot12InOversizeFrameErrors;
  u_int32_t dot12InDataErrors;
  u_int32_t dot12InNullAddressedFrames;
  u_int32_t dot12OutHighPriorityFrames;
  u_int64_t dot12OutHighPriorityOctets;
  u_int32_t dot12TransitionIntoTrainings;
  u_int64_t dot12HCInHighPriorityOctets;
  u_int64_t dot12HCInNormPriorityOctets;
  u_int64_t dot12HCOutHighPriorityOctets;
} SFLVg_counters;

typedef struct _SFLVlan_counters {
  u_int32_t vlan_id;
  u_int64_t octets;
  u_int32_t ucastPkts;
  u_int32_t multicastPkts;
  u_int32_t broadcastPkts;
  u_int32_t discards;
} SFLVlan_counters;

/* Counters data */

enum SFLCounters_type_tag {
  /* enterprise = 0, format = ... */
  SFLCOUNTERS_GENERIC      = 1,
  SFLCOUNTERS_ETHERNET     = 2,
  SFLCOUNTERS_TOKENRING    = 3,
  SFLCOUNTERS_VG           = 4,
  SFLCOUNTERS_VLAN         = 5
};

typedef union _SFLCounters_type {
  SFLIf_counters generic;
  SFLEthernet_counters ethernet;
  SFLTokenring_counters tokenring;
  SFLVg_counters vg;
  SFLVlan_counters vlan;
} SFLCounters_type;

typedef struct _SFLCounters_sample_element {
  struct _SFLCounters_sample_element *nxt; /* linked list */
  u_int32_t tag; /* SFLCounters_type_tag */
  u_int32_t length;
  SFLCounters_type counterBlock;
} SFLCounters_sample_element;

typedef struct _SFLCounters_sample {
  /* u_int32_t tag;    */       /* SFL_sample_tag -- enterprise = 0 : format = 2 */
  /* u_int32_t length; */
  u_int32_t sequence_number;    /* Incremented with each counters sample
				   generated by this source_id */
  u_int32_t source_id;          /* fsSourceId */
  u_int32_t num_elements;
  SFLCounters_sample_element *elements;
} SFLCounters_sample;

/* same thing, but the expanded version, so ds_index can be a full 32 bits */
typedef struct _SFLCounters_sample_expanded {
  /* u_int32_t tag;    */       /* SFL_sample_tag -- enterprise = 0 : format = 2 */
  /* u_int32_t length; */
  u_int32_t sequence_number;    /* Incremented with each counters sample
				   generated by this source_id */
  u_int32_t ds_class;           /* EXPANDED */
  u_int32_t ds_index;           /* EXPANDED */
  u_int32_t num_elements;
  SFLCounters_sample_element *elements;
} SFLCounters_sample_expanded;

#define SFLADD_ELEMENT(_sm, _el) do { (_el)->nxt = (_sm)->elements; (_sm)->elements = (_el); } while(0)

/* Format of a sample datagram */

enum SFLDatagram_version {
  SFLDATAGRAM_VERSION2 = 2,
  SFLDATAGRAM_VERSION4 = 4,
  SFLDATAGRAM_VERSION5 = 5
};

typedef struct _SFLSample_datagram_hdr {
  u_int32_t datagram_version;      /* (enum SFLDatagram_version) = VERSION5 = 5 */
  SFLAddress agent_address;        /* IP address of sampling agent */
  u_int32_t sub_agent_id;          /* Used to distinguishing between datagram
                                      streams from separate agent sub entities
                                      within an device. */
  u_int32_t sequence_number;       /* Incremented with each sample datagram
				      generated */
  u_int32_t uptime;                /* Current time (in milliseconds since device
				      last booted). Should be set as close to
				      datagram transmission time as possible.*/
  u_int32_t num_records;           /* Number of tag-len-val flow/counter records to follow */
} SFLSample_datagram_hdr;

#define SFL_MAX_DATAGRAM_SIZE 1500
#define SFL_MIN_DATAGRAM_SIZE 200
#define SFL_DEFAULT_DATAGRAM_SIZE 1400

#define SFL_DATA_PAD 400


typedef struct _SFSample {
  struct timeval *ts;
  struct sockaddr_storage sourceIP;
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
  u_int32_t dcd_flowLabel;
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
  u_int32_t cvlan;
  u_int32_t cvlan_priority;

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
  u_char *ip_payload;
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

extern void readv2v4FlowSample(SFSample *, struct packet_ptrs_vector *, struct plugin_requests *);
extern void readv5FlowSample(SFSample *, int, struct packet_ptrs_vector *, struct plugin_requests *, int);
extern void readv2v4CountersSample(SFSample *, struct packet_ptrs_vector *);
extern void readv5CountersSample(SFSample *, int, struct packet_ptrs_vector *);
extern void skipv5Sample(SFSample *);
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
extern void readExtendedClass2(SFSample *);
extern void readExtendedTag(SFSample *);
extern void readFlowSample_header(SFSample *);
extern void readFlowSample_ethernet(SFSample *);
extern void readFlowSample_IPv4(SFSample *);
extern void readFlowSample_IPv6(SFSample *);

extern char *getPointer(SFSample *);
extern u_int32_t getData32(SFSample *);
extern u_int32_t getData32_nobswap(SFSample *);
extern u_int64_t getData64(SFSample *);
extern u_int32_t getAddress(SFSample *, SFLAddress *);
extern char *printTag(u_int32_t, char *, int);
extern void skipBytes(SFSample *, int);
extern int skipBytesAndCheck(SFSample *, int);
extern int lengthCheck(SFSample *, u_char *, u_int32_t);
extern u_int32_t getString(SFSample *, char *, u_int32_t);


#if defined(__cplusplus)
}  /* extern "C" */
#endif

#endif /* SFLOW_H */

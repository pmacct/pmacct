/* Netflow stuff */

/*  NetFlow Export Version 1 Header Format  */
struct struct_header_v1  {
  u_int16_t version;		/* Current version = 1 */
  u_int16_t count;		/* The number of records in PDU. */
  u_int32_t SysUptime;		/* Current time in msecs since router booted */
  u_int32_t unix_secs;		/* Current seconds since 0000 UTC 1970 */
  u_int32_t unix_nsecs;		/* Residual nanoseconds since 0000 UTC 1970 */
};

/*  NetFlow Export Version 5 Header Format  */
struct struct_header_v5 {
  u_int16_t version;		/* Version = 5 */
  u_int16_t count;		/* The number of records in PDU. */
  u_int32_t SysUptime;		/* Current time in msecs since router booted */
  u_int32_t unix_secs;		/* Current seconds since 0000 UTC 1970 */
  u_int32_t unix_nsecs;		/* Residual nanoseconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;	/* Sequence number of total flows seen */
  unsigned char engine_type;    /* Type of flow switching engine (RP,VIP,etc.) */
  unsigned char engine_id;      /* Slot number of the flow switching engine */
  u_int16_t sampling;
};

/*  NetFlow Export Version 7 Header Format  */
struct struct_header_v7 {
  u_int16_t version;		/* Version = 7 */
  u_int16_t count;		/* The number of records in the PDU */
  u_int32_t SysUptime;		/* Current time in millisecs since router booted */
  u_int32_t unix_secs;		/* Current seconds since 0000 UTC 1970 */
  u_int32_t unix_nsecs;		/* Residual nanoseconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;	/* Seq counter of total flows seen */
  u_int8_t  engine_type;	/* Type of flow switching engine (RP,VIP,etc.) */
  u_int8_t  engine_id;		/* Slot number of the flow switching engine */
  u_int16_t reserved;
};

/*  NetFlow Export Version 8 Header Format  */
struct struct_header_v8 {
  u_int16_t version;       	/* Version = 8 */
  u_int16_t count;         	/* The number of records in the PDU */
  u_int32_t SysUptime;     	/* Current time in millisecs since router booted */
  u_int32_t unix_secs;     	/* Current seconds since 0000 UTC 1970 */
  u_int32_t unix_nsecs;    	/* Residual nanoseconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;	/* Seq counter of total flows seen */
  unsigned char engine_type;	/* Type of flow switching engine (RP,VIP,etc.) */
  unsigned char engine_id;	/* Slot number of the flow switching engine */
  u_int8_t  aggregation;	/* Aggregation method being used */
  u_int8_t  agg_version;	/* Version of the aggregation export */
  u_int32_t reserved;
};

/*  NetFlow Export Version 9 Header Format  */
struct struct_header_v9 {
  u_int16_t version;		/* version = 9 */
  u_int16_t count;		/* The number of records in PDU. */
  u_int32_t SysUptime;		/* Current time in msecs since router booted */
  u_int32_t unix_secs;		/* Current seconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;	/* Sequence number of total flows seen */
  u_int32_t source_id;		/* Source id */
};

struct struct_header_ipfix {
  u_int16_t version;            /* version = 10 */
  u_int16_t len;                /* Total length of the IPFIX Message */
  u_int32_t unix_secs;          /* Current seconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;      /* Sequence number of total flows seen */
  u_int32_t source_id;          /* Source id */
};

/* NetFlow Export version 1 */
struct struct_export_v1 {
  struct in_addr srcaddr;	/* Source IP Address */
  struct in_addr dstaddr;	/* Destination IP Address */
  struct in_addr nexthop;	/* Next hop router's IP Address */
  u_int16_t input;		/* Input interface index */
  u_int16_t output;    		/* Output interface index */
  u_int32_t dPkts;      	/* Packets sent in Duration (milliseconds between 1st & last packet in this flow)*/
  u_int32_t dOctets;    	/* Octets sent in Duration (milliseconds between 1st & last packet in this flow)*/
  u_int32_t First;      	/* SysUptime at start of flow */
  u_int32_t Last;       	/* and of last packet of the flow */
  u_int16_t srcport;   		/* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport;   		/* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t pad;       		/* pad to word boundary */
  unsigned char prot;           /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  unsigned char tos;            /* IP Type-of-Service */
  unsigned char pad_2[8];	/* pad to word boundary */
};

/* NetFlow Export version 5 */
struct struct_export_v5 {
  struct in_addr srcaddr;       /* Source IP Address */
  struct in_addr dstaddr;       /* Destination IP Address */
  struct in_addr nexthop;       /* Next hop router's IP Address */
  u_int16_t input;   		/* Input interface index */
  u_int16_t output;  		/* Output interface index */
  u_int32_t dPkts;    		/* Packets sent in Duration (milliseconds between 1st & last packet in this flow) */
  u_int32_t dOctets;  		/* Octets sent in Duration (milliseconds between 1st & last packet in this flow) */
  u_int32_t First;    		/* SysUptime at start of flow */
  u_int32_t Last;     		/* and of last packet of the flow */
  u_int16_t srcport; 		/* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport; 		/* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  unsigned char pad;          	/* pad to word boundary */
  unsigned char tcp_flags;    	/* Cumulative OR of tcp flags */
  unsigned char prot;         	/* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  unsigned char tos;          	/* IP Type-of-Service */
  u_int16_t src_as;  		/* source peer/origin Autonomous System */
  u_int16_t dst_as;  		/* dst peer/origin Autonomous System */
  unsigned char src_mask;       /* source route's mask bits */ 
  unsigned char dst_mask;       /* destination route's mask bits */
  u_int16_t pad_1;   		/* pad to word boundary */
};

/* NetFlow Export version 7 */
struct struct_export_v7 {
  u_int32_t srcaddr;		/* Source IP Address */
  u_int32_t dstaddr;		/* Destination IP Address */
  u_int32_t nexthop;		/* Next hop router's IP Address */
  u_int16_t input;		/* Input interface index */
  u_int16_t output;		/* Output interface index */
  u_int32_t dPkts;		/* Packets sent in Duration */
  u_int32_t dOctets;		/* Octets sent in Duration. */
  u_int32_t First;		/* SysUptime at start of flow */
  u_int32_t Last;		/* and of last packet of flow */
  u_int16_t srcport;		/* TCP/UDP source port number or equivalent */
  u_int16_t dstport;		/* TCP/UDP destination port number or equiv */
  u_int8_t  pad;
  u_int8_t  tcp_flags;		/* Cumulative OR of tcp flags */
  u_int8_t  prot;		/* IP protocol, e.g., 6=TCP, 17=UDP, ... */
  u_int8_t  tos;		/* IP Type-of-Service */
  u_int16_t src_as;		/* originating AS of source address */
  u_int16_t dst_as;		/* originating AS of destination address */
  u_int8_t  src_mask;		/* source address prefix mask bits */
  u_int8_t  dst_mask;		/* destination address prefix mask bits */
  u_int16_t drops;
  u_int32_t router_sc;		/* Router which is shortcut by switch */
};

struct struct_export_v8_1 {
  u_int32_t dFlows;     /* Number of flows */
  u_int32_t dPkts;      /* Packets sent in duration */
  u_int32_t dOctets;    /* Octets sent in duration */
  u_int32_t First;      /* SysUpTime at start of flow */
  u_int32_t Last;       /* and of last packet of flow */
  u_int16_t src_as;     /* originating AS of source address */
  u_int16_t dst_as;     /* originating AS of destination address */
  u_int16_t input;      /* input interface index */
  u_int16_t output;     /* output interface index */
};

struct struct_export_v8_2 {
  u_int32_t dFlows;     /* Number of flows */
  u_int32_t dPkts;      /* Packets sent in duration */
  u_int32_t dOctets;    /* Octets sent in duration */
  u_int32_t First;      /* SysUpTime at start of flow */
  u_int32_t Last;       /* and of last packet of flow */
  u_int8_t  prot;       /* IP protocol */
  u_int8_t  pad;
  u_int16_t reserved;
  u_int16_t srcport;    /* TCP/UDP source port number of equivalent */
  u_int16_t dstport;    /* TCP/UDP dst port number of equivalent */
};

struct struct_export_v8_3 {
  u_int32_t dFlows;     /* Number of flows */
  u_int32_t dPkts;      /* Packets sent in duration */
  u_int32_t dOctets;    /* Octets sent in duration */
  u_int32_t First;      /* SysUpTime at start of flow */
  u_int32_t Last;       /* and of last packet of flow */
  u_int32_t src_prefix;
  u_int8_t  src_mask;
  u_int8_t  pad;
  u_int16_t src_as;
  u_int16_t input;
  u_int16_t reserved;
};

struct struct_export_v8_4 {
  u_int32_t dFlows;     /* Number of flows */
  u_int32_t dPkts;      /* Packets sent in duration */
  u_int32_t dOctets;    /* Octets sent in duration */
  u_int32_t First;      /* SysUpTime at start of flow */
  u_int32_t Last;       /* and of last packet of flow */
  u_int32_t dst_prefix;
  u_int8_t  dst_mask;
  u_int8_t  pad;
  u_int16_t dst_as;
  u_int16_t output;
  u_int16_t reserved;
};

struct struct_export_v8_5 {
  u_int32_t dFlows;     /* Number of flows */
  u_int32_t dPkts;      /* Packets sent in duration */
  u_int32_t dOctets;    /* Octets sent in duration */
  u_int32_t First;      /* SysUpTime at start of flow */
  u_int32_t Last;       /* and of last packet of flow */
  u_int32_t src_prefix;
  u_int32_t dst_prefix;
  u_int8_t  dst_mask;
  u_int8_t  src_mask;
  u_int16_t reserved;
  u_int16_t src_as;
  u_int16_t dst_as;
  u_int16_t input;
  u_int16_t output;
};

struct struct_export_v8_6 {
  u_int32_t dstaddr;   /* destination IP address */
  u_int32_t dPkts;      /* Packets sent in duration */
  u_int32_t dOctets;    /* Octets sent in duration */
  u_int32_t First;      /* SysUpTime at start of flow */
  u_int32_t Last;       /* and of last packet of flow */
  u_int16_t output;     /* output interface index */
  u_int8_t  tos;        /* tos */
  u_int8_t  marked_tos; /* tos of pkts that exceeded the contract */
  u_int32_t extra_pkts; /* packets that exceed the contract */
  u_int32_t router_sc;  /* IP address of the router being shortcut */
};

struct struct_export_v8_7 {
  u_int32_t dstaddr;    /* destination IP address */
  u_int32_t srcaddr;    /* source address */
  u_int32_t dPkts;      /* Packets sent in duration */
  u_int32_t dOctets;    /* Octets sent in duration */
  u_int32_t First;      /* SysUpTime at start of flow */
  u_int32_t Last;       /* and of last packet of flow */
  u_int16_t output;     /* output interface index */
  u_int16_t input;      /* input interface index */
  u_int8_t  tos;        /* tos */
  u_int8_t  marked_tos; /* tos of pkts that exceeded the contract */
  u_int16_t reserved;
  u_int32_t extra_pkts; /* packets that exceed the contract */
  u_int32_t router_sc;  /* IP address of the router being shortcut */
};

struct struct_export_v8_8 {
  u_int32_t dstaddr;    /* destination IP address */
  u_int32_t srcaddr;    /* source IP address */
  u_int16_t dstport;    /* TCP/UDP destination port */
  u_int16_t srcport;    /* TCP/UDP source port */
  u_int32_t dPkts;      /* Packets sent in duration */
  u_int32_t dOctets;    /* Octets sent in duration */
  u_int32_t First;      /* SysUpTime at start of flow */
  u_int32_t Last;       /* and of last packet of flow */
  u_int16_t output;     /* output interface index */
  u_int16_t input;      /* input interface index */
  u_int8_t  tos;        /* tos */
  u_int8_t  prot;       /* protocol */
  u_int8_t  marked_tos; /* tos of pkts that exceeded the contract */
  u_int8_t  reserved;
  u_int32_t extra_pkts; /* packets that exceed the contract */
  u_int32_t router_sc;  /* IP address of the router being shortcut */
};

struct struct_export_v8_9 {
  u_int32_t dFlows;     /* Number of flows */
  u_int32_t dPkts;      /* Packets sent in duration */
  u_int32_t dOctets;    /* Octets sent in duration */
  u_int32_t First;      /* SysUpTime at start of flow */
  u_int32_t Last;       /* and of last packet of flow */
  u_int16_t src_as;     /* originating AS of source address */
  u_int16_t dst_as;     /* originating AS of destination address */
  u_int16_t input;      /* input interface index */
  u_int16_t output;     /* output interface index */
  u_int8_t  tos;        /* tos */
  u_int8_t  pad;
  u_int16_t reserved;
};

struct struct_export_v8_10 {
  u_int32_t dFlows;     /* Number of flows */
  u_int32_t dPkts;      /* Packets sent in duration */
  u_int32_t dOctets;    /* Octets sent in duration */
  u_int32_t First;      /* SysUpTime at start of flow */
  u_int32_t Last;       /* and of last packet of flow */
  u_int8_t  prot;       /* IP protocol */
  u_int8_t  tos;        /* tos */
  u_int16_t reserved;
  u_int16_t srcport;    /* TCP/UDP source port number of equivalent */
  u_int16_t dstport;    /* TCP/UDP dst port number of equivalent */
  u_int16_t input;      /* input interface */
  u_int16_t output;     /* output interface index */
};

struct struct_export_v8_11 {
  u_int32_t dFlows;     /* Number of flows */
  u_int32_t dPkts;      /* Packets sent in duration */
  u_int32_t dOctets;    /* Octets sent in duration */
  u_int32_t First;      /* SysUpTime at start of flow */
  u_int32_t Last;       /* and of last packet of flow */
  u_int32_t src_prefix; /* Source Prefix */
  u_int8_t  src_mask;   /* Source Prefix mask length */
  u_int8_t  tos;        /* tos */
  u_int16_t src_as;     /* Source AS */
  u_int16_t input;      /* input interface */
  u_int16_t reserved;
};

struct struct_export_v8_12 {
  u_int32_t dFlows;     /* Number of flows */
  u_int32_t dPkts;      /* Packets sent in duration */
  u_int32_t dOctets;    /* Octets sent in duration */
  u_int32_t First;      /* SysUpTime at start of flow */
  u_int32_t Last;       /* and of last packet of flow */
  u_int32_t dst_prefix; /* Destination Prefix */
  u_int8_t  dst_mask;   /* Destination Prefix mask length */
  u_int8_t  tos;        /* tos */
  u_int16_t dst_as;     /* Destination AS */
  u_int16_t output;     /* output interface */
  u_int16_t reserved;
};

struct struct_export_v8_13 {
  u_int32_t dFlows;     /* Number of flows */
  u_int32_t dPkts;      /* Packets sent in duration */
  u_int32_t dOctets;    /* Octets sent in duration */
  u_int32_t First;      /* SysUpTime at start of flow */
  u_int32_t Last;       /* and of last packet of flow */
  u_int32_t src_prefix; /* Source Prefix */
  u_int32_t dst_prefix; /* Destination Prefix */
  u_int8_t  dst_mask;   /* Destination Prefix mask length */
  u_int8_t  src_mask;   /* Source Prefix mask length */
  u_int8_t  tos;        /* tos */
  u_int8_t  pad;
  u_int16_t src_as;     /* Source AS */
  u_int16_t dst_as;     /* Destination AS */
  u_int16_t input;      /* input interface */
  u_int16_t output;     /* output interface */
};

struct struct_export_v8_14 {
  u_int32_t dFlows;     /* Number of flows */
  u_int32_t dPkts;      /* Packets sent in duration */
  u_int32_t dOctets;    /* Octets sent in duration */
  u_int32_t First;      /* SysUpTime at start of flow */
  u_int32_t Last;       /* and of last packet of flow */
  u_int32_t src_prefix; /* Source Prefix */
  u_int32_t dst_prefix; /* Destination Prefix */
  u_int8_t  dst_mask;   /* Destination Prefix mask length */
  u_int8_t  src_mask;   /* Source Prefix mask length */
  u_int8_t  tos;        /* tos */
  u_int8_t  prot;       /* protocol */
  u_int16_t srcport;    /* Source port */
  u_int16_t dstport;    /* Destination port */
  u_int16_t input;      /* input interface */
  u_int16_t output;     /* output interface */
};

/* NetFlow Export version 9 */
struct template_field_v9 {
  u_int16_t type;
  u_int16_t len;
}; 

struct template_hdr_v9 {
  u_int16_t template_id;
  u_int16_t num;
};

struct options_template_hdr_v9 {
  u_int16_t template_id;
  u_int16_t scope_len;
  u_int16_t option_len;
};

/* IPFIX: option field count and scope field count apparently inverted compared to NetFlow v9 */
struct options_template_hdr_ipfix {
  u_int16_t template_id;
  u_int16_t option_count;
  u_int16_t scope_count;
};

struct data_hdr_v9 {
  u_int16_t flow_id; /* == 0: template; == 1: options template; >= 256: data */
  u_int16_t flow_len;
};

/* defines */
#define DEFAULT_NFACCTD_PORT 2100
#define NETFLOW_MSG_SIZE PKT_MSG_SIZE
#define V1_MAXFLOWS 24  /* max records in V1 packet */
#define V5_MAXFLOWS 30  /* max records in V5 packet */
#define V7_MAXFLOWS 27  /* max records in V7 packet */
#define V8_1_MAXFLOWS  51  /* max records in V8 AS packet */
#define V8_2_MAXFLOWS  51  /* max records in V8 PROTO PORT packet */
#define V8_3_MAXFLOWS  44  /* max records in V8 SRC PREFIX packet */
#define V8_4_MAXFLOWS  44  /* max records in V8 DST PREFIX packet */
#define V8_5_MAXFLOWS  35  /* max records in V8 PREFIX packet */
#define V8_6_MAXFLOWS  44  /* max records in V8 DESTONLY packet */
#define V8_7_MAXFLOWS  35  /* max records in V8 SRC_DEST packet */
#define V8_8_MAXFLOWS  32  /* max records in V8 FULL_FLOW packet */
#define V8_9_MAXFLOWS  44  /* max records in V8 AS_TOS packet */
#define V8_10_MAXFLOWS 44  /* max records in V8 PROT_PORT_TOS packet */
#define V8_11_MAXFLOWS 44  /* max records in V8 SRC_PREFIX_TOS packet */
#define V8_12_MAXFLOWS 44  /* max records in V8 DST_PREFIX_TOS packet */
#define V8_13_MAXFLOWS 35  /* max records in V8 PREFIX_TOS packet */
#define V8_14_MAXFLOWS 35  /* max records in V8 PREFIX_PORT_TOS packet */
#define TEMPLATE_CACHE_ENTRIES 255

#define NF_TIME_MSECS 0 /* times are in msecs */
#define NF_TIME_SECS 1 /* times are in secs */ 
#define NF_TIME_NEW 2 /* ignore netflow engine times and generate new ones */ 

#define IPFIX_TPL_EBIT                  0x8000 /* IPFIX telmplate enterprise bit */
#define IPFIX_VARIABLE_LENGTH           65535

/* NetFlow V9 stuff */
#define NF9_TEMPLATE_FLOWSET_ID         0
#define NF9_OPTIONS_FLOWSET_ID          1
#define NF9_MIN_RECORD_FLOWSET_ID       256
#define NF9_MAX_DEFINED_FIELD		384

#define IES_PER_TPL_EXT_DB_ENTRY        32
#define TPL_EXT_DB_ENTRIES              8
#define TPL_LIST_ENTRIES                256
#define TPL_TYPE_LEGACY                 0
#define TPL_TYPE_EXT_DB                 1

/* Flowset record types the we care about */
#define NF9_IN_BYTES			1
#define NF9_IN_PACKETS			2
#define NF9_FLOWS			3
#define NF9_L4_PROTOCOL			4
#define NF9_SRC_TOS                     5
#define NF9_TCP_FLAGS                   6
#define NF9_L4_SRC_PORT                 7
#define NF9_IPV4_SRC_ADDR               8
#define NF9_SRC_MASK                    9
#define NF9_INPUT_SNMP                  10
#define NF9_L4_DST_PORT                 11
#define NF9_IPV4_DST_ADDR               12
#define NF9_DST_MASK                    13
#define NF9_OUTPUT_SNMP                 14
#define NF9_IPV4_NEXT_HOP               15
#define NF9_SRC_AS                      16
#define NF9_DST_AS                      17
#define NF9_BGP_IPV4_NEXT_HOP		18
#define NF9_MUL_DST_PKTS                19
#define NF9_MUL_DST_BYTES               20
/* ... */
#define NF9_LAST_SWITCHED               21
#define NF9_FIRST_SWITCHED              22
#define NF9_OUT_BYTES			23
#define NF9_OUT_PACKETS			24
/* ... */
#define NF9_IPV6_SRC_ADDR               27
#define NF9_IPV6_DST_ADDR               28
#define NF9_IPV6_SRC_MASK               29
#define NF9_IPV6_DST_MASK               30
#define NF9_ICMP_TYPE                   32
/* ... */
#define NF9_ENGINE_TYPE                 38
#define NF9_ENGINE_ID                   39
/* ... */
#define NF9_IN_SRC_MAC                  56
#define NF9_OUT_DST_MAC                 57
#define NF9_IN_VLAN                     58
#define NF9_OUT_VLAN                    59
#define NF9_IP_PROTOCOL_VERSION         60
#define NF9_DIRECTION                   61
#define NF9_IPV6_NEXT_HOP		62
#define NF9_BGP_IPV6_NEXT_HOP		63
/* ... */
#define NF9_MPLS_LABEL_1		70
#define NF9_MPLS_LABEL_2		71
#define NF9_MPLS_LABEL_3		72
#define NF9_MPLS_LABEL_4		73
#define NF9_MPLS_LABEL_5		74
#define NF9_MPLS_LABEL_6		75
#define NF9_MPLS_LABEL_7		76
#define NF9_MPLS_LABEL_8		77
#define NF9_MPLS_LABEL_9		78
#define NF9_MPLS_LABEL_10		79
#define NF9_IN_DST_MAC			80 
#define NF9_OUT_SRC_MAC			81 
/* ... */
#define NF9_FLOW_BYTES			85 
#define NF9_FLOW_PACKETS		86 
/* ... */
#define NF9_PEER_SRC_AS			128
#define NF9_PEER_DST_AS			129
#define NF9_EXPORTER_IPV4_ADDRESS	130
#define NF9_EXPORTER_IPV6_ADDRESS	131
/* ... */
#define NF9_FIRST_SWITCHED_SEC		150
#define NF9_LAST_SWITCHED_SEC		151
#define NF9_FIRST_SWITCHED_MSEC		152
#define NF9_LAST_SWITCHED_MSEC		153
/* ... */
#define NF9_UDP_SRC_PORT                180
#define NF9_UDP_DST_PORT                181
#define NF9_TCP_SRC_PORT                182
#define NF9_TCP_DST_PORT                183
/* ... */
#define NF9_CUST_TAG			201
#define NF9_CUST_TAG2			202
/* ... */
#define NF9_POST_NAT_IPV4_SRC_ADDR	225
#define NF9_POST_NAT_IPV4_DST_ADDR	226
#define NF9_POST_NAT_IPV4_SRC_PORT	227
#define NF9_POST_NAT_IPV4_DST_PORT	228
/* ... */
#define NF9_NAT_EVENT			230
/* ... */
#define NF9_ETHERTYPE			256
/* ... */
#define NF9_OBSERVATION_TIME_SEC	322
#define NF9_OBSERVATION_TIME_MSEC	323
/* ... */
#define NF9_ASA_XLATE_IPV4_SRC_ADDR	40001
#define NF9_ASA_XLATE_IPV4_DST_ADDR	40002
#define NF9_ASA_XLATE_L4_SRC_PORT	40003
#define NF9_ASA_XLATE_L4_DST_PORT	40004

/* Sampling */
#define NF9_SAMPLING_INTERVAL		34
#define NF9_SAMPLING_ALGORITHM		35
#define NF9_FLOW_SAMPLER_ID		48
#define NF9_FLOW_SAMPLER_MODE		49
#define NF9_FLOW_SAMPLER_INTERVAL	50

/* Classification */
#define NF9_APPLICATION_DESC		94
#define NF9_APPLICATION_ID		95
#define NF9_APPLICATION_NAME		96

#define NF9_OPT_SCOPE_SYSTEM		1
#define NF9_OPT_SCOPE_IF		2
#define NF9_OPT_SCOPE_LC		3
#define NF9_OPT_SCOPE_CACHE		4
#define NF9_OPT_SCOPE_TPL		5

#define MAX_TPL_DESC_LIST 81
static char *tpl_desc_list[] = {
  "",
  "in bytes",
  "in packets",
  "flows",
  "L4 protocol",
  "tos",
  "tcp flags",
  "L4 src port",
  "IPv4 src addr",
  "IPv4 src mask",
  "input snmp",
  "L4 dst port",
  "IPv4 dst addr",
  "IPv4 dst mask",
  "output snmp",
  "IPv4 next hop",
  "src as",
  "dst as",
  "BGP IPv4 next hop",
  "", "",
  "last switched",
  "first switched",
  "out bytes",
  "out packets",
  "", "",
  "IPv6 src addr",
  "IPv6 dst addr",
  "IPv6 src mask",
  "IPv6 dst mask",
  "",
  "icmp type", 
  "",
  "sampling interval",
  "sampling algorithm",
  "",
  "", "", "", "",
  "", "", "", "",
  "", "", "",
  "sampler ID",
  "sampler mode",
  "sampler interval",
  "", "", "", "",
  "",
  "in src mac",
  "out dst mac",
  "", "",
  "ip version",
  "direction",
  "IPv6 next hop",
  "IPv6 BGP next hop",
  "",
  "", "", "", "",
  "",
  "mpls label 1",
  "mpls label 2",
  "mpls label 3",
  "mpls label 4",
  "mpls label 5",
  "mpls label 6",
  "mpls label 7",
  "mpls label 8",
  "mpls label 9",
  "mpls label 10",
  "in dst mac",
  "out src mac"
};

#define MAX_OPT_TPL_DESC_LIST 100
static char *opt_tpl_desc_list[] = {
  "",
  "scope", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "sampler ID",
  "sampler algorithm", "sampler interval", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "",
  "", "", "sampler name",
  "", "", "",
  "", "", "",
  "", "", "",
  "app desc", "app id", "app name",
  "", "", "",
  ""
};

/* Ordered Template field */
struct otpl_field {
  u_int16_t off;
  u_int16_t len;
  u_int16_t tpl_len;
};

/* Unsorted Template field */
struct utpl_field {
  u_int32_t pen;
  u_int16_t type;
  u_int16_t off;
  u_int16_t len;
  u_int16_t tpl_len;
};

/* Template field database */
struct tpl_field_db {
  struct utpl_field ie[IES_PER_TPL_EXT_DB_ENTRY];
};

/* Template field ordered list */
struct tpl_field_list {
  u_int8_t type;
  char *ptr;
};

struct template_cache_entry {
  struct host_addr agent;               /* NetFlow Exporter agent */
  u_int32_t source_id;                  /* Exporter Observation Domain */
  u_int16_t template_id;                /* template ID */
  u_int16_t template_type;              /* Data = 0, Options = 1 */
  u_int16_t num;                        /* number of fields described into template */
  u_int16_t len;                        /* total length of the described flowset */
  u_int8_t vlen;                        /* flag for variable-length fields */
  struct otpl_field tpl[NF9_MAX_DEFINED_FIELD];
  struct tpl_field_db ext_db[TPL_EXT_DB_ENTRIES];
  struct tpl_field_list list[TPL_LIST_ENTRIES];
  struct template_cache_entry *next;
};

struct template_cache {
  u_int16_t num;
  struct template_cache_entry *c[TEMPLATE_CACHE_ENTRIES];
};

typedef void (*v8_filter_handler)(struct packet_ptrs *, void *);
struct v8_handler_entry {
  u_int8_t max_flows;
  u_int8_t exp_size;
  v8_filter_handler fh;
};

/* functions */
#if (!defined __NFACCTD_C)
#define EXT extern
#else
#define EXT
#endif
EXT void process_v1_packet(unsigned char *, u_int16_t, struct packet_ptrs *, struct plugin_requests *);
EXT void process_v5_packet(unsigned char *, u_int16_t, struct packet_ptrs *, struct plugin_requests *);
EXT void process_v7_packet(unsigned char *, u_int16_t, struct packet_ptrs *, struct plugin_requests *);
EXT void process_v8_packet(unsigned char *, u_int16_t, struct packet_ptrs *, struct plugin_requests *);
EXT void process_v9_packet(unsigned char *, u_int16_t, struct packet_ptrs_vector *, struct plugin_requests *, u_int16_t);
EXT void process_raw_packet(unsigned char *, u_int16_t, struct packet_ptrs_vector *, struct plugin_requests *);
EXT u_int16_t NF_evaluate_flow_type(struct template_cache_entry *, struct packet_ptrs *);
EXT u_int16_t NF_evaluate_direction(struct template_cache_entry *, struct packet_ptrs *);
EXT pm_class_t NF_evaluate_classifiers(struct xflow_status_entry_class *, pm_class_t *, struct xflow_status_entry *);
EXT void reset_mac(struct packet_ptrs *);
EXT void reset_mac_vlan(struct packet_ptrs *);
EXT void reset_ip4(struct packet_ptrs *);
EXT void reset_ip6(struct packet_ptrs *);
EXT void notify_malf_packet(short int, char *, struct sockaddr *);
EXT int NF_find_id(struct id_table *, struct packet_ptrs *, pm_id_t *, pm_id_t *);

EXT char *nfv578_check_status(struct packet_ptrs *);
EXT char *nfv9_check_status(struct packet_ptrs *, u_int32_t, u_int32_t, u_int32_t, u_int8_t);

EXT struct template_cache tpl_cache;
EXT struct v8_handler_entry v8_handlers[15];
#undef EXT

#if (!defined __NFV9_TEMPLATE_C)
#define EXT extern
#else
#define EXT
#endif
EXT struct template_cache_entry *handle_template(struct template_hdr_v9 *, struct packet_ptrs *, u_int16_t, u_int32_t, u_int16_t *, u_int16_t);
EXT struct template_cache_entry *find_template(u_int16_t, struct packet_ptrs *, u_int16_t, u_int32_t);
EXT struct template_cache_entry *insert_template(struct template_hdr_v9 *, struct packet_ptrs *, u_int16_t, u_int32_t, u_int16_t *, u_int8_t, u_int16_t);
EXT struct template_cache_entry *refresh_template(struct template_hdr_v9 *, struct template_cache_entry *, struct packet_ptrs *, u_int16_t, u_int32_t, u_int16_t *, u_int8_t, u_int16_t);
EXT void log_template_header(struct template_cache_entry *, struct packet_ptrs *, u_int16_t, u_int32_t, u_int8_t);
EXT void log_opt_template_field(u_int16_t, u_int16_t, u_int16_t, u_int8_t);
EXT void log_template_field(u_int8_t, u_int32_t *, u_int16_t, u_int16_t, u_int16_t, u_int8_t);
EXT void log_template_footer(u_int16_t, u_int8_t);
EXT struct template_cache_entry *insert_opt_template(void *, struct packet_ptrs *, u_int16_t, u_int32_t, u_int8_t, u_int16_t);
EXT struct template_cache_entry *refresh_opt_template(void *, struct template_cache_entry *, struct packet_ptrs *, u_int16_t, u_int32_t, u_int8_t, u_int16_t);

EXT void resolve_vlen_template(char *, struct template_cache_entry *);
EXT u_int8_t get_ipfix_vlen(char *, u_int16_t *);
#undef EXT

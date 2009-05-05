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
  unsigned char dst_mask;       /* destination route's mask bits */
  unsigned char src_mask;       /* source route's mask bits */
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

struct data_hdr_v9 {
  u_int16_t flow_id; /* == 0: template; >= 256: data */
  u_int16_t flow_len;
};

/* defines */
#define DEFAULT_NFACCTD_PORT 2100
#define NETFLOW_MSG_SIZE 1550
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

#define NF_AS_KEEP 0 /* Keep AS numbers in NetFlow packets */
#define NF_AS_NEW 1 /* ignore AS numbers in NetFlow packets and generate new ones */ 

/* NetFlow V9 stuff */
#define NF9_TEMPLATE_FLOWSET_ID         0
#define NF9_OPTIONS_FLOWSET_ID          1
#define NF9_MIN_RECORD_FLOWSET_ID       256
// #define NF9_MAX_DEFINED_FIELD	100
#define NF9_MAX_DEFINED_FIELD		210

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
#define NF9_SRC_MAC                     56
#define NF9_DST_MAC                     57
#define NF9_SRC_VLAN                    58
#define NF9_DST_VLAN                    59
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
/* ... */
#define NF9_CUST_CLASS			200
#define NF9_CUST_TAG			201

#define NF9_FTYPE_IPV4			0
#define NF9_FTYPE_IPV6			1
#define NF9_FTYPE_VLAN			5
#define NF9_FTYPE_VLAN_IPV4		5
#define NF9_FTYPE_VLAN_IPV6		6
#define NF9_FTYPE_MPLS			10
#define NF9_FTYPE_MPLS_IPV4		10
#define NF9_FTYPE_MPLS_IPV6		11
#define NF9_FTYPE_VLAN_MPLS		15	
#define NF9_FTYPE_VLAN_MPLS_IPV4	15
#define NF9_FTYPE_VLAN_MPLS_IPV6	16

/* Ordered Template field */
struct otpl_field {
  u_int16_t off;
  u_int16_t len;
};

struct template_cache_entry {
  struct host_addr agent;		/* NetFlow Exporter agent */
  u_int32_t source_id;			/* Exporter Observation Domain */
  u_int16_t template_id;		/* template ID */
  u_int16_t num;			/* number of fields described into template */ 
  u_int16_t len;			/* total length of the described flowset */
  struct otpl_field tpl[NF9_MAX_DEFINED_FIELD];
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
EXT void process_v9_packet(unsigned char *, u_int16_t, struct packet_ptrs_vector *, struct plugin_requests *);
EXT void load_allow_file(char *, struct hosts_table *);
EXT int check_allow(struct hosts_table *, struct sockaddr *);
EXT u_int16_t NF_evaluate_flow_type(struct template_cache_entry *, struct packet_ptrs *);
EXT void reset_mac(struct packet_ptrs *);
EXT void reset_mac_vlan(struct packet_ptrs *);
EXT void reset_ip4(struct packet_ptrs *);
EXT void reset_ip6(struct packet_ptrs *);
EXT void notify_malf_packet(short int, char *, struct sockaddr *);
EXT int NF_find_id(struct packet_ptrs *);

EXT char *nfv578_check_status(struct packet_ptrs *);
EXT char *nfv9_check_status(struct packet_ptrs *);

EXT struct template_cache tpl_cache;
EXT struct v8_handler_entry v8_handlers[15];
#undef EXT

#if (!defined __NFV9_TEMPLATE_C)
#define EXT extern
#else
#define EXT
#endif
EXT void handle_template_v9(struct template_hdr_v9 *, struct packet_ptrs *);
EXT struct template_cache_entry *find_template_v9(u_int16_t, struct packet_ptrs *);
EXT struct template_cache_entry *insert_template_v9(struct template_hdr_v9 *, struct packet_ptrs *);
EXT void refresh_template_v9(struct template_hdr_v9 *, struct template_cache_entry *, struct packet_ptrs *);
#undef EXT


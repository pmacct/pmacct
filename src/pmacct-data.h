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

#ifndef PMACCT_DATA_H
#define PMACCT_DATA_H

/* defines */
#define PLUGIN_ID_CORE          0
#define PLUGIN_ID_MEMORY        1
#define PLUGIN_ID_PRINT         2
#define PLUGIN_ID_NFPROBE       3
#define PLUGIN_ID_SFPROBE       4
#define PLUGIN_ID_MYSQL		5 
#define PLUGIN_ID_PGSQL         6
#define PLUGIN_ID_SQLITE3       7
#define PLUGIN_ID_TEE		8
#define PLUGIN_ID_MONGODB	9
#define PLUGIN_ID_AMQP		10
#define PLUGIN_ID_KAFKA		11
#define PLUGIN_ID_UNKNOWN	255 

/* vars */
extern int protocols_number;

/* structures */
static const struct _primitives_matrix_struct _primitives_matrix[] = {
  /* primitive, pmacctd, uacctd, nfacctd, sfacctd, pmtelemetryd, pmbgpd, pmbmpd */
  {"L2", 1, 1, 1, 1, 0, 0, 0, ""}, 
  {"cos", 1, 0, 1, 1, 0, 0, 0, "Ethernet CoS, 802.1P"},
  {"etype", 1, 0, 1, 1, 0, 0, 0, "Ethernet Ethertype"},
  {"src_mac", 1, 1, 1, 1, 0, 0, 0, "Source MAC address"},
  {"dst_mac", 1, 1, 1, 1, 0, 0, 0, "Destination MAC address"},
  {"vlan", 1, 1, 1, 1, 0, 0, 0, "Ethernet VLAN, 802.1Q"},
  {"L3", 1, 1, 1, 1, 0, 0, 0, ""}, 
  {"src_host", 1, 1, 1, 1, 0, 0, 0, "Source IPv4/IPv6 address"}, 
  {"dst_host", 1, 1, 1, 1, 0, 0, 0, "Destination IPv4/IPv6 address"},
  {"src_mask", 1, 1, 1, 1, 0, 0, 0, "Source network mask"},
  {"dst_mask", 1, 1, 1, 1, 0, 0, 0, "Destination network mask"},
  {"src_net", 1, 1, 1, 1, 0, 0, 0, "Source IPv4/IPv6 prefix"},
  {"dst_net", 1, 1, 1, 1, 0, 0, 0, "Destination IPv4/IPv6 prefix"},
  {"proto", 1, 1, 1, 1, 0, 0, 0, "IP protocol"},
  {"tos", 1, 1, 1, 1, 0, 0, 0, "IP ToS"},
  {"L4", 1, 1, 1, 1, 0, 0, 0, ""}, 
  {"src_port", 1, 1, 1, 1, 0, 0, 0, "Source TCP/UDP port"},
  {"dst_port", 1, 1, 1, 1, 0, 0, 0, "Destination TCP/UDP port"},
  {"tcpflags", 1, 1, 1, 1, 0, 0, 0, "TCP flags"},
  {"BGP", 1, 1, 1, 1, 0, 0, 0, ""}, 
  {"src_as", 1, 1, 1, 1, 0, 0, 0, "Source ASN"},
  {"dst_as", 1, 1, 1, 1, 0, 0, 0, "Destination ASN"},
  {"as_path", 1, 1, 1, 1, 0, 0, 0, "AS PATH"},
  {"std_comm", 1, 1, 1, 1, 0, 0, 0, "Standard Communities"},
  {"ext_comm", 1, 1, 1, 1, 0, 0, 0, "Extended Communities"},
  {"lrg_comm", 1, 1, 1, 1, 0, 0, 0, "Large Communities"},
  {"local_pref", 1, 1, 1, 1, 0, 0, 0, "Local Preference"},
  {"med", 1, 1, 1, 1, 0, 0, 0, "Multi-Exit Discriminator"},
  {"src_as_path", 1, 1, 1, 1, 0, 0, 0, "Source AS PATH (via reverse BGP lookup)"},
  {"src_std_comm", 1, 1, 1, 1, 0, 0, 0, "Source Standard Communities (via reverse BGP lookup)"},
  {"src_ext_comm", 1, 1, 1, 1, 0, 0, 0, "Source Extended Communities (via reverse BGP lookup)"},
  {"src_lrg_comm", 1, 1, 1, 1, 0, 0, 0, "Source Large Communities (via reverse BGP lookup)"},
  {"src_local_pref", 1, 1, 1, 1, 0, 0, 0, "Source Local Preference (by default via reverse BGP lookup)"},
  {"src_med", 1, 1, 1, 1, 0, 0, 0, "Source MED (by default via reverse BGP lookup)"},
  {"peer_src_as", 1, 1, 1, 1, 0, 0, 0, "Source peer ASN (by default via reverse BGP lookup)"},
  {"peer_dst_as", 1, 1, 1, 1, 0, 0, 0, "Destination peer ASN"},
  {"peer_dst_ip", 1, 1, 1, 1, 0, 0, 0, "BGP next-hop"},
  {"NAT", 1, 1, 1, 1, 0, 0, 0, ""}, 
  {"fw_event", 0, 0, 1, 0, 0, 0, 0, "Firewall event ID"},
  {"nat_event", 0, 0, 1, 0, 0, 0, 0, "NAT event ID"},
  {"post_nat_src_host", 0, 0, 1, 0, 0, 0, 0, "Source IPv4/IPv6 address after NAT translation"},
  {"post_nat_dst_host", 0, 0, 1, 0, 0, 0, 0, "Destination IPv4/IPv6 address after NAT translation"},
  {"post_nat_src_port", 0, 0, 1, 0, 0, 0, 0, "Source TCP/UDP port after NAT translation"},
  {"post_nat_dst_port", 0, 0, 1, 0, 0, 0, 0, "Destination TCP/UDP port after NAT translation"},
  {"TUNNEL", 1, 1, 1, 1, 0, 0, 0, ""}, 
  {"vxlan", 1, 1, 1, 1, 0, 0, 0, "VXLAN Network Identifier"},
  {"tunnel_src_mac", 1, 1, 0, 1, 0, 0, 0, "Tunnel inner Source MAC address"},
  {"tunnel_dst_mac", 1, 1, 0, 1, 0, 0, 0, "Tunnel inner Destination MAC address"},
  {"tunnel_src_host", 1, 1, 0, 1, 0, 0, 0, "Tunnel inner Source IPv4/IPv6 address"},
  {"tunnel_dst_host", 1, 1, 0, 1, 0, 0, 0, "Tunnel inner Destination IPv4/IPv6 address"},
  {"tunnel_proto", 1, 1, 0, 1, 0, 0, 0, "Tunnel inner IP protocol"},
  {"tunnel_tos", 1, 1, 0, 1, 0, 0, 0, "Tunnel inner IP ToS"},
  {"tunnel_src_port", 1, 1, 0, 1, 0, 0, 0, "Tunnel inner Source TCP/UDP port"},
  {"tunnel_dst_port", 1, 1, 0, 1, 0, 0, 0, "Tunnel inner Destination TCP/UDP port"},
  {"MPLS", 1, 1, 1, 1, 0, 0, 0, ""}, 
  {"mpls_label_bottom", 1, 1, 1, 0, 0, 0, 0, "Bottom MPLS label"},
  {"mpls_label_top", 1, 1, 1, 0, 0, 0, 0, "Top MPLS label"},
  {"mpls_stack_depth", 1, 1, 1, 0, 0, 0, 0, "MPLS stack depth"},
  {"mpls_vpn_rd", 0, 0, 1, 1, 0, 0, 0, "MPLS L3 VPN Route Distinguisher"},
  {"mpls_pw_id", 0, 0, 1, 1, 0, 0, 0, "MPLS L2 VPN Pseudowire ID"},
  {"MISC", 1, 1, 1, 1, 0, 0, 0, ""}, 
  {"class", 1, 1, 1, 1, 0, 0, 0, "L7 protocol classification"},
  {"flows", 0, 0, 1, 0, 0, 0, 0, "IP flows"},
  {"src_host_country", 1, 1, 1, 1, 0, 0, 0, "Source IP address GeoIP resolution: country"},
  {"dst_host_country", 1, 1, 1, 1, 0, 0, 0, "Destination IP address GeoIP resolution: country"},
  {"src_host_pocode", 1, 1, 1, 1, 0, 0, 0, "Source IP address GeoIP resolution: postal code"},
  {"dst_host_pocode", 1, 1, 1, 1, 0, 0, 0, "Destination IP address GeoIP resolution: postal code"},
  {"src_host_coords", 1, 1, 1, 1, 0, 0, 0, "Source IP address GeoIP resolution: lat/lon coordinates"},
  {"dst_host_coords", 1, 1, 1, 1, 0, 0, 0, "Destination IP address GeoIP resolution: lat/lon coordinates"},
  {"in_iface", 0, 1, 1, 1, 0, 0, 0, "Input interface, SNMP ifIndex"}, 
  {"out_iface", 0, 1, 1, 1, 0, 0, 0, "Output interface, SNMP ifIndex"}, 
  {"peer_src_ip", 0, 0, 1, 1, 0, 0, 0, "IP address or identificator of telemetry exporting device"},
  {"sampling_rate", 1, 1, 1, 1, 0, 0, 0, "Sampling rate"},
  {"sampling_direction", 0, 0, 1, 0, 0, 0, 0, "Sampling direction (ie. ingress vs egress)"},
  {"tag", 1, 1, 1, 1, 0, 0, 0, "Numeric tag, ie. as result of pre_tag_map evaluation"},
  {"tag2", 1, 1, 1, 1, 0, 0, 0, "Numeric tag, ie. as result of pre_tag_map evaluation"},
  {"label", 1, 1, 1, 1, 0, 0, 0, "String label, ie. as result of pre_tag_map evaluation"},
  {"export_proto_seqno", 0, 0, 1, 1, 0, 0, 0, "Export protocol (ie. NetFlow) sequence number"},
  {"export_proto_version", 0, 0, 1, 1, 0, 0, 0, "Export protocol (ie. NetFlow) version"},
  {"export_proto_sysid", 0, 0, 1, 1, 0, 0, 0, "Export protocol ID (ie. sFlow subAgentID, IPFIX Obs Domain ID)"},
  {"src_roa", 1, 1, 1, 1, 0, 0, 0, "RPKI validation status for source IP prefix"},
  {"dst_roa", 1, 1, 1, 1, 0, 0, 0, "RPKI validation status for destination IP prefix"},
  {"TIME", 1, 1, 1, 1, 0, 0, 0, ""}, 
  {"timestamp_start", 0, 0, 1, 0, 0, 0, 0, "Flow start time or observation time at the exporter"},
  {"timestamp_end", 0, 0, 1, 0, 0, 0, 0, "Flow end time"},
  {"timestamp_arrival", 1, 1, 1, 1, 0, 0, 0, "Observation time at the collector"},
  {"timestamp_export", 0, 0, 1, 0, 0, 0, 0, "Observation time at the exporter"},
  {"", 0, 0, 0, 0, 0, 0, 0, ""}
};

static const struct _protocols_struct _protocols[] = {
  {"0", 0},
  {"icmp", 1},
  {"igmp", 2},
  {"ggp", 3},
  {"ipencap", 4},
  {"5", 5},
  {"tcp", 6},
  {"7", 7},
  {"egp", 8},
  {"igp", 9},
  {"10", 10},
  {"11", 11},
  {"12", 12},
  {"13", 13},
  {"14", 14},
  {"15", 15},
  {"16", 16},
  {"udp", 17},
  {"mux", 18},
  {"19", 19},
  {"20", 20},
  {"21", 21},
  {"22", 22},
  {"23", 23},
  {"24", 24},
  {"25", 25},
  {"26", 26},
  {"27", 27},
  {"28", 28},
  {"29", 29},
  {"30", 30},
  {"31", 31},
  {"32", 32},
  {"33", 33},
  {"34", 34},
  {"35", 35},
  {"36", 36},
  {"37", 37},
  {"38", 38}, 
  {"39", 39},
  {"40", 40},
  {"ipv6", 41},
  {"42", 42},
  {"ipv6-route", 43},
  {"ipv6-frag", 44},
  {"45", 45},
  {"rsvp", 46},
  {"gre", 47},
  {"48", 48},
  {"49", 49},
  {"esp", 50}, 
  {"ah", 51},
  {"52", 52}, 
  {"53", 53},  
  {"54", 54}, 
  {"mobile", 55},   
  {"tlsp", 56},
  {"57", 57}, 
  {"ipv6-icmp", 58},    
  {"ipv6-nonxt", 59},
  {"ipv6-opts", 60},
  {"61", 61},
  {"62", 62},
  {"63", 63},
  {"64", 64},     
  {"65", 65},  
  {"66", 66},
  {"67", 67}, 
  {"68", 68},
  {"69", 69},   
  {"70", 70},
  {"71", 71},  
  {"72", 72}, 
  {"73", 73},
  {"74", 74},
  {"75", 75},
  {"76", 76},  
  {"77", 77},
  {"78", 78}, 
  {"79", 79},  
  {"iso-ip", 80},
  {"81", 81}, 
  {"82", 82},
  {"vines", 83},
  {"84", 84},
  {"85", 85}, 
  {"86", 86},
  {"87", 87},  
  {"eigrp", 88},   
  {"ospf", 89},
  {"90", 90}, 
  {"larp", 91},
  {"92", 92}, 
  {"ax.25", 93},   
  {"ipip", 94},
  {"95", 95},
  {"96", 96},
  {"97", 97},    
  {"encap", 98},
  {"99", 99},
  {"100", 100},  
  {"101", 101}, 
  {"pnni", 102},
  {"pim", 103},
  {"104", 104},
  {"105", 105},  
  {"106", 106},
  {"107", 107},
  {"IPcomp", 108}, 
  {"109", 109},
  {"110", 110},  
  {"ipx-in-ip", 111},
  {"vrrp", 112},
  {"113", 113}, 
  {"114", 114},
  {"l2tp", 115},   
  {"116", 116},
  {"117", 117}, 
  {"118", 118},
  {"119", 119},
  {"120", 120},  
  {"121", 121}, 
  {"122", 122},
  {"123", 123},
  {"isis", 124},
  {"125", 125},  
  {"126", 126},
  {"127", 127},
  {"128", 128}, 
  {"129", 129},
  {"130", 130},
  {"131", 131}, 
  {"sctp", 132},
  {"fc", 133},
  {"", -1},
};

/* cps = custom primitive semantics */
static const char __attribute__((unused)) *cps_type[] = {
  "",
  "u",
  "x",
  "s",
  "s",
  "s",
  "s"
};

static const int __attribute__((unused)) cps_flen[] = {
  0,
  3,
  5,
  0,
  10,
  0,
  0,
  0,
  20
};

static const char __attribute__((unused)) *bgp_origin[] = {
  "i",
  "e",
  "u",
  ""
};

static const char __attribute__((unused)) *bgp_rd_origin[] = {
  "unknown",
  "bgp",
  "bmp",
  "flow",
  ""
};

static const u_int16_t __attribute__((unused)) lookup_type_to_bgp_rd_origin[] = {
  RD_ORIGIN_UNKNOWN,
  RD_ORIGIN_BGP,
  RD_ORIGIN_BMP
};

static const char __attribute__((unused)) *rpki_roa[] = {
  "u",
  "i",
  "v",
  "V",
  "U"
};

extern struct tunnel_entry tunnel_handlers_list[];
extern struct _devices_struct _devices[];

#endif //PMACCT_DATA_H

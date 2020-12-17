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

#ifndef BMP_H
#define BMP_H

/* includes */

/* defines */
#define BMP_TCP_PORT		1790
#define BMP_MAX_PEERS_DEFAULT	4
#define BMP_V3			3
#define BMP_V4			4

#define BMP_CMN_HDRLEN		5
#define BMP_PEER_HDRLEN		42

#define BMP_MISSING_PEER_UP_LOG_TOUT	60

/* BMP message types */
#define BMP_MSG_ROUTE_MONITOR		0	
#define	BMP_MSG_STATS			1
#define BMP_MSG_PEER_DOWN		2
#define BMP_MSG_PEER_UP			3
#define	BMP_MSG_INIT			4
#define BMP_MSG_TERM			5
#define BMP_MSG_ROUTE_MIRROR		6
#define BMP_MSG_TMP_RPAT		100
#define BMP_MSG_TYPE_MAX		100 /* set to the highest BMP_MSG_* value */

static const char __attribute__((unused)) *bmp_msg_types[] = {
  "Route Monitoring",
  "Statistics Report",
  "Peer Down Notification",
  "Peer Up Notification",
  "Initiation Message",
  "Termination Message",
  "Route Mirroring",
  "", "", "", "",    
  "", "", "", "", "",
  "", "", "", "", "",
  "", "", "", "", "",
  "", "", "", "", "",
  "", "", "", "", "",
  "", "", "", "", "",
  "", "", "", "", "",
  "", "", "", "", "",
  "", "", "", "", "",
  "", "", "", "", "",
  "", "", "", "", "",
  "", "", "", "", "",
  "", "", "", "", "",
  "", "", "", "", "",
  "", "", "", "", "",
  "", "", "", "", "",
  "", "", "", "", "",
  "", "", "", "", 
  "RPAT"
};

struct bmp_common_hdr {
  u_char	version;
  u_int32_t	len;
  u_char	type;
} __attribute__ ((packed));

#define BMP_PEER_TYPE_GLOBAL	0
#define BMP_PEER_TYPE_L3VPN	1
#define BMP_PEER_TYPE_LOCAL	2
#define BMP_PEER_TYPE_LOC_RIB	3 /* draft-ietf-grow-bmp-local-rib */ 
#define BMP_PEER_TYPE_MAX	3 /* set to the highest BMP_PEER_TYPE_* value */

static const char __attribute__((unused)) *bmp_peer_types[] = {
  "Global Instance Peer",
  "RD Instance Peer",
  "Local Instance Peer",
  "Loc-RIB Instance Peer"
};

#define BMP_PEER_FLAGS_ARI_V	0x80
#define BMP_PEER_FLAGS_ARI_L	0x40
#define BMP_PEER_FLAGS_ARI_A	0x20
#define BMP_PEER_FLAGS_LR_F	0x80 /* draft-ietf-grow-bmp-local-rib */
#define BMP_PEER_FLAGS_ARO_O	0x10 /* rfc8671 */

struct bmp_chars {
  /* key */
  u_int8_t peer_type;
  u_int8_t is_post;
  u_int8_t is_2b_asn;
  u_int8_t is_filtered;
  u_int8_t is_out;
  u_int8_t is_loc;
  rd_t rd;

  /* non-key */
  struct pm_list *tlvs;
};

struct bmp_data {
  u_int8_t family;
  struct host_addr peer_ip;
  struct host_addr bgp_id;
  u_int32_t peer_asn;
  struct bmp_chars chars;
  struct timeval tstamp;
  struct timeval tstamp_arrival;
};

struct bmp_peer_hdr {
  u_char	type;
  u_char	flags;
  u_char	rd[RD_LEN];
  u_int32_t	addr[4];
  u_int32_t	asn;
  u_int32_t	bgp_id;
  u_int32_t	tstamp_sec;
  u_int32_t	tstamp_usec;
} __attribute__ ((packed));

struct bmp_tlv_hdr {
  u_int16_t     type;
  u_int16_t     len;
} __attribute__ ((packed));

#define BMP_TLV_EBIT		0x8000 	/* BMP TLV enterprise bit */
#define BMP_TLV_PEN_STD		0 	/* PEN for standardized TLVs */

typedef int (*bmp_logdump_func)(struct bgp_peer *, struct bmp_data *, void *, void *, char *, int, void *);

struct bmp_tlv_def {
  char *name;
  int semantics;
  bmp_logdump_func logdump_func;
};

#define BMP_TLV_SEM_UNKNOWN	CUSTOM_PRIMITIVE_TYPE_UNKNOWN
#define BMP_TLV_SEM_UINT	CUSTOM_PRIMITIVE_TYPE_UINT
#define BMP_TLV_SEM_HEX		CUSTOM_PRIMITIVE_TYPE_HEX
#define BMP_TLV_SEM_STRING	CUSTOM_PRIMITIVE_TYPE_STRING
#define BMP_TLV_SEM_IP		CUSTOM_PRIMITIVE_TYPE_IP
#define BMP_TLV_SEM_MAC		CUSTOM_PRIMITIVE_TYPE_MAC
#define BMP_TLV_SEM_RAW		CUSTOM_PRIMITIVE_TYPE_RAW
#define BMP_TLV_SEM_COMPLEX	CUSTOM_PRIMITIVE_TYPE_COMPLEX

#define BMP_INIT_INFO_STRING	0
#define BMP_INIT_INFO_SYSDESCR	1
#define BMP_INIT_INFO_SYSNAME	2
#define BMP_INIT_INFO_MAX	2
#define BMP_INIT_INFO_ENTRIES	8

static const struct bmp_tlv_def __attribute__((unused)) bmp_init_info_types[] = {
  { "string", BMP_TLV_SEM_STRING, NULL }, 
  { "sysdescr", BMP_TLV_SEM_STRING, NULL },
  { "sysname", BMP_TLV_SEM_STRING, NULL }
};

#define BMP_TERM_INFO_STRING    0
#define BMP_TERM_INFO_REASON	1
#define BMP_TERM_INFO_MAX	1
#define BMP_TERM_INFO_ENTRIES	8

#define BMP_TERM_REASON_ADM	0
#define BMP_TERM_REASON_UNK	1
#define BMP_TERM_REASON_OOR	2
#define BMP_TERM_REASON_DUP	3
#define BMP_TERM_REASON_PERM	4
#define BMP_TERM_REASON_MAX	4 /* set to the highest BMP_TERM_* value */

static const struct bmp_tlv_def __attribute__((unused)) bmp_term_info_types[] = {
  { "string", BMP_TLV_SEM_STRING, NULL },
  { "reason", BMP_TLV_SEM_UINT, NULL }
};

static const char __attribute__((unused)) *bmp_term_reason_types[] = {
  "Session administratively closed",
  "Unspecified reason",
  "Out of resources",
  "Redundant connection",
  "Session permanently administratively closed"
};

struct bmp_stats_hdr {
  u_int32_t	count;
} __attribute__ ((packed));

struct bmp_peer {
  struct bgp_peer self;
  void *bgp_peers_v4;
  void *bgp_peers_v6;
  struct log_notification missing_peer_up;
};

#define BMP_STATS_TYPE0		0  /* (32-bit Counter) Number of prefixes rejected by inbound policy */
#define BMP_STATS_TYPE1		1  /* (32-bit Counter) Number of (known) duplicate prefix advertisements */
#define BMP_STATS_TYPE2		2  /* (32-bit Counter) Number of (known) duplicate withdraws */
#define BMP_STATS_TYPE3		3  /* (32-bit Counter) Number of updates invalidated due to CLUSTER_LIST loop */
#define BMP_STATS_TYPE4		4  /* (32-bit Counter) Number of updates invalidated due to AS_PATH loop */
#define BMP_STATS_TYPE5		5  /* (32-bit Counter) Number of updates invalidated due to ORIGINATOR_ID */ 
#define BMP_STATS_TYPE6		6  /* (32-bit Counter) Number of updates invalidated due to AS_CONFED loop */
#define BMP_STATS_TYPE7		7  /* (64-bit Gauge) Number of routes in Adj-RIB-In */
#define BMP_STATS_TYPE8		8  /* (64-bit Gauge) Number of routes in Loc-RIB */
#define BMP_STATS_TYPE9		9  /* (64-bit Gauge) Number of routes in per-AFI/SAFI Abj-RIB-In */
#define BMP_STATS_TYPE10	10 /* (64-bit Gauge) Number of routes in per-AFI/SAFI Loc-RIB */
#define BMP_STATS_TYPE11	11 /* (32-bit Counter) Number of updates subjected to treat-as-withdraw */ 
#define BMP_STATS_TYPE12	12 /* (32-bit Counter) Number of prefixes subjected to treat-as-withdraw */
#define BMP_STATS_TYPE13	13 /* (32-bit Counter) Number of duplicate update messages received */
#define BMP_STATS_TYPE14	14 /* (64-bit Gauge) Number of routes in Adj-RIBs-Out Pre-Policy */
#define BMP_STATS_TYPE15	15 /* (64-bit Gauge) Number of routes in Adj-RIBs-Out Post-Policy */
#define BMP_STATS_TYPE16	16 /* (64-bit Gauge) Number of routes in per-AFI/SAFI Abj-RIB-Out */
#define BMP_STATS_TYPE17	17 /* (64-bit Gauge) Number of routes in per-AFI/SAFI Abj-RIB-Out */
#define BMP_STATS_MAX		17 /* set to the highest BMP_STATS_* value */

/* dummy */
static const struct bmp_tlv_def __attribute__((unused)) bmp_stats_info_types[] = {
  { "", BMP_TLV_SEM_UNKNOWN, NULL }
};

#define BMP_STATS_INFO_MAX	-1

static const char __attribute__((unused)) *bmp_stats_cnt_types[] = {
  "Number of prefixes rejected by inbound policy",
  "Number of (known) duplicate prefix advertisements",
  "Number of (known) duplicate withdraws",
  "Number of updates invalidated due to CLUSTER_LIST loop",
  "Number of updates invalidated due to AS_PATH loop",
  "Number of updates invalidated due to ORIGINATOR_ID",
  "Number of updates invalidated due to AS_CONFED loop",
  "Number of routes in Adj-RIBs-In",
  "Number of routes in Loc-RIB",
  "Number of routes in per-AFI/SAFI Abj-RIB-In",
  "Number of routes in per-AFI/SAFI Loc-RIB",
  "Number of updates subjected to treat-as-withdraw",
  "Number of prefixes subjected to treat-as-withdraw",
  "Number of duplicate update messages received",
  "Number of routes in Adj-RIBs-Out Pre-Policy",
  "Number of routes in Adj-RIBs-Out Post-Policy",
  "Number of routes in per-AFI/SAFI Abj-RIB-Out Pre-Policy",
  "Number of routes in per-AFI/SAFI Abj-RIB-Out Post-Policy"
};

struct bmp_stats_cnt_hdr {
  u_int16_t	type;
  u_int16_t	len;
} __attribute__ ((packed));

static const struct bmp_tlv_def __attribute__((unused)) bmp_peer_up_info_types[] = {
  { "string", BMP_TLV_SEM_STRING, NULL }
};

#define BMP_PEER_UP_INFO_STRING		0
#define BMP_PEER_UP_INFO_MAX		0
#define BMP_PEER_UP_INFO_ENTRIES	8	

#define BMP_PEER_DOWN_RESERVED		0
#define BMP_PEER_DOWN_LOC_NOT_MSG	1
#define BMP_PEER_DOWN_LOC_CODE		2
#define BMP_PEER_DOWN_REM_NOT_MSG	3
#define BMP_PEER_DOWN_REM_CODE		4
#define BMP_PEER_DOWN_DECFG		5
#define BMP_PEER_DOWN_MAX		5 /* set to the highest BMP_PEER_DOWN_* value */

#define BMP_PEER_DOWN_INFO_MAX		-1
#define BMP_PEER_DOWN_INFO_ENTRIES	BMP_PEER_UP_INFO_ENTRIES

static const char __attribute__((unused)) *bmp_peer_down_reason_types[] = {
  "Reserved",
  "The local system closed the session",
  "The local system closed the session without a notification message",
  "The remote system closed the session",
  "The remote system closed the session without a notification message",
  "Info for this peer will no longer be sent for configuration reasons"
};

static const struct bmp_tlv_def __attribute__((unused)) bmp_peer_down_info_types[] = {
  { "", BMP_TLV_SEM_UNKNOWN }
};

struct bmp_peer_down_hdr {
  u_char	reason;
} __attribute__ ((packed));

struct bmp_peer_up_hdr {
  u_int32_t	loc_addr[4];
  u_int16_t	loc_port;
  u_int16_t	rem_port;
  /* Sent OPEN Message */
  /* Received OPEN Message */
} __attribute__ ((packed));

/* more includes */
#include "bmp_logdump.h"

/* draft-cppy-grow-bmp-path-marking-tlv */
static const struct bmp_tlv_def __attribute__((unused)) bmp_rm_info_types[] = {
  { "path_marking", BMP_TLV_SEM_COMPLEX, bmp_log_rm_tlv_path_marking }
};

#define BMP_ROUTE_MONITOR_INFO_MARKING	0
#define BMP_ROUTE_MONITOR_INFO_MAX	0
#define BMP_ROUTE_MONITOR_INFO_ENTRIES	4

struct bmp_rm_pm_tlv {
  u_int16_t	path_index;
  u_int32_t     path_status;
  u_int16_t     reason_code;
} __attribute__ ((packed));

#define BMP_RM_PM_PS_UNKNOWN	0x00000000
#define BMP_RM_PM_PS_INVALID	0x00000001
#define BMP_RM_PM_PS_BEST	0x00000002
#define BMP_RM_PM_PS_NO_SELECT	0x00000004
#define BMP_RM_PM_PS_PRIMARY	0x00000008
#define BMP_RM_PM_PS_BACKUP	0x00000010
#define BMP_RM_PM_PS_NO_INSTALL	0x00000020
#define BMP_RM_PM_PS_BEST_EXT	0x00000040
#define BMP_RM_PM_PS_ADD_PATH	0x00000080

static const char __attribute__((unused)) *bmp_rm_pm_reason_types[] = {
  "invalid for unknown",
  "invalid for super network",
  "invalid for dampening",
  "invalid for history",
  "invalid for policy deny",
  "invalid for ROA not validation",
  "invalid for interface error",
  "invalid for nexthop route unreachable",
  "invalid for nexthop tunnel unreachable",
  "invalid for nexthop restrain",
  "invalid for relay BGP LSP",
  "invalid for being inactive within VPN instance",
  "invalid for prefix-sid not exist",
  "not preferred for peer address",
  "not preferred for router ID",
  "not preferred for Cluster List",
  "not preferred for IGP cost",
  "not preferred for peer type",
  "not preferred for MED",
  "not preferred for origin",
  "not preferred for AS-Path",
  "not preferred for route type",
  "not preferred for Local_Pref",
  "not preferred for PreVal",
  "not preferred for not direct route",
  "not preferred for nexthop bit error",
  "not preferred for received path-id",
  "not preferred for validation",
  "not preferred for originate IP",
  "not preferred for route distinguisher",
  "not preferred for route-select delay",
  "not preferred for being imported route",
  "not preferred for med-plus-igp",
  "not preferred for AIGP",
  "not preferred for nexthop-resolved aigp",
  "not preferred for nexthop unreachable",
  "not preferred for nexthop IP",
  "not preferred for high-priority",
  "not preferred for nexthop-priority",
  "not preferred for process ID",
  "no reason code"
};

/* more includes */
#include "bmp_msg.h"
#include "bmp_util.h"
#include "bmp_lookup.h"
#include "bmp_tlv.h"
#include "bmp_rpat.h"

/* prototypes */
extern void bmp_daemon_wrapper();
extern int skinny_bmp_daemon();
extern void bmp_prepare_thread();
extern void bmp_prepare_daemon();

/* global variables */
extern struct bmp_peer *bmp_peers;
extern u_int32_t (*bmp_route_info_modulo)(struct bgp_peer *, path_id_t *, int);
extern struct bgp_rt_structs *bmp_routing_db;
extern struct bgp_misc_structs *bmp_misc_db;

#endif //BMP_H

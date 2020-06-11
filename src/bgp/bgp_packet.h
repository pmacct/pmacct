/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2019 by Paolo Lucente
*/

/* 
 * Definitions for BGP packet disassembly structures and routine
 *
 * Baselined from:
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _BGP_PACKET_H_
#define _BGP_PACKET_H_

/* some handy things to know */
#define BGP_BUFFER_SIZE			100000
#define BGP_MARKER_SIZE			16	/* size of BGP marker */
#define BGP_HEADER_SIZE			19	/* size of BGP header, including marker */
#define BGP_MIN_OPEN_MSG_SIZE		29
#define BGP_MIN_UPDATE_MSG_SIZE		23
#define BGP_MIN_NOTIFICATION_MSG_SIZE	21
#define BGP_MIN_KEEPALVE_MSG_SIZE	BGP_HEADER_SIZE
#define BGP_TCP_PORT			179
#define BGP_VERSION4			4
#define BGP_MAX_MSGLEN			4096
#define CAPABILITY_CODE_AS4_LEN		4

/* BGP message types */
#define BGP_OPEN		1
#define BGP_UPDATE		2
#define BGP_NOTIFICATION	3
#define BGP_KEEPALIVE		4
#define BGP_ROUTE_REFRESH       5
#define BGP_CAPABILITY		6
#define BGP_ROUTE_REFRESH_CISCO 0x80

/* Address family numbers from RFC1700. */
#define AFI_IP                    1
#define AFI_IP6                   2
#define AFI_MAX                   3

/* Subsequent Address Family Identifier. */
#define SAFI_UNICAST              1
#define SAFI_MULTICAST            2
#define SAFI_UNICAST_MULTICAST    3
#define SAFI_MPLS_LABEL           4
#define SAFI_MPLS_VPN             128
#define SAFI_MAX                  129

struct bgp_header {
    u_int8_t bgpo_marker[BGP_MARKER_SIZE];
    u_int16_t bgpo_len;
    u_int8_t bgpo_type;
};

/* BGP OPEN message */
struct bgp_open {
    u_int8_t bgpo_marker[BGP_MARKER_SIZE];
    u_int16_t bgpo_len;
    u_int8_t bgpo_type;
    u_int8_t bgpo_version;
    u_int16_t bgpo_myas;
    u_int16_t bgpo_holdtime;
    u_int32_t bgpo_id;
    u_int8_t bgpo_optlen;
    /* options should follow */
};

/* BGP NOTIFICATION message */
/* BGP notify message codes.  */
#define BGP_NOTIFY_HEADER_ERR			1
#define BGP_NOTIFY_OPEN_ERR			2
#define BGP_NOTIFY_UPDATE_ERR			3
#define BGP_NOTIFY_HOLD_ERR			4
#define BGP_NOTIFY_FSM_ERR			5
#define BGP_NOTIFY_CEASE			6
#define BGP_NOTIFY_CAPABILITY_ERR		7
#define BGP_NOTIFY_MAX				8

#define BGP_NOTIFY_SUBCODE_UNSPECIFIC		0

/* BGP_NOTIFY_CEASE sub codes (RFC 4486).  */
#define BGP_NOTIFY_CEASE_MAX_PREFIX		1
#define BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN		2
#define BGP_NOTIFY_CEASE_PEER_UNCONFIG		3
#define BGP_NOTIFY_CEASE_ADMIN_RESET		4
#define BGP_NOTIFY_CEASE_CONNECT_REJECT		5
#define BGP_NOTIFY_CEASE_CONFIG_CHANGE		6
#define BGP_NOTIFY_CEASE_COLLISION_RESOLUTION	7
#define BGP_NOTIFY_CEASE_OUT_OF_RESOURCE	8
#define BGP_NOTIFY_CEASE_MAX			9 

struct bgp_notification {
    u_int8_t bgpn_marker[BGP_MARKER_SIZE];
    u_int16_t bgpn_len;
    u_int8_t bgpn_type;
    u_int8_t bgpn_major;
    u_int8_t bgpn_minor;
    /* data should follow */
};

/* based on: rfc8203 */
/* #define BGP_NOTIFY_CEASE_SM_LEN		128 */
/* based on: draft-ietf-idr-rfc8203bis */
#define BGP_NOTIFY_CEASE_SM_LEN			255

struct bgp_notification_shutdown_msg {
    u_int8_t bgpnsm_len;
    char bgpnsm_data[BGP_NOTIFY_CEASE_SM_LEN];
};

/* BGP ROUTE-REFRESH message */
struct bgp_route_refresh {
    u_int8_t bgpr_marker[BGP_MARKER_SIZE];
    u_int16_t bgpr_len;
    u_int8_t bgpr_type;
    u_int16_t bgpr_afi;
    u_int8_t bgpr_reserved;
    u_int8_t bgpr_safi;
};

struct capability_mp_data
{
  u_int16_t afi;
  u_char reserved;
  u_char safi;
};

struct capability_as4
{
  uint32_t as4;
};

struct capability_add_paths
{
  u_int16_t afi;
  u_char safi;
  u_char sndrcv;
};

/* attribute flags, from RFC1771 */
#define BGP_ATTR_FLAG_OPTIONAL        0x80
#define BGP_ATTR_FLAG_TRANSITIVE      0x40
#define BGP_ATTR_FLAG_PARTIAL         0x20
#define BGP_ATTR_FLAG_EXTENDED_LENGTH 0x10

/* AS_PATH segment types */
#define AS_SET             1   /* RFC1771 */
#define AS_SEQUENCE        2   /* RFC1771 */
#define AS_CONFED_SET      4   /* RFC1965 has the wrong values, corrected in  */
#define AS_CONFED_SEQUENCE 3   /* RFC3065 */

/* OPEN message Optional Parameter types  */
#define BGP_OPTION_AUTHENTICATION	1   /* RFC1771 */
#define BGP_OPTION_CAPABILITY		2   /* RFC2842 */

/* BGP capability code */
#define BGP_CAPABILITY_RESERVED		           0   /* RFC2434 */
#define BGP_CAPABILITY_MULTIPROTOCOL	           1   /* RFC2858 */
#define BGP_CAPABILITY_ROUTE_REFRESH	           2   /* RFC2918 */
#define BGP_CAPABILITY_4_OCTET_AS_NUMBER	0x41   /* RFC4893 */
#define BGP_CAPABILITY_ADD_PATHS		0x45   /* RFC7911 */

/* well-known communities, from RFC1997 */
#define BGP_COMM_NO_EXPORT           0xFFFFFF01
#define BGP_COMM_NO_ADVERTISE        0xFFFFFF02
#define BGP_COMM_NO_EXPORT_SUBCONFED 0xFFFFFF03
#define FOURHEX0                     0x00000000
#define FOURHEXF                     0xFFFF0000

/* Extended community type */
#define BGP_EXT_COM_RT_0        0x0002  /* Route Target,Format AS(2bytes):AN(4bytes) */
#define BGP_EXT_COM_RT_1        0x0102  /* Route Target,Format IP address:AN(2bytes) */
#define BGP_EXT_COM_RT_2        0x0202  /* Route Target,Format AS(2bytes):AN(4bytes) */
#define BGP_EXT_COM_RO_0        0x0003  /* Route Origin,Format AS(2bytes):AN(4bytes) */
#define BGP_EXT_COM_RO_1        0x0103  /* Route Origin,Format IP address:AN(2bytes) */
#define BGP_EXT_COM_RO_2        0x0203  /* Route Origin,Format AS(2bytes):AN(4bytes) */
#define BGP_EXT_COM_LINKBAND    0x0004  /* Link Bandwidth,Format AS(2B):Bandwidth(4B) */
                                        /* -2 version of the draft */
#define BGP_EXT_COM_VPN_ORIGIN  0x0005  /* OSPF Domin ID / VPN of Origin  */
                                        /* draft-rosen-vpns-ospf-bgp-mpls */
#define BGP_EXT_COM_OSPF_RTYPE  0X8000  /* OSPF Route Type,Format Area(4B):RouteType(1B):Options(1B) */
#define BGP_EXT_COM_OSPF_RID    0x8001  /* OSPF Router ID,Format RouterID(4B):Unused(2B) */
#define BGP_EXT_COM_L2INFO      0x800a  /* draft-kompella-ppvpn-l2vpn */

/* Extended community & Route dinstinguisher formats */
#define FORMAT_AS2_LOC      0x00    /* Format AS(2bytes):AN(4bytes) */
#define FORMAT_IP_LOC       0x01    /* Format IP address:AN(2bytes) */
#define FORMAT_AS4_LOC      0x02    /* Format AS(4bytes):AN(2bytes) */

#ifndef offsetof
#define offsetof(type, member)  ((size_t)(&((type *)0)->member))
#endif

#endif

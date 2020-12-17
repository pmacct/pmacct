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

#ifndef RPKI_H
#define RPKI_H

/* defines */
#define ROA_STATUS_UNKNOWN		0	/* 'u' - Unknown */
#define ROA_STATUS_INVALID		1	/* 'i' - Invalid with no covering prefix */
#define ROA_STATUS_VALID		2	/* 'v' - Valid */
#define ROA_STATUS_OVERLAP_VALID	3	/* 'o' - Invalid with covering valid prefix */ 
#define ROA_STATUS_OVERLAP_UNKNOWN	4	/* 'O' - Invalid with covering unknown prefix */ 
#define ROA_STATUS_MAX			4

#define RPKI_RTR_V0			0	/* rfc6810 */
#define RPKI_RTR_V1			1	/* rfc8210 */

#define RPKI_RTR_V0_DEFAULT_RETRY_IVL	10	/* discretionary */
#define RPKI_RTR_V0_DEFAULT_REFRESH_IVL	10	/* discretionary */
#define RPKI_RTR_V0_DEFAULT_EXPIRE_IVL	7200	/* discretionary */
#define RPKI_RTR_V1_DEFAULT_RETRY_IVL	600	/* rfc8210 */
#define RPKI_RTR_V1_DEFAULT_REFRESH_IVL	3600	/* in case of missing/zero timer in eod */
#define RPKI_RTR_V1_DEFAULT_EXPIRE_IVL	7200	/* in case of missing/zero timer in eod */

#define RPKI_RTR_PDU_SERIAL_NOTIFY	0
#define RPKI_RTR_PDU_SERIAL_QUERY	1
#define RPKI_RTR_PDU_RESET_QUERY	2
#define RPKI_RTR_PDU_CACHE_RESPONSE	3
#define RPKI_RTR_PDU_IPV4_PREFIX	4
#define RPKI_RTR_PDU_IPV6_PREFIX	6
#define RPKI_RTR_PDU_END_OF_DATA	7
#define RPKI_RTR_PDU_CACHE_RESET	8
#define RPKI_RTR_PDU_ROUTER_KEY		9
#define RPKI_RTR_PDU_ERROR_REPORT	10

#define RPKI_RTR_PDU_SERIAL_NOTIFY_LEN	12
#define RPKI_RTR_PDU_SERIAL_QUERY_LEN	12
#define RPKI_RTR_PDU_RESET_QUERY_LEN	8
#define RPKI_RTR_PDU_CACHE_RESPONSE_LEN	8
#define RPKI_RTR_PDU_IPV4_PREFIX_LEN	20
#define RPKI_RTR_PDU_IPV6_PREFIX_LEN	32
#define RPKI_RTR_PDU_END_OF_DATA_V0_LEN	12
#define RPKI_RTR_PDU_END_OF_DATA_V1_LEN	24
#define RPKI_RTR_PDU_CACHE_RESET_LEN	8

#define RPKI_RTR_ERR_CORRUPT_DATA	0
#define RPKI_RTR_ERR_INTERNAL_ERROR	1
#define RPKI_RTR_ERR_NO_DATA		2
#define RPKI_RTR_ERR_INVALID_REQUEST	3
#define RPKI_RTR_ERR_PROTO_VERSION	4
#define RPKI_RTR_ERR_INVALID_PDU_TYPE	5
#define RPKI_RTR_ERR_WITHDRAWAL		6
#define RPKI_RTR_ERR_DUPLICATE		7

#define RPKI_RTR_PREFIX_FLAGS_WITHDRAW	0
#define RPKI_RTR_PREFIX_FLAGS_ANNOUNCE	1

struct rpki_rtr_serial {
  u_int8_t version;
  u_int8_t pdu_type;
  u_int16_t session_id;
  u_int32_t len;
  u_int32_t serial;
} __attribute__ ((packed));

struct rpki_rtr_reset {
  u_int8_t version;
  u_int8_t pdu_type;
  u_int16_t unused;
  u_int32_t len;
} __attribute__ ((packed));

struct rpki_rtr_cache_response {
  u_int8_t version;
  u_int8_t pdu_type;
  u_int16_t session_id;
  u_int32_t len;
} __attribute__ ((packed));

struct rpki_rtr_ipv4_pref {
  u_int8_t version;
  u_int8_t pdu_type;
  u_int16_t unused_1;
  u_int32_t len;
  u_int8_t flags;
  u_int8_t pref_len;
  u_int8_t max_len;
  u_int8_t unused_2;
  u_int32_t prefix;
  u_int32_t asn;
} __attribute__ ((packed));

struct rpki_rtr_ipv6_pref {
  u_int8_t version;
  u_int8_t pdu_type;
  u_int16_t unused_1;
  u_int32_t len;
  u_int8_t flags;
  u_int8_t pref_len;
  u_int8_t max_len;
  u_int8_t unused_2;
  u_int32_t prefix[4];
  u_int32_t asn;
} __attribute__ ((packed));

struct rpki_rtr_eod_v0 {
  u_int8_t version;
  u_int8_t pdu_type;
  u_int16_t session_id;
  u_int32_t len;
  u_int32_t serial;
} __attribute__ ((packed));

struct rpki_rtr_eod_v1 {
  u_int8_t version;
  u_int8_t pdu_type;
  u_int16_t session_id;
  u_int32_t len;
  u_int32_t serial;
  u_int32_t refresh_ivl;
  u_int32_t retry_ivl;
  u_int32_t expire_ivl;
} __attribute__ ((packed));

struct rpki_rtr_cache_reset {
  u_int8_t version;
  u_int8_t pdu_type;
  u_int16_t unused;
  u_int32_t len;
} __attribute__ ((packed));

struct rpki_rtr_router_key {
  u_int8_t version;
  u_int8_t pdu_type;
  u_int8_t flags;
  u_int8_t unused;
  u_int32_t len;
  u_int8_t subject_key_id[20];
  u_int32_t asn;
  /* subject public key info */
} __attribute__ ((packed));

struct rpki_rtr_err_report {
  u_int8_t version;
  u_int8_t pdu_type;
  u_int16_t errcode;
  u_int32_t tot_len;
  /* pdu len */
  /* copy of pdu */
  /* err text len */
  /* err text */
} __attribute__ ((packed));

struct rpki_rtr_timer {
  time_t tstamp;
  u_int32_t ivl;
};

struct rpki_rtr_handle {
  struct sockaddr_storage sock;
  socklen_t socklen;
  int fd;
  int dont_reconnect;

  time_t now; 
  struct rpki_rtr_timer refresh;
  struct rpki_rtr_timer retry;
  struct rpki_rtr_timer expire;

  u_int16_t session_id;
  u_int32_t serial;
};

#include "rpki_msg.h"
#include "rpki_lookup.h"
#include "rpki_util.h"

/* prototypes */
extern void rpki_daemon_wrapper();
extern void rpki_prepare_thread();
extern int rpki_daemon();
extern void rpki_roas_file_reload();

/* global variables */
extern struct bgp_rt_structs *rpki_roa_db;
extern struct bgp_misc_structs *rpki_misc_db;
extern struct bgp_peer rpki_peer;
#endif //RPKI_H

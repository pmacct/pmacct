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

/* includes */
#include "pmacct.h"
#include "addr.h"
#include "bgp.h"
#include "bgp_blackhole.h"

int bgp_parse_msg(struct bgp_peer *peer, time_t now, int online)
{
  struct bgp_misc_structs *bms;
  struct bgp_msg_data bmd;
  char *bgp_packet_ptr;
  char bgp_peer_str[INET6_ADDRSTRLEN];
  struct bgp_header *bhdr;
  int ret, bgp_len = 0;

  if (!peer || !peer->buf.base) return ERR;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) return ERR;

  memset(&bmd, 0, sizeof(bmd));
  bmd.peer = peer;

  for (bgp_packet_ptr = peer->buf.base; peer->msglen > 0; peer->msglen -= bgp_len, bgp_packet_ptr += bgp_len) {
    bhdr = (struct bgp_header *) bgp_packet_ptr;

    if (peer->msglen < BGP_HEADER_SIZE && bgp_packet_ptr == peer->buf.base) {
      bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] Received malformed BGP packet (incomplete header).\n",
		config.name, bms->log_str, bgp_peer_str);
      return BGP_NOTIFY_HEADER_ERR;
    }

    bgp_len = ntohs(bhdr->bgpo_len);

    if (bgp_max_msglen_check(bgp_len) == ERR) {
      bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] Received malformed BGP packet (packet length check failed).\n",
		config.name, bms->log_str, bgp_peer_str);
      return BGP_NOTIFY_HEADER_ERR;
    }

    if (bgp_marker_check(bhdr, BGP_MARKER_SIZE) == ERR) {
      bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] Received malformed BGP packet (marker check failed).\n",
		config.name, bms->log_str, bgp_peer_str);
      return BGP_NOTIFY_HEADER_ERR;
    }

    switch (bhdr->bgpo_type) {
    case BGP_OPEN:
      ret = bgp_parse_open_msg(&bmd, bgp_packet_ptr, now, online);
      if (ret < 0) return BGP_NOTIFY_OPEN_ERR;

      break;
    case BGP_NOTIFICATION:
      {
	u_int16_t shutdown_msglen = (BGP_NOTIFY_CEASE_SM_LEN + 1);
	u_int8_t res_maj = 0, res_min = 0;
        char shutdown_msg[shutdown_msglen];

	memset(shutdown_msg, 0, shutdown_msglen);
        bgp_parse_notification_msg(&bmd, bgp_packet_ptr, &res_maj, &res_min, shutdown_msg, shutdown_msglen);

        bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
        Log(LOG_INFO, "INFO ( %s/%s ): [%s] BGP_NOTIFICATION received (%u, %u). Shutdown Message: '%s'\n",
	    config.name, bms->log_str, bgp_peer_str, res_maj, res_min, shutdown_msg);

        return ERR;
      }
    case BGP_KEEPALIVE:
      bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): [%s] BGP_KEEPALIVE received\n", config.name, bms->log_str, bgp_peer_str);
      if (peer->status >= OpenSent) {
        if (peer->status < Established) peer->status = Established;

	if (online) {
	  char bgp_reply_pkt[BGP_BUFFER_SIZE], *bgp_reply_pkt_ptr;

	  memset(bgp_reply_pkt, 0, BGP_BUFFER_SIZE);
          bgp_reply_pkt_ptr = bgp_reply_pkt;
          bgp_reply_pkt_ptr += bgp_write_keepalive_msg(bgp_reply_pkt_ptr);
          ret = send(peer->fd, bgp_reply_pkt, bgp_reply_pkt_ptr - bgp_reply_pkt, 0);
          peer->last_keepalive = now;

          bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
	  Log(LOG_DEBUG, "DEBUG ( %s/%s ): [%s] BGP_KEEPALIVE sent\n", config.name, bms->log_str, bgp_peer_str);
	}
      }
      /* If we didn't pass through a successful BGP OPEN exchange just yet
         let's temporarily silently discard BGP KEEPALIVEs */
      break;
    case BGP_UPDATE:
      if (peer->status < Established) {
        bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
	Log(LOG_DEBUG, "DEBUG ( %s/%s ): [%s] BGP UPDATE received (no neighbor). Discarding.\n",
		config.name, bms->log_str, bgp_peer_str);
	return BGP_NOTIFY_FSM_ERR;
      }

      ret = bgp_parse_update_msg(&bmd, bgp_packet_ptr);
      if (ret < 0) {
        bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
	Log(LOG_WARNING, "WARN ( %s/%s ): [%s] BGP UPDATE: malformed.\n", config.name, bms->log_str, bgp_peer_str);
	return BGP_NOTIFY_UPDATE_ERR;
      }

      break;
    case BGP_ROUTE_REFRESH:
      /* just ignore */
      break;
    default:
      bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] Received malformed BGP packet (unsupported message type).\n",
	  config.name, bms->log_str, bgp_peer_str);
      return BGP_NOTIFY_HEADER_ERR;
    }
  }

  return SUCCESS;
}

int bgp_parse_open_msg(struct bgp_msg_data *bmd, char *bgp_packet_ptr, time_t now, int online)
{
  struct bgp_peer *peer = bmd->peer;
  struct bgp_misc_structs *bms;
  char bgp_reply_pkt[BGP_BUFFER_SIZE], *bgp_reply_pkt_ptr;
  char bgp_peer_str[INET6_ADDRSTRLEN];
  struct bgp_open *bopen;
  int ret;
  u_int16_t remote_as = 0;
  u_int32_t remote_as4 = 0;

  if (!peer || !bgp_packet_ptr) return ERR;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) return ERR;

  if (!online || (peer->status < OpenSent)) {
    peer->status = Active;
    bopen = (struct bgp_open *) bgp_packet_ptr;  

    if (bopen->bgpo_version == BGP_VERSION4) {
      char bgp_open_cap_reply[BGP_BUFFER_SIZE-BGP_MIN_OPEN_MSG_SIZE];
      char *bgp_open_cap_reply_ptr = bgp_open_cap_reply, *bgp_open_cap_ptr;

      remote_as = ntohs(bopen->bgpo_myas);
      peer->ht = MAX(5, ntohs(bopen->bgpo_holdtime));
      peer->id.family = AF_INET; 
      peer->id.address.ipv4.s_addr = bopen->bgpo_id;
      peer->version = BGP_VERSION4;

      /* Check: duplicate Router-IDs; BGP only, ie. no BMP */
      if (!config.bgp_disable_router_id_check && bms->bgp_msg_open_router_id_check) {
	int check_ret;

	check_ret = bms->bgp_msg_open_router_id_check(bmd);
	if (check_ret) return check_ret;
      }

      /* OPEN options parsing */
      if (bopen->bgpo_optlen && bopen->bgpo_optlen >= 2) {
	u_int8_t len, opt_type, opt_len;
	char *ptr;

	/* pre-flight check */
	if (ntohs(bopen->bgpo_len) < (BGP_MIN_OPEN_MSG_SIZE + bopen->bgpo_optlen)) {
          bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
	  Log(LOG_INFO, "INFO ( %s/%s ): [%s] Received malformed BGP Open packet (too long option length).\n",
	      config.name, bms->log_str, bgp_peer_str);
	  return ERR;
	}

	ptr = bgp_packet_ptr + BGP_MIN_OPEN_MSG_SIZE;
	if (online) memset(bgp_open_cap_reply, 0, sizeof(bgp_open_cap_reply));

	for (len = bopen->bgpo_optlen; len > 0; len -= opt_len, ptr += opt_len) {
	  opt_type = (u_int8_t) ptr[0];
	  opt_len = (u_int8_t) ptr[1];

	  if (opt_len > len) {
            bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
	    Log(LOG_INFO, "INFO ( %s/%s ): [%s] Received malformed BGP Open packet (option length overrun).\n",
		config.name, bms->log_str, bgp_peer_str);
	    return ERR;
	  } 

	  /* 
	   * If we stumble upon capabilities let's iterate through them to find
	   * those that we do support (ie. MP-BGP, 4-bytes AS support, etc.)
 	   */
	  if (opt_type == BGP_OPTION_CAPABILITY) {
	    char *optcap_ptr, *bgp_open_cap_len_reply_ptr, *bgp_open_cap_base_reply_ptr;
	    int optcap_len;

	    bgp_open_cap_ptr = ptr;
	    memcpy(bgp_open_cap_reply_ptr, bgp_open_cap_ptr, 2);
	    bgp_open_cap_len_reply_ptr = bgp_open_cap_reply_ptr + 1;
	    bgp_open_cap_base_reply_ptr = bgp_open_cap_reply_ptr;
	    bgp_open_cap_reply_ptr += 2;

	    ptr += 2;
	    len -= 2;
	    optcap_ptr = ptr;
	    optcap_len = opt_len;

	    while (optcap_len > 0) {
	      u_int8_t cap_len = optcap_ptr[1];
	      u_int8_t cap_type = optcap_ptr[0];

	      if (cap_len > optcap_len) {
                bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
		Log(LOG_INFO, "INFO ( %s/%s ): [%s] Received malformed BGP Open packet (malformed capability: %x).\n",
			config.name, bms->log_str, bgp_peer_str, cap_type);
		return ERR;
   	      }
				     
	      if (cap_type == BGP_CAPABILITY_MULTIPROTOCOL) {
	  	char *cap_ptr = optcap_ptr+2;
	  	struct capability_mp_data cap_data;

	  	memcpy(&cap_data, cap_ptr, sizeof(cap_data));
					  
		if (online) {
                  bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
	  	  Log(LOG_INFO, "INFO ( %s/%s ): [%s] Capability: MultiProtocol [%x] AFI [%x] SAFI [%x]\n",
			config.name, bms->log_str, bgp_peer_str, cap_type, ntohs(cap_data.afi), cap_data.safi);
		}
		peer->cap_mp = TRUE;

		if (online) {
		  memcpy(bgp_open_cap_reply_ptr, optcap_ptr, cap_len+2);
		  bgp_open_cap_reply_ptr += cap_len+2;
		}
	      }
	      else if (cap_type == BGP_CAPABILITY_4_OCTET_AS_NUMBER) {
		char *cap_ptr = optcap_ptr+2;
		u_int32_t as4_ptr;

	   	if (cap_len == CAPABILITY_CODE_AS4_LEN) {
		  struct capability_as4 cap_data;

		  memcpy(&cap_data, cap_ptr, sizeof(cap_data));

		  if (online) {
                    bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
		    Log(LOG_INFO, "INFO ( %s/%s ): [%s] Capability: 4-bytes AS [%x] ASN [%u]\n",
	    		config.name, bms->log_str, bgp_peer_str, cap_type, ntohl(cap_data.as4));
		  }
		  memcpy(&as4_ptr, cap_ptr, 4);
		  remote_as4 = ntohl(as4_ptr);

		  if (online) {
		    memcpy(bgp_open_cap_reply_ptr, optcap_ptr, cap_len+2); 
		    peer->cap_4as = bgp_open_cap_reply_ptr+2;
		    bgp_open_cap_reply_ptr += cap_len+2;
		  }
		  else peer->cap_4as = bgp_open_cap_ptr+4;
		}
		else {
                  bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
		  Log(LOG_INFO, "INFO ( %s/%s ): [%s] Received malformed BGP Open packet (malformed AS4 option).\n",
			config.name, bms->log_str, bgp_peer_str);
		  return ERR;
		}
	      }
	      else if (cap_type == BGP_CAPABILITY_ADD_PATHS) {
		char *cap_ptr = (optcap_ptr + 2);
		struct capability_add_paths cap_data;

		int cap_set = FALSE;
		u_int8_t *cap_newlen_ptr; /* ptr to field of outbound cap_len */
		int cap_idx;
		
		/* check for each AFI.SAFI included if remote can send - only then reply with receive */
		for (cap_idx = 0; cap_idx < cap_len; cap_idx += sizeof(struct capability_add_paths)) {
		  memcpy(&cap_data, cap_ptr+cap_idx, sizeof(cap_data));
		  if (online) {
		    bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
		    Log(LOG_INFO, "INFO ( %s/%s ): [%s] Capability: ADD-PATHs [%x] AFI [%x] SAFI [%x] SEND_RECEIVE [%x]\n",
		  	config.name, bms->log_str, bgp_peer_str, cap_type, ntohs(cap_data.afi), cap_data.safi,
			cap_data.sndrcv);
		  }
		  if ((cap_data.sndrcv == 2 /* send */) || (cap_data.sndrcv == 3 /* send and receive */)) {
		    peer->cap_add_paths[ntohs(cap_data.afi)][cap_data.safi] = TRUE; 
		    if (online) {
		      if (!cap_set) {
			/* we need to send BGP_CAPABILITY_ADD_PATHS first */
			cap_set = TRUE;
			memcpy(bgp_open_cap_reply_ptr, optcap_ptr, 2);
			cap_newlen_ptr = (u_char *)(bgp_open_cap_reply_ptr + 1);
			(*cap_newlen_ptr) = 0;
			bgp_open_cap_reply_ptr += 2;
		      }
		      cap_data.sndrcv = 1; /* we can receive */
		      (*cap_newlen_ptr) += sizeof(cap_data);
		      memcpy(bgp_open_cap_reply_ptr, &cap_data, sizeof(cap_data));
		      bgp_open_cap_reply_ptr += sizeof(cap_data);
		    }
		  }
	        }
	      }
	      else if (cap_type == BGP_CAPABILITY_ROUTE_REFRESH) {
		if (config.tmp_bgp_daemon_route_refresh) {
		  bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
		  Log(LOG_INFO, "INFO ( %s/%s ): [%s] Capability: Route Refresh [%x]\n",
		      config.name, bms->log_str, bgp_peer_str, cap_type);

		  memcpy(bgp_open_cap_reply_ptr, optcap_ptr, cap_len+2); 
		  bgp_open_cap_reply_ptr += cap_len+2;
		}
	      }

	      optcap_ptr += (cap_len + 2);
	      optcap_len -= (cap_len + 2);
	    }

	    /* writing the new capability length */
	    if (bgp_open_cap_reply_ptr > bgp_open_cap_base_reply_ptr + 2) {
	      (*bgp_open_cap_len_reply_ptr) = ((bgp_open_cap_reply_ptr - bgp_open_cap_base_reply_ptr) - 2);
	    }
	    /* otherwise rollback */
	    else {
	      bgp_open_cap_reply_ptr = bgp_open_cap_base_reply_ptr;
	    }
	  }
	  else {
	    ptr += 2;
	    len -= 2;
	  }
	} 
      }

      /* Let's grasp the remote ASN */
      if (remote_as == BGP_AS_TRANS) {
	if (remote_as4 && remote_as4 != BGP_AS_TRANS)
	  peer->as = remote_as4;
	/* It is not valid to use the transitional ASN in the BGP OPEN and
 	   present an ASN == 0 or ASN == 23456 in the 4AS capability */
	else {
          bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
	  Log(LOG_INFO, "INFO ( %s/%s ): [%s] Received malformed BGP Open packet (invalid AS4 option).\n",
		config.name, bms->log_str, bgp_peer_str);
	  return ERR;
	}
      }
      else {
	if (remote_as4 == 0 || remote_as4 == remote_as)
	  peer->as = remote_as;
 	/* It is not valid to not use the transitional ASN in the BGP OPEN and
	   present an ASN != remote_as in the 4AS capability */
	else {
          bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
	  Log(LOG_INFO, "INFO ( %s/%s ): [%s] Received malformed BGP Open packet (mismatching AS4 option).\n",
		config.name, bms->log_str, bgp_peer_str);
	  return ERR;
	}
      }

      if (online) {
        bgp_reply_pkt_ptr = bgp_reply_pkt;

        /* Replying to OPEN message */
	if (!config.bgp_daemon_as) peer->myas = peer->as;
	else peer->myas = config.bgp_daemon_as;

        bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
        Log(LOG_INFO, "INFO ( %s/%s ): [%s] BGP_OPEN: Local AS: %u Remote AS: %u HoldTime: %u\n", config.name,
		bms->log_str, bgp_peer_str, peer->myas, peer->as, peer->ht);

        ret = bgp_write_open_msg(bgp_reply_pkt_ptr, bgp_open_cap_reply, bgp_open_cap_reply_ptr-bgp_open_cap_reply, peer);
        if (ret > 0) bgp_reply_pkt_ptr += ret;
        else {
          bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
	  Log(LOG_INFO, "INFO ( %s/%s ): [%s] Local peer is 4AS while remote peer is 2AS: unsupported configuration.\n",
		config.name, bms->log_str, bgp_peer_str);
	  return ERR;
        }

        /* sticking a KEEPALIVE to it */
        bgp_reply_pkt_ptr += bgp_write_keepalive_msg(bgp_reply_pkt_ptr);
        ret = send(peer->fd, bgp_reply_pkt, bgp_reply_pkt_ptr - bgp_reply_pkt, 0);
        peer->last_keepalive = now;
      }
    }
    else {
      bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] Received malformed BGP Open packet (unsupported version).\n",
		config.name, bms->log_str, bgp_peer_str);
      return ERR;
    }

    peer->status = Established;

    return (BGP_MIN_OPEN_MSG_SIZE + bopen->bgpo_optlen); 
  }

  return ERR;
}

int bgp_max_msglen_check(u_int32_t length)
{
  if (length <= BGP_MAX_MSGLEN) return SUCCESS; 
  else return ERR;
}

/* Marker check. */
int bgp_marker_check(struct bgp_header *bhdr, int length)
{
  int i;

  for (i = 0; i < length; i++)
    if (bhdr->bgpo_marker[i] != 0xff)
      return ERR;

  return SUCCESS;
}

/* write BGP KEEPALIVE msg */
int bgp_write_keepalive_msg(char *msg)
{
  struct bgp_header bhdr;
	
  memset(&bhdr.bgpo_marker, 0xff, BGP_MARKER_SIZE);
  bhdr.bgpo_type = BGP_KEEPALIVE;
  bhdr.bgpo_len = htons(BGP_HEADER_SIZE);
  memcpy(msg, &bhdr, sizeof(bhdr));

  return BGP_HEADER_SIZE;
}

/* write BGP OPEN msg */
int bgp_write_open_msg(char *msg, char *cp_msg, int cp_msglen, struct bgp_peer *peer)
{
  struct bgp_open *bopen_reply = (struct bgp_open *) msg;
  char my_id_static[] = "1.2.3.4", *my_id = my_id_static;
  struct host_addr my_id_addr, bgp_ip, bgp_id;
  u_int16_t local_as;
  u_int32_t *local_as4;

  memset(bopen_reply->bgpo_marker, 0xff, BGP_MARKER_SIZE);
  bopen_reply->bgpo_type = BGP_OPEN;
  bopen_reply->bgpo_version = BGP_VERSION4;
  bopen_reply->bgpo_holdtime = htons(peer->ht);
  if (peer->myas > BGP_AS_MAX) {
    if (peer->cap_4as) {
      bopen_reply->bgpo_myas = htons(BGP_AS_TRANS);
      local_as4 = (u_int32_t *) peer->cap_4as;
      *local_as4 = htonl(peer->myas);
    }
    /* This is currently an unsupported configuration */
    else return ERR;
  }
  else {
    local_as = peer->myas;
    bopen_reply->bgpo_myas = htons(local_as);
    if (peer->cap_4as) {
      local_as4 = (u_int32_t *) peer->cap_4as;
      *local_as4 = htonl(peer->myas);
    }
  }

  if (cp_msglen) bopen_reply->bgpo_optlen = cp_msglen;
  bopen_reply->bgpo_len = htons(BGP_MIN_OPEN_MSG_SIZE + bopen_reply->bgpo_optlen);

  if (config.bgp_daemon_ip) str_to_addr(config.bgp_daemon_ip, &bgp_ip);
  else memset(&bgp_ip, 0, sizeof(bgp_ip));

  if (config.bgp_daemon_id) str_to_addr(config.bgp_daemon_id, &bgp_id);
  else memset(&bgp_id, 0, sizeof(bgp_id));

  /* set BGP router-ID trial #1 */
  memset(&my_id_addr, 0, sizeof(my_id_addr));

  if (config.bgp_daemon_id && !is_any(&bgp_id) && !my_id_addr.family) {
    my_id = config.bgp_daemon_id;
    str_to_addr(my_id, &my_id_addr);
    if (my_id_addr.family != AF_INET) memset(&my_id_addr, 0, sizeof(my_id_addr));
  }

  /* set BGP router-ID trial #2 */
  if (config.bgp_daemon_ip && !is_any(&bgp_ip) && !my_id_addr.family) {
    my_id = config.bgp_daemon_ip;
    str_to_addr(my_id, &my_id_addr);
    if (my_id_addr.family != AF_INET) memset(&my_id_addr, 0, sizeof(my_id_addr));
  }

  /* set BGP router-ID trial #3 */
  if (!my_id_addr.family) {
    my_id = my_id_static;
    str_to_addr(my_id, &my_id_addr);
  }

  bopen_reply->bgpo_id = my_id_addr.address.ipv4.s_addr;

  memcpy(msg+BGP_MIN_OPEN_MSG_SIZE, cp_msg, cp_msglen);

  return BGP_MIN_OPEN_MSG_SIZE + cp_msglen;
}

int bgp_write_notification_msg(char *msg, int msglen, u_int8_t n_major, u_int8_t n_minor, char *shutdown_msg)
{
  struct bgp_notification *bn_reply = (struct bgp_notification *) msg;
  struct bgp_notification_shutdown_msg *bnsm_reply;
  u_int16_t shutdown_msglen;
  int ret = FALSE;
  char *reply_msg_ptr;

  if (bn_reply && msglen >= BGP_MIN_NOTIFICATION_MSG_SIZE) {
    memset(bn_reply->bgpn_marker, 0xff, BGP_MARKER_SIZE);

    bn_reply->bgpn_len = ntohs(BGP_MIN_NOTIFICATION_MSG_SIZE); 
    bn_reply->bgpn_type = BGP_NOTIFICATION; 

    if (!n_major) bn_reply->bgpn_major = BGP_NOTIFY_CEASE;
    else bn_reply->bgpn_major = n_major;

    if (!n_minor) bn_reply->bgpn_minor = BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN;
    else bn_reply->bgpn_minor =  n_minor;

    ret += BGP_MIN_NOTIFICATION_MSG_SIZE;

    /* rfc8203 */
    if (shutdown_msg) {
      shutdown_msglen = strlen(shutdown_msg);

      if (shutdown_msglen <= BGP_NOTIFY_CEASE_SM_LEN) {
        if (msglen >= (BGP_MIN_NOTIFICATION_MSG_SIZE + shutdown_msglen)) {
          reply_msg_ptr = (char *) (msg + BGP_MIN_NOTIFICATION_MSG_SIZE);
          memset(reply_msg_ptr, 0, (msglen - BGP_MIN_NOTIFICATION_MSG_SIZE));
          bnsm_reply = (struct bgp_notification_shutdown_msg *) reply_msg_ptr;

          bnsm_reply->bgpnsm_len = shutdown_msglen;
          strncpy(bnsm_reply->bgpnsm_data, shutdown_msg, shutdown_msglen);
	  bn_reply->bgpn_len = htons(BGP_MIN_NOTIFICATION_MSG_SIZE + shutdown_msglen + 1 /* bgpnsm_len */);
          ret += (shutdown_msglen + 1 /* bgpnsm_len */);
	}
      }
    }
  }

  return ret;
}

int bgp_parse_notification_msg(struct bgp_msg_data *bmd, char *pkt, u_int8_t *res_maj, u_int8_t *res_min, char *shutdown_msg, u_int16_t shutdown_msglen)
{
  struct bgp_peer *peer = bmd->peer;
  struct bgp_notification *bn = (struct bgp_notification *) pkt;
  struct bgp_notification_shutdown_msg *bnsm;
  char *pkt_ptr = pkt;
  u_int32_t rem_len;
  int ret = 0;

  if (!peer || !pkt || !shutdown_msg || peer->msglen < BGP_MIN_NOTIFICATION_MSG_SIZE) return ERR;

  rem_len = peer->msglen;
  ret += BGP_MIN_NOTIFICATION_MSG_SIZE;
  rem_len -= BGP_MIN_NOTIFICATION_MSG_SIZE;
  (*res_maj) = bn->bgpn_major;
  (*res_min) = bn->bgpn_minor;

  /* rfc8203 */
  if (bn->bgpn_major == BGP_NOTIFY_CEASE &&
      (bn->bgpn_minor == BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN || bn->bgpn_minor == BGP_NOTIFY_CEASE_ADMIN_RESET)) {
    if (rem_len) {
      pkt_ptr = (pkt + BGP_MIN_NOTIFICATION_MSG_SIZE);
      bnsm = (struct bgp_notification_shutdown_msg *) pkt_ptr;

      if (bnsm->bgpnsm_len <= rem_len && bnsm->bgpnsm_len < shutdown_msglen) {
	memcpy(shutdown_msg, bnsm->bgpnsm_data, bnsm->bgpnsm_len);
	shutdown_msg[bnsm->bgpnsm_len] = '\0';
	
	ret += (bnsm->bgpnsm_len + 1);
	rem_len -= (bnsm->bgpnsm_len + 1);
      }
    }
  }

  return ret;
}

int bgp_parse_update_msg(struct bgp_msg_data *bmd, char *pkt)
{
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer = bmd->peer;
  char bgp_peer_str[INET6_ADDRSTRLEN];
  struct bgp_header bhdr;
  struct bgp_attr attr;
  struct bgp_attr_extra attr_extra;
  u_int16_t attribute_len;
  u_int16_t update_len;
  u_int16_t withdraw_len;
  u_int16_t end, tmp;
  struct bgp_nlri update;
  struct bgp_nlri withdraw;
  struct bgp_nlri mp_update;
  struct bgp_nlri mp_withdraw;
  int ret, parsed = FALSE;

  if (!peer || !pkt) return ERR;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) return ERR;

  /* Set initial values. */
  memset(&attr, 0, sizeof (struct bgp_attr));
  memset(&attr_extra, 0, sizeof (struct bgp_attr_extra));
  memset(&update, 0, sizeof (struct bgp_nlri));
  memset(&withdraw, 0, sizeof (struct bgp_nlri));
  memset(&mp_update, 0, sizeof (struct bgp_nlri));
  memset(&mp_withdraw, 0, sizeof (struct bgp_nlri));

  memcpy(&bhdr, pkt, sizeof(bhdr));
  end = ntohs(bhdr.bgpo_len);
  end -= BGP_HEADER_SIZE;
  pkt += BGP_HEADER_SIZE;

  /* handling Unfeasible routes */
  memcpy(&tmp, pkt, 2);
  withdraw_len = ntohs(tmp);
  if (withdraw_len > end) return ERR;  
  else {
    end -= withdraw_len;
    pkt += 2; end -= 2;
  }

  if (withdraw_len > 0) {
    withdraw.afi = AFI_IP;
    withdraw.safi = SAFI_UNICAST;
    withdraw.nlri = (u_char *) pkt;
    withdraw.length = withdraw_len;
    pkt += withdraw_len;
  }

  /* handling Attributes */
  memcpy(&tmp, pkt, 2);
  attribute_len = ntohs(tmp);
  if (attribute_len > end) return ERR;
  else {
    end -= attribute_len;
    pkt += 2; end -= 2;
  }

  if (attribute_len > 0) {
    ret = bgp_attr_parse(peer, &attr, &attr_extra, pkt, attribute_len, &mp_update, &mp_withdraw);
    if (ret < 0) return ret;
    pkt += attribute_len;
  }

  update_len = end; end = 0;

  if (update_len > 0) {
    update.afi = AFI_IP;
    update.safi = SAFI_UNICAST;
    update.nlri = (u_char *) pkt;
    update.length = update_len;
  }

  /* NLRI parsing */
  if (withdraw.length) {
    bgp_nlri_parse(bmd, NULL, &attr_extra, &withdraw, BGP_NLRI_WITHDRAW);
    parsed = TRUE;
  }

  if (update.length) {
    bgp_nlri_parse(bmd, &attr, &attr_extra, &update, BGP_NLRI_UPDATE);
    parsed = TRUE;
  }
	
  if (mp_update.length
	  && mp_update.afi == AFI_IP
	  && (mp_update.safi == SAFI_UNICAST || mp_update.safi == SAFI_MPLS_LABEL ||
	      mp_update.safi == SAFI_MPLS_VPN)) {
    bgp_nlri_parse(bmd, &attr, &attr_extra, &mp_update, BGP_NLRI_UPDATE);
    parsed = TRUE;
  }

  if (mp_withdraw.length
	  && mp_withdraw.afi == AFI_IP
	  && (mp_withdraw.safi == SAFI_UNICAST || mp_withdraw.safi == SAFI_MPLS_LABEL ||
	      mp_withdraw.safi == SAFI_MPLS_VPN)) {
    bgp_nlri_parse (bmd, NULL, &attr_extra, &mp_withdraw, BGP_NLRI_WITHDRAW);
    parsed = TRUE;
  }

  if (mp_update.length
	  && mp_update.afi == AFI_IP6
	  && (mp_update.safi == SAFI_UNICAST || mp_update.safi == SAFI_MPLS_LABEL ||
	      mp_update.safi == SAFI_MPLS_VPN)) {
    bgp_nlri_parse(bmd, &attr, &attr_extra, &mp_update, BGP_NLRI_UPDATE);
    parsed = TRUE;
  }

  if (mp_withdraw.length
	  && mp_withdraw.afi == AFI_IP6
	  && (mp_withdraw.safi == SAFI_UNICAST || mp_withdraw.safi == SAFI_MPLS_LABEL ||
	      mp_withdraw.safi == SAFI_MPLS_VPN)) {
    bgp_nlri_parse(bmd, NULL, &attr_extra, &mp_withdraw, BGP_NLRI_WITHDRAW);
    parsed = TRUE;
  }

  if (mp_update.length
	  && mp_update.afi == AFI_BGP_LS
	  && (mp_update.safi == SAFI_LS_GLOBAL || mp_update.safi == SAFI_LS_VPN)) {
    bgp_nlri_parse(bmd, &attr, &attr_extra, &mp_update, BGP_NLRI_UPDATE);
    parsed = TRUE;
  }

  if (mp_withdraw.length
	  && mp_withdraw.afi == AFI_BGP_LS
	  && (mp_withdraw.safi == SAFI_LS_GLOBAL || mp_withdraw.safi == SAFI_LS_VPN)) {
    bgp_nlri_parse(bmd, &attr, &attr_extra, &mp_update, BGP_NLRI_WITHDRAW);
    parsed = TRUE;
  }

  /* Receipt of End-of-RIB can be processed here; being a silent
	 BGP receiver only, honestly it doesn't matter to us */

  if ((update_len || withdraw_len ||  mp_update.length || mp_withdraw.length) && !parsed) {
    bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
    Log(LOG_DEBUG, "DEBUG ( %s/%s ): [%s] bgp_parse_update_msg() Received unsupported NLRI afi=%u safi=%u\n",
        config.name, bms->log_str, bgp_peer_str,
	mp_update.length ? mp_update.afi : mp_withdraw.afi,
	mp_update.length ? mp_update.safi : mp_withdraw.safi);
  }

  /* Everything is done.  We unintern temporary structures which
	 interned in bgp_attr_parse(). */
  if (attr.aspath)
    aspath_unintern(peer, attr.aspath);
  if (attr.community)
    community_unintern(peer, attr.community);
  if (attr.ecommunity)
    ecommunity_unintern(peer, attr.ecommunity);
  if (attr.lcommunity)
    lcommunity_unintern(peer, attr.lcommunity);

  ret = ntohs(bhdr.bgpo_len);

  return ret;
}

/* BGP UPDATE Attribute parsing */
int bgp_attr_parse(struct bgp_peer *peer, struct bgp_attr *attr, struct bgp_attr_extra *attr_extra,
		   char *ptr, int len, struct bgp_nlri *mp_update, struct bgp_nlri *mp_withdraw)
{
  int to_the_end = len, ret;
  u_int8_t flag, type, *tmp;
  u_int16_t tmp16, attr_len;
  struct aspath *as4_path = NULL;

  if (!ptr) return ERR;

  while (to_the_end > 0) {
    if (to_the_end < BGP_ATTR_MIN_LEN) return ERR;

    tmp = (u_int8_t *) ptr++; to_the_end--; flag = *tmp;
    tmp = (u_int8_t *) ptr++; to_the_end--; type = *tmp;

    /* Attribute length */
    if (flag & BGP_ATTR_FLAG_EXTLEN) {
      memcpy(&tmp16, ptr, 2); ptr += 2; to_the_end -= 2; attr_len = ntohs(tmp16);
      if (attr_len > to_the_end) return ERR;
    }
    else {
      tmp = (u_int8_t *) ptr++; to_the_end--; attr_len = *tmp;
      if (attr_len > to_the_end) return ERR;
    }

    switch (type) {
    case BGP_ATTR_AS_PATH:
      ret = bgp_attr_parse_aspath(peer, attr_len, attr, ptr, flag);
      break;
    case BGP_ATTR_AS4_PATH:
      ret = bgp_attr_parse_as4path(peer, attr_len, attr, ptr, flag, &as4_path);
      break;
    case BGP_ATTR_NEXT_HOP:
      ret = bgp_attr_parse_nexthop(peer, attr_len, attr, ptr, flag);
      break;
    case BGP_ATTR_COMMUNITIES:
      ret = bgp_attr_parse_community(peer, attr_len, attr, ptr, flag);
      break;
    case BGP_ATTR_EXT_COMMUNITIES:
      ret = bgp_attr_parse_ecommunity(peer, attr_len, attr, ptr, flag);
      break;
    case BGP_ATTR_LARGE_COMMUNITIES:
      ret = bgp_attr_parse_lcommunity(peer, attr_len, attr, ptr, flag);
      break;
    case BGP_ATTR_MULTI_EXIT_DISC:
      ret = bgp_attr_parse_med(peer, attr_len, attr, ptr, flag);
      break;
    case BGP_ATTR_LOCAL_PREF:
      ret = bgp_attr_parse_local_pref(peer, attr_len, attr, ptr, flag);
      break;
    case BGP_ATTR_ORIGIN:
      ret = bgp_attr_parse_origin(peer, attr_len, attr, ptr, flag);
      break;
    case BGP_ATTR_MP_REACH_NLRI:
      ret = bgp_attr_parse_mp_reach(peer, attr_len, attr, ptr, mp_update);
      break;
    case BGP_ATTR_MP_UNREACH_NLRI:
      ret = bgp_attr_parse_mp_unreach(peer, attr_len, attr, ptr, mp_withdraw);
      break;
    case BGP_ATTR_AIGP:
      ret = bgp_attr_parse_aigp(peer, attr_len, attr_extra, ptr, flag);
      break;
    case BGP_ATTR_PREFIX_SID:
      ret = bgp_attr_parse_prefix_sid(peer, attr_len, attr_extra, ptr, flag);
      break;
    default:
      ret = 0;
      break;
    }

    if (ret < 0) return ret; 

    ptr += attr_len;
    to_the_end -= attr_len;
  }

  if (as4_path) {
    /* AS_PATH and AS4_PATH merge up */
    ret = bgp_attr_munge_as4path(peer, attr, as4_path);

    /* AS_PATH and AS4_PATH info are now fully merged;
       hence we can free up temporary structures. */
    aspath_unintern(peer, as4_path);
  
    if (ret < 0) return ret;
  }

  return SUCCESS;
}

int bgp_attr_parse_aspath(struct bgp_peer *peer, u_int16_t len, struct bgp_attr *attr, char *ptr, u_int8_t flag)
{
  u_int8_t cap_4as = peer->cap_4as ? 1 : 0;

  attr->aspath = aspath_parse(peer, ptr, len, cap_4as);

  return SUCCESS;
}

int bgp_attr_parse_as4path(struct bgp_peer *peer, u_int16_t len, struct bgp_attr *attr, char *ptr, u_int8_t flag, struct aspath **aspath4)
{
  *aspath4 = aspath_parse(peer, ptr, len, 1);

  return SUCCESS;
}

int bgp_attr_parse_nexthop(struct bgp_peer *peer, u_int16_t len, struct bgp_attr *attr, char *ptr, u_char flag)
{
  u_int32_t tmp;

  /* Length check. */
  if (len != 4) return ERR;

  memcpy(&tmp, ptr, 4);
  attr->nexthop.s_addr = tmp;
  ptr += 4;

  return SUCCESS;
}

int bgp_attr_parse_community(struct bgp_peer *peer, u_int16_t len, struct bgp_attr *attr, char *ptr, u_int8_t flag)
{
  if (len == 0) attr->community = NULL;
  else attr->community = (struct community *) community_parse(peer, (u_int32_t *)ptr, len);

  return SUCCESS;
}

int bgp_attr_parse_ecommunity(struct bgp_peer *peer, u_int16_t len, struct bgp_attr *attr, char *ptr, u_int8_t flag)
{
  if (len == 0) attr->ecommunity = NULL;
  else attr->ecommunity = (struct ecommunity *) ecommunity_parse(peer, (u_char *) ptr, len);

  return SUCCESS;
}

int bgp_attr_parse_lcommunity(struct bgp_peer *peer, u_int16_t len, struct bgp_attr *attr, char *ptr, u_int8_t flag)
{
  if (len == 0) attr->lcommunity = NULL;
  else attr->lcommunity = (struct lcommunity *) lcommunity_parse(peer, (u_char *) ptr, len);

  return SUCCESS;
}

/* MED atrribute. */
int bgp_attr_parse_med(struct bgp_peer *peer, u_int16_t len, struct bgp_attr *attr, char *ptr, u_char flag)
{
  u_int32_t tmp;

  /* Length check. */
  if (len != 4) return ERR;

  memcpy(&tmp, ptr, 4);
  attr->med = ntohl(tmp);
  attr->bitmap |= BGP_BMAP_ATTR_MULTI_EXIT_DISC;
  ptr += 4;

  return SUCCESS;
}

/* Local preference attribute. */
int bgp_attr_parse_local_pref(struct bgp_peer *peer, u_int16_t len, struct bgp_attr *attr, char *ptr, u_char flag)
{
  u_int32_t tmp;

  if (len != 4) return ERR;

  memcpy(&tmp, ptr, 4);
  attr->local_pref = ntohl(tmp);
  attr->bitmap |= BGP_BMAP_ATTR_LOCAL_PREF;
  ptr += 4;

  return SUCCESS;
}

/* Origin attribute. */
int bgp_attr_parse_origin(struct bgp_peer *peer, u_int16_t len, struct bgp_attr *attr, char *ptr, u_char flag)
{
  if (len != 1) return ERR;

  memcpy(&attr->origin, ptr, 1);
  ptr += 1;

  return SUCCESS;
}

int bgp_attr_parse_mp_reach(struct bgp_peer *peer, u_int16_t len, struct bgp_attr *attr, char *ptr, struct bgp_nlri *mp_update)
{
  u_int16_t afi, tmp16, mpreachlen, mpnhoplen;
  u_int16_t nlri_len;
  u_char safi;

  /* length check */
#define BGP_MP_REACH_MIN_SIZE 5
  if (len < BGP_MP_REACH_MIN_SIZE) return ERR;

  mpreachlen = len;
  memcpy(&tmp16, ptr, 2); afi = ntohs(tmp16); ptr += 2;
  safi = *ptr; ptr++;
  mpnhoplen = *ptr; ptr++;
  mpreachlen -= 4; /* 2+1+1 above */ 
  
  /* IPv4 (4), RD+IPv4 (12), IPv6 (16), RD+IPv6 (24), IPv6 link-local+IPv6 global (32) */
  if (mpnhoplen == 4 || mpnhoplen == 12 || mpnhoplen == 16 || mpnhoplen == 24 || mpnhoplen == 32) {
    if (mpreachlen > mpnhoplen) {
      memset(&attr->mp_nexthop, 0, sizeof(struct host_addr));

      switch (mpnhoplen) {
      case 4:
	attr->mp_nexthop.family = AF_INET;
	memcpy(&attr->mp_nexthop.address.ipv4, ptr, 4); 
	break;
      case 12:
	// XXX: make any use of RD ? 
	attr->mp_nexthop.family = AF_INET;
	memcpy(&attr->mp_nexthop.address.ipv4, ptr+8, 4);
	break;
      case 16:
      case 32:
	attr->mp_nexthop.family = AF_INET6;
	memcpy(&attr->mp_nexthop.address.ipv6, ptr, 16); 
	break;
      case 24:
	// XXX: make any use of RD ? 
	attr->mp_nexthop.family = AF_INET6;
	memcpy(&attr->mp_nexthop.address.ipv6, ptr+8, 16);
	break;
      default:
	memset(&attr->mp_nexthop, 0, sizeof(struct host_addr));
	break;
      }

      mpreachlen -= mpnhoplen;
      ptr += mpnhoplen;

      /* Skipping SNPA info */
      mpreachlen--; ptr++;
    }
    else return ERR;
  }
  else return ERR;

  nlri_len = mpreachlen;

  /* length check once again */
  if (!nlri_len || nlri_len > len) return ERR;

  /* XXX: perhaps sanity check (applies to: mp_reach, mp_unreach, update, withdraw) */

  mp_update->afi = afi;
  mp_update->safi = safi;
  mp_update->nlri = (u_char *) ptr;
  mp_update->length = nlri_len;

  return SUCCESS;
}

int bgp_attr_parse_mp_unreach(struct bgp_peer *peer, u_int16_t len, struct bgp_attr *attr, char *ptr, struct bgp_nlri *mp_withdraw)
{
  u_int16_t afi, mpunreachlen, tmp16;
  u_int16_t withdraw_len;
  u_char safi;

  /* length check */
#define BGP_MP_UNREACH_MIN_SIZE 3
  if (len < BGP_MP_UNREACH_MIN_SIZE) return ERR;

  mpunreachlen = len;
  memcpy(&tmp16, ptr, 2); afi = ntohs(tmp16); ptr += 2;
  safi = *ptr; ptr++;
  mpunreachlen -= 3; /* 2+1 above */

  withdraw_len = mpunreachlen;

  mp_withdraw->afi = afi;
  mp_withdraw->safi = safi;
  mp_withdraw->nlri = (u_char *) ptr;
  mp_withdraw->length = withdraw_len;

  return SUCCESS;
}

/* BGP UPDATE NLRI parsing */
int bgp_nlri_parse(struct bgp_msg_data *bmd, void *attr, struct bgp_attr_extra *attr_extra, struct bgp_nlri *info, int type)
{
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer = bmd->peer;
  char bgp_peer_str[INET6_ADDRSTRLEN];
  u_char *pnt;
  u_char *lim;
  struct prefix p;
  int psize = 0, end;
  int ret, idx;
  u_int32_t tmp32;
  u_int16_t tmp16;
  struct rd_ip  *rdi;
  struct rd_as  *rda;
  struct rd_as4 *rda4;

  if (!peer) return ERR;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) return ERR;
  
  memset(&p, 0, sizeof(struct prefix));

  pnt = info->nlri;
  lim = pnt + info->length;
  end = info->length;

  for (idx = 0; pnt < lim; pnt += psize, idx++) {
    /* handle path identifier */
    if (peer->cap_add_paths[info->afi][info->safi]) {
      memcpy(&attr_extra->path_id, pnt, 4);
      attr_extra->path_id = ntohl(attr_extra->path_id);
      pnt += 4;
    }

    memset(&p, 0, sizeof(struct prefix));

    /* Fetch prefix length and cross-check */
    p.prefixlen = *pnt++; end--;
    p.family = bgp_afi2family (info->afi);

    if (info->safi == SAFI_UNICAST) {
      if ((info->afi == AFI_IP && p.prefixlen > 32) || (info->afi == AFI_IP6 && p.prefixlen > 128)) return ERR;

      psize = ((p.prefixlen+7)/8);
      if (psize > end) return ERR;

      /* Fetch prefix from NLRI packet. */
      memcpy(&p.u.prefix, pnt, psize);
    }
    else if (info->safi == SAFI_MPLS_LABEL) { /* rfc3107 labeled unicast */
      int labels_size = 0;
      u_char *label_ptr = NULL;

      if ((info->afi == AFI_IP && p.prefixlen > 56) || (info->afi == AFI_IP6 && p.prefixlen > 152)) return ERR;

      psize = ((p.prefixlen+7)/8);
      if (psize > end || psize < 3 /* one label */) return ERR;

      /* Fetch label(s) and prefix from NLRI packet */
      label_ptr = pnt;

      if (type == BGP_NLRI_UPDATE) {
	while (((labels_size + 3) <= psize) && !check_bosbit(label_ptr)) {
	  label_ptr += 3;
	  labels_size += 3;
	}
      }

      if ((labels_size + 3) <= psize) {
        memcpy(attr_extra->label, label_ptr, 3);
        label_ptr += 3;
        labels_size += 3;
      }
      else return ERR;
	
      memcpy(&p.u.prefix, (pnt + labels_size), (psize - labels_size));
      p.prefixlen -= (8 * labels_size);
    }
    else if (info->safi == SAFI_MPLS_VPN) { /* rfc4364 BGP/MPLS IP Virtual Private Networks */
      int labels_size = 0;
      u_char *label_ptr = NULL;

      if ((info->afi == AFI_IP && p.prefixlen > 120) || (info->afi == AFI_IP6 && p.prefixlen > 216)) return ERR;

      psize = ((p.prefixlen+7)/8);
      if (psize > end || psize < 3 /* one label */) return ERR;

      /* Fetch label (3), RD (8) and prefix from NLRI packet */
      label_ptr = pnt;

      if (type == BGP_NLRI_UPDATE) {
	while (((labels_size + 3) <= psize) && !check_bosbit(label_ptr)) {
	  label_ptr += 3;
	  labels_size += 3;
	}
      }

      if ((labels_size + 3) <= psize) {
	memcpy(attr_extra->label, label_ptr, 3);
	label_ptr += 3;
	labels_size += 3;
      }
      else return ERR;

      if (labels_size + 8 /* RD */ > psize) return ERR; 

      memcpy(&attr_extra->rd.type, (pnt + labels_size), 2);
      attr_extra->rd.type = ntohs(attr_extra->rd.type);
      switch(attr_extra->rd.type) {
      case RD_TYPE_AS: 
	rda = (struct rd_as *) &attr_extra->rd;
	memcpy(&tmp16, (pnt + labels_size + 2 /* RD type */), 2);
	memcpy(&tmp32, (pnt + labels_size + 2 /* RD type */ + 2 /* RD AS */), 4);
	rda->as = ntohs(tmp16);
	rda->val = ntohl(tmp32);
	break;
      case RD_TYPE_IP: 
	rdi = (struct rd_ip *) &attr_extra->rd;
	memcpy(&rdi->ip.s_addr, (pnt + labels_size + 2 /* RD type */), 4);
	memcpy(&tmp16, (pnt + labels_size + 2 /* RD type */ + 4 /* RD IP */), 2);
	rdi->val = ntohs(tmp16);
	break;
      case RD_TYPE_AS4: 
	rda4 = (struct rd_as4 *) &attr_extra->rd;
	memcpy(&tmp32, (pnt + labels_size + 2 /* RD type */), 4);
	memcpy(&tmp16, (pnt + labels_size + 2 /* RD type */ + 4 /* RD AS4 */), 2);
	rda4->as = ntohl(tmp32);
	rda4->val = ntohs(tmp16);
	break;
      default:
	return ERR;
	break;
      }
      bgp_rd_origin_set(&attr_extra->rd, RD_ORIGIN_BGP);
    
      memcpy(&p.u.prefix, (pnt + labels_size + 8 /* RD */), (psize - (labels_size + 8 /* RD */)));
      p.prefixlen -= (8 * (labels_size + 8 /* RD */));
    }
    else {
      bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): [%s] bgp_nlri_parse() Received unsupported NLRI afi=%u safi=%u\n",
        config.name, bms->log_str, bgp_peer_str, info->afi, info->safi);
      continue;
    }

    // XXX: check prefix correctnesss now that we have it?

#if defined WITH_ZMQ
    if (config.bgp_blackhole_stdcomm_list) {
      bmd->is_blackhole = bgp_blackhole_evaluate_comms(attr);

      /* let's process withdraws before withdrawing */  
      if (!attr && bmd->is_blackhole) {
	bgp_blackhole_instrument(peer, &p, attr, info->afi, info->safi);
      }
    }
#endif

    /* Let's do our job now! */
    if (attr) {
      ret = bgp_process_update(bmd, &p, attr, attr_extra, info->afi, info->safi, idx);
    }
    else {
      ret = bgp_process_withdraw(bmd, &p, attr, attr_extra, info->afi, info->safi, idx);
      (void)ret; //Treat error?
    }

#if defined WITH_ZMQ
    if (config.bgp_blackhole_stdcomm_list) {
      /* let's process updates after installing */  
      if (attr && bmd->is_blackhole) {
	bgp_blackhole_instrument(peer, &p, attr, info->afi, info->safi);
      }
    }
#endif
  }

  return SUCCESS;
}

/* AIGP attribute. */
int bgp_attr_parse_aigp(struct bgp_peer *peer, u_int16_t len, struct bgp_attr_extra *attr_extra, char *ptr, u_char flag)
{
  u_int64_t tmp64;
  int ret = SUCCESS;

  /* Length check. */
  if (len < 3) return ERR;

  /* XXX: skipping type check as only type 1 is defined */

  switch (len) {
  case 3:
    attr_extra->aigp = 0; 
    break;
  /* rfc7311: [If present] The value field of the AIGP TLV is always 8 octets long */
  case 11:
    memcpy(&tmp64, (ptr + 3), 8);
    attr_extra->aigp = pm_ntohll(tmp64);
    attr_extra->bitmap |= BGP_BMAP_ATTR_AIGP;
    break;
  default:
    /* unsupported */
    attr_extra->aigp = 0;
    ret = ERR;
    break;
  }

  ptr += len;

  return ret;
}

/* Prefix-SID attribute */
int bgp_attr_parse_prefix_sid(struct bgp_peer *peer, u_int16_t len, struct bgp_attr_extra *attr_extra, char *ptr, u_char flag)
{
  u_int8_t tlv_type;
  u_int16_t tlv_len;
  u_int32_t tmp;

  /* Length check. */
  if (len < 3) return ERR;

  tlv_type = (u_int8_t) (*ptr);
  memcpy(&tlv_len, (ptr + 1), 2);
  tlv_len = ntohs(tlv_len);

  if (tlv_type == BGP_PREFIX_SID_LI_TLV) {
    if (tlv_len == 7) {
      memcpy(&tmp, (ptr + 6), 4);
      attr_extra->psid_li = ntohl(tmp); 
    }
    else {
      return ERR;
    }
  }

  /* XXX: Originator SRGB TLV not decoded yet */

  ptr += len;

  return SUCCESS;
}

int bgp_process_update(struct bgp_msg_data *bmd, struct prefix *p, void *attr, struct bgp_attr_extra *attr_extra, afi_t afi, safi_t safi, int idx)
{
  struct bgp_peer *peer = bmd->peer;
  struct bgp_rt_structs *inter_domain_routing_db;
  struct bgp_misc_structs *bms;
  struct bgp_node *route = NULL, route_local;
  struct bgp_info *ri = NULL, *new = NULL, ri_local;
  struct bgp_attr *attr_new = NULL;
  u_int32_t modulo;

  if (!peer) return ERR;

  inter_domain_routing_db = bgp_select_routing_db(peer->type);
  bms = bgp_select_misc_db(peer->type);

  if (!inter_domain_routing_db || !bms) return ERR;

  if (!bms->skip_rib) { 
    modulo = bms->route_info_modulo(peer, &attr_extra->path_id, bms->table_per_peer_buckets);
    route = bgp_node_get(peer, inter_domain_routing_db->rib[afi][safi], p);

    /* Check previously received route. */
    for (ri = route->info[modulo]; ri; ri = ri->next) {
      if (ri->peer == peer) { 
        if (safi == SAFI_MPLS_VPN) {
	  if (ri->attr_extra && !memcmp(&ri->attr_extra->rd, &attr_extra->rd, sizeof(rd_t)));
	  else continue;
        }

        if (peer->cap_add_paths[afi][safi]) {
	  if (ri->attr_extra && (attr_extra->path_id == ri->attr_extra->path_id));
	  else continue;
        }

	if (ri->bmed.id) {
	  if (bms->bgp_extra_data_cmp && !(*bms->bgp_extra_data_cmp)(&bmd->extra, &ri->bmed));
	  else continue;
	} 

        break;
      }
    }

    attr_new = bgp_attr_intern(peer, attr);

    if (ri) {
      /* Received same information */
      if (attrhash_cmp(ri->attr, attr_new)) {
        bgp_unlock_node(peer, route);
        bgp_attr_unintern(peer, attr_new);

        if (bms->msglog_backend_methods)
	  goto log_update;

        return SUCCESS;
      }
      else {
        /* Update to new attribute.  */
        bgp_attr_unintern(peer, ri->attr);
        ri->attr = attr_new;
        bgp_attr_extra_process(peer, ri, afi, safi, attr_extra);
        if (bms->bgp_extra_data_process) (*bms->bgp_extra_data_process)(&bmd->extra, ri, idx, BGP_NLRI_UPDATE);

        bgp_unlock_node (peer, route);

        if (bms->msglog_backend_methods)
	  goto log_update;

        return SUCCESS;
      }
    }

    /* Make new BGP info. */
    new = bgp_info_new(peer);
    if (new) {
      new->peer = peer;
      new->attr = attr_new;
      bgp_attr_extra_process(peer, new, afi, safi, attr_extra);
      if (bms->bgp_extra_data_process) (*bms->bgp_extra_data_process)(&bmd->extra, new, idx, BGP_NLRI_UPDATE);
    }
    else return ERR;

    /* Register new BGP information. */
    bgp_info_add(peer, route, new, modulo);

    /* route_node_get lock */
    bgp_unlock_node(peer, route);

    if (bms->msglog_backend_methods) {
      ri = new;
      goto log_update;
    }
  }
  else {
    if (bms->msglog_backend_methods) {
      route = &route_local;
      memset(&route_local, 0, sizeof(struct bgp_node));
      memcpy(&route_local.p, p, sizeof(struct prefix)); 

      ri = &ri_local;
      memset(&ri_local, 0, sizeof(struct bgp_info));

      ri->peer = peer;
      ri->attr = bgp_attr_intern(peer, attr);
      bgp_attr_extra_process(peer, ri, afi, safi, attr_extra);
      if (bms->bgp_extra_data_process) (*bms->bgp_extra_data_process)(&bmd->extra, ri, idx, BGP_NLRI_UPDATE);

      goto log_update;
    }
  }

  return SUCCESS;

log_update:
  {
    char event_type[] = "log";

    bgp_peer_log_msg(route, ri, afi, safi, event_type, bms->msglog_output, NULL, BGP_LOG_TYPE_UPDATE);
  }

  if (bms->skip_rib) {
    if (ri->attr_extra) bgp_attr_extra_free(peer, &ri->attr_extra);
    if (bms->bgp_extra_data_free) (*bms->bgp_extra_data_free)(&ri->bmed);
    bgp_attr_unintern(peer, ri->attr);
  }

  return SUCCESS;
}

int bgp_process_withdraw(struct bgp_msg_data *bmd, struct prefix *p, void *attr, struct bgp_attr_extra *attr_extra, afi_t afi, safi_t safi, int idx)
{
  struct bgp_peer *peer = bmd->peer;
  struct bgp_rt_structs *inter_domain_routing_db;
  struct bgp_misc_structs *bms;
  struct bgp_node *route = NULL, route_local;
  struct bgp_info *ri = NULL, ri_local;
  u_int32_t modulo = 0;

  if (!peer) return ERR;

  inter_domain_routing_db = bgp_select_routing_db(peer->type);
  bms = bgp_select_misc_db(peer->type);

  if (!inter_domain_routing_db || !bms) return ERR;

  if (!bms->skip_rib) {
    modulo = bms->route_info_modulo(peer, &attr_extra->path_id, bms->table_per_peer_buckets);

    /* Lookup node. */
    route = bgp_node_get(peer, inter_domain_routing_db->rib[afi][safi], p);

    /* Check previously received route. */
    for (ri = route->info[modulo]; ri; ri = ri->next) {
      if (ri->peer == peer) {
        if (safi == SAFI_MPLS_VPN) {
          if (ri->attr_extra && !memcmp(&ri->attr_extra->rd, &attr_extra->rd, sizeof(rd_t)));
          else continue;
        }

        if (peer->cap_add_paths[afi][safi]) {
          if (ri->attr_extra && (attr_extra->path_id == ri->attr_extra->path_id));
          else continue;
	}

        if (ri->bmed.id) {
          if (bms->bgp_extra_data_cmp && !(*bms->bgp_extra_data_cmp)(&bmd->extra, &ri->bmed));
          else continue;
        }

        break;
      }
    }
  }
  else {
    if (bms->msglog_backend_methods) {
      route = &route_local;
      memset(&route_local, 0, sizeof(struct bgp_node));
      memcpy(&route_local.p, p, sizeof(struct prefix));

      ri = &ri_local;
      memset(&ri_local, 0, sizeof(struct bgp_info));

      ri->peer = peer;
      bgp_attr_extra_process(peer, ri, afi, safi, attr_extra);
      if (bms->bgp_extra_data_process) (*bms->bgp_extra_data_process)(&bmd->extra, ri, idx, BGP_NLRI_WITHDRAW);
    }
  }

  if (ri && bms->msglog_backend_methods) {
    char event_type[] = "log";

    bgp_peer_log_msg(route, ri, afi, safi, event_type, bms->msglog_output, NULL, BGP_LOG_TYPE_WITHDRAW);
  }

  if (!bms->skip_rib) {
    /* Withdraw specified route from routing table. */
    if (ri) bgp_info_delete(peer, route, ri, modulo); 

    /* Unlock bgp_node_get() lock. */
    bgp_unlock_node(peer, route);
  }
  else {
    if (bms->msglog_backend_methods) {
      if (ri->attr_extra) bgp_attr_extra_free(peer, &ri->attr_extra);
      if (bms->bgp_extra_data_free) (*bms->bgp_extra_data_free)(&ri->bmed);
    }
  }

  return SUCCESS;
}

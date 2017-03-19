/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2017 by Paolo Lucente
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

/* defines */
#define __BGP_MSG_C

/* includes */
#include "pmacct.h"
#include "addr.h"
#include "bgp.h"

int bgp_parse_msg(struct bgp_peer *peer, time_t now, int online)
{
  struct bgp_misc_structs *bms;
  struct bgp_msg_data bmd;
  char tmp_packet[BGP_BUFFER_SIZE], *bgp_packet_ptr;
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
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] Received malformed BGP packet (incomplete header).\n",
		config.name, bms->log_str, bgp_peer_print(peer));
      return BGP_NOTIFY_HEADER_ERR;
    }

    /* BGP buffer segmentation + reassembly */
    if (peer->msglen < BGP_HEADER_SIZE || peer->msglen < (bgp_len = ntohs(bhdr->bgpo_len))) {
      memcpy(tmp_packet, bgp_packet_ptr, peer->msglen);
      memcpy(peer->buf.base, tmp_packet, peer->msglen);
      peer->buf.truncated_len = peer->msglen;

      break;
    }
    else peer->buf.truncated_len = 0;

    if (bgp_max_msglen_check(bgp_len) == ERR) {
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] Received malformed BGP packet (packet length check failed).\n",
		config.name, bms->log_str, bgp_peer_print(peer));
      return BGP_NOTIFY_HEADER_ERR;
    }

    if (bgp_marker_check(bhdr, BGP_MARKER_SIZE) == ERR) {
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] Received malformed BGP packet (marker check failed).\n",
		config.name, bms->log_str, bgp_peer_print(peer));
      return BGP_NOTIFY_HEADER_ERR;
    }

    switch (bhdr->bgpo_type) {
    case BGP_OPEN:
      ret = bgp_parse_open_msg(&bmd, bgp_packet_ptr, now, online);
      if (ret < 0) return BGP_NOTIFY_OPEN_ERR;

      break;
    case BGP_NOTIFICATION:
      {
	u_int8_t res_maj = 0, res_min = 0, shutdown_msglen = (BGP_NOTIFY_CEASE_SM_LEN + 1);
        char shutdown_msg[shutdown_msglen];

	memset(shutdown_msg, 0, shutdown_msglen);
        bgp_parse_notification_msg(&bmd, bgp_packet_ptr, &res_maj, &res_min, shutdown_msg, shutdown_msglen);

        Log(LOG_INFO, "INFO ( %s/%s ): [%s] BGP_NOTIFICATION received (%u, %u). Shutdown Message: '%s'\n",
	    config.name, bms->log_str, bgp_peer_print(peer), res_maj, res_min, shutdown_msg);

        return ERR;
      }
    case BGP_KEEPALIVE:
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): [%s] BGP_KEEPALIVE received\n", config.name, bms->log_str, bgp_peer_print(peer));
      if (peer->status >= OpenSent) {
        if (peer->status < Established) peer->status = Established;

	if (online) {
	  char bgp_reply_pkt[BGP_BUFFER_SIZE], *bgp_reply_pkt_ptr;

	  memset(bgp_reply_pkt, 0, BGP_BUFFER_SIZE);
          bgp_reply_pkt_ptr = bgp_reply_pkt;
          bgp_reply_pkt_ptr += bgp_write_keepalive_msg(bgp_reply_pkt_ptr);
          ret = send(peer->fd, bgp_reply_pkt, bgp_reply_pkt_ptr - bgp_reply_pkt, 0);
          peer->last_keepalive = now;

	  Log(LOG_DEBUG, "DEBUG ( %s/%s ): [%s] BGP_KEEPALIVE sent\n", config.name, bms->log_str, bgp_peer_print(peer));
	}
      }
      /* If we didn't pass through a successful BGP OPEN exchange just yet
         let's temporarily silently discard BGP KEEPALIVEs */
      break;
    case BGP_UPDATE:
      if (peer->status < Established) {
	Log(LOG_DEBUG, "DEBUG ( %s/%s ): [%s] BGP UPDATE received (no neighbor). Discarding.\n",
		config.name, bms->log_str, bgp_peer_print(peer));
	return BGP_NOTIFY_FSM_ERR;
      }

      ret = bgp_parse_update_msg(&bmd, bgp_packet_ptr);
      if (ret < 0) {
	Log(LOG_WARNING, "WARN ( %s/%s ): [%s] BGP UPDATE: malformed (%d).\n", config.name, bms->log_str, bgp_peer_print(peer), ret);
	return BGP_NOTIFY_UPDATE_ERR;
      }

      break;
    default:
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] Received malformed BGP packet (unsupported message type).\n",
	  config.name, bms->log_str, bgp_peer_print(peer));
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

      /* OPEN options parsing */
      if (bopen->bgpo_optlen && bopen->bgpo_optlen >= 2) {
	u_int8_t len, opt_type, opt_len, cap_type;
	char *ptr;

	ptr = bgp_packet_ptr + BGP_MIN_OPEN_MSG_SIZE;
	if (online) memset(bgp_open_cap_reply, 0, sizeof(bgp_open_cap_reply));

	for (len = bopen->bgpo_optlen; len > 0; len -= opt_len, ptr += opt_len) {
	  opt_type = (u_int8_t) ptr[0];
	  opt_len = (u_int8_t) ptr[1];

	  if (opt_len > bopen->bgpo_optlen) {
	    Log(LOG_INFO, "INFO ( %s/%s ): [%s] Received malformed BGP packet (option length).\n",
		config.name, bms->log_str, bgp_peer_print(peer));
	    return ERR;
	  } 

	  /* 
 	   * If we stumble upon capabilities let's curse through them to find
 	   * some we are forced to support (ie. MP-BGP or 4-bytes AS support)
 	   */
	  if (opt_type == BGP_OPTION_CAPABILITY) {
	    char *optcap_ptr;
	    int optcap_len;

	    bgp_open_cap_ptr = ptr;
	    ptr += 2;
	    len -= 2;
	    optcap_ptr = ptr;
	    optcap_len = len;

	    while (optcap_len > 0) {
	      u_int8_t cap_len = optcap_ptr[1];
	      u_int8_t cap_type = optcap_ptr[0];

	      if (cap_len > optcap_len) {
		Log(LOG_INFO, "INFO ( %s/%s ): [%s] Received malformed BGP packet (malformed capability: %x).\n",
			config.name, bms->log_str, bgp_peer_print(peer), cap_type);
		return ERR;
   	      }
				     
	      if (cap_type == BGP_CAPABILITY_MULTIPROTOCOL) {
	  	char *cap_ptr = optcap_ptr+2;
	  	struct capability_mp_data cap_data;

	  	memcpy(&cap_data, cap_ptr, sizeof(cap_data));
					  
		if (online)
	  	  Log(LOG_INFO, "INFO ( %s/%s ): [%s] Capability: MultiProtocol [%x] AFI [%x] SAFI [%x]\n",
			config.name, bms->log_str, bgp_peer_print(peer), cap_type, ntohs(cap_data.afi), cap_data.safi);
		peer->cap_mp = TRUE;

		if (online) {
		  memcpy(bgp_open_cap_reply_ptr, bgp_open_cap_ptr, opt_len+2); 
		  bgp_open_cap_reply_ptr += opt_len+2;
		}
	      }
	      else if (cap_type == BGP_CAPABILITY_4_OCTET_AS_NUMBER) {
		char *cap_ptr = optcap_ptr+2;
		u_int32_t as4_ptr;

	   	if (cap_len == CAPABILITY_CODE_AS4_LEN) {
		  struct capability_as4 cap_data;

		  memcpy(&cap_data, cap_ptr, sizeof(cap_data));

		  if (online)
		    Log(LOG_INFO, "INFO ( %s/%s ): [%s] Capability: 4-bytes AS [%x] ASN [%u]\n",
	    		config.name, bms->log_str, bgp_peer_print(peer), cap_type, ntohl(cap_data.as4));
		  memcpy(&as4_ptr, cap_ptr, 4);
		  remote_as4 = ntohl(as4_ptr);

		  if (online) {
		    memcpy(bgp_open_cap_reply_ptr, bgp_open_cap_ptr, opt_len+2); 
		    peer->cap_4as = bgp_open_cap_reply_ptr+4;
		    bgp_open_cap_reply_ptr += opt_len+2;
		  }
		  else peer->cap_4as = bgp_open_cap_ptr+4;
		}
		else {
		  Log(LOG_INFO, "INFO ( %s/%s ): [%s] Received malformed BGP packet (malformed AS4 option).\n",
			config.name, bms->log_str, bgp_peer_print(peer));
		  return ERR;
		}
	      }
	      else if (cap_type == BGP_CAPABILITY_ADD_PATHS) {
		char *cap_ptr = optcap_ptr+2;
		struct capability_add_paths cap_data;

		memcpy(&cap_data, cap_ptr, sizeof(cap_data));

		if (online)
		  Log(LOG_INFO, "INFO ( %s/%s ): [%s] Capability: ADD-PATHs [%x] AFI [%x] SAFI [%x] SEND_RECEIVE [%x]\n",
			config.name, bms->log_str, bgp_peer_print(peer), cap_type, ntohs(cap_data.afi), cap_data.safi,
			cap_data.sndrcv);

		if (cap_data.sndrcv == 2 /* send */) {
		  peer->cap_add_paths = TRUE; 
		  if (online) {
		    memcpy(bgp_open_cap_reply_ptr, bgp_open_cap_ptr, opt_len+2);
		    *(bgp_open_cap_reply_ptr+((opt_len+2)-1)) = 1; /* receive */
		    bgp_open_cap_reply_ptr += opt_len+2;
		  }
		}
	      }

	      optcap_ptr += cap_len+2;
	      optcap_len -= cap_len+2;
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
	  Log(LOG_INFO, "INFO ( %s/%s ): [%s] Received malformed BGP packet (invalid AS4 option).\n",
		config.name, bms->log_str, bgp_peer_print(peer));
	  return ERR;
	}
      }
      else {
	if (remote_as4 == 0 || remote_as4 == remote_as)
	  peer->as = remote_as;
 	/* It is not valid to not use the transitional ASN in the BGP OPEN and
	   present an ASN != remote_as in the 4AS capability */
	else {
	  Log(LOG_INFO, "INFO ( %s/%s ): [%s] Received malformed BGP packet (mismatching AS4 option).\n",
		config.name, bms->log_str, bgp_peer_print(peer));
	  return ERR;
	}
      }

      if (online) {
        bgp_reply_pkt_ptr = bgp_reply_pkt;

        /* Replying to OPEN message */
	if (!config.nfacctd_bgp_as) peer->myas = peer->as;
	else peer->myas = config.nfacctd_bgp_as;

        Log(LOG_INFO, "INFO ( %s/%s ): [%s] BGP_OPEN: Local AS: %u Remote AS: %u HoldTime: %u\n", config.name,
		bms->log_str, bgp_peer_print(peer), peer->myas, peer->as, peer->ht);

        ret = bgp_write_open_msg(bgp_reply_pkt_ptr, bgp_open_cap_reply, bgp_open_cap_reply_ptr-bgp_open_cap_reply, peer);
        if (ret > 0) bgp_reply_pkt_ptr += ret;
        else {
	  Log(LOG_INFO, "INFO ( %s/%s ): [%s] Local peer is 4AS while remote peer is 2AS: unsupported configuration.\n",
		config.name, bms->log_str, bgp_peer_print(peer));
	  return ERR;
        }

        /* sticking a KEEPALIVE to it */
        bgp_reply_pkt_ptr += bgp_write_keepalive_msg(bgp_reply_pkt_ptr);
        ret = send(peer->fd, bgp_reply_pkt, bgp_reply_pkt_ptr - bgp_reply_pkt, 0);
        peer->last_keepalive = now;
      }
    }
    else {
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] Received malformed BGP packet (unsupported version).\n",
		config.name, bms->log_str, bgp_peer_print(peer));
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

  bopen_reply->bgpo_optlen = cp_msglen;
  bopen_reply->bgpo_len = htons(BGP_MIN_OPEN_MSG_SIZE + bopen_reply->bgpo_optlen);

  if (config.nfacctd_bgp_ip) str_to_addr(config.nfacctd_bgp_ip, &bgp_ip);
  else memset(&bgp_ip, 0, sizeof(bgp_ip));

  if (config.nfacctd_bgp_id) str_to_addr(config.nfacctd_bgp_id, &bgp_id);
  else memset(&bgp_id, 0, sizeof(bgp_id));

  /* set BGP router-ID trial #1 */
  memset(&my_id_addr, 0, sizeof(my_id_addr));

  if (config.nfacctd_bgp_id && !is_any(&bgp_id) && !my_id_addr.family) {
    my_id = config.nfacctd_bgp_id;
    str_to_addr(my_id, &my_id_addr);
    if (my_id_addr.family != AF_INET) memset(&my_id_addr, 0, sizeof(my_id_addr));
  }

  /* set BGP router-ID trial #2 */
  if (config.nfacctd_bgp_ip && !is_any(&bgp_ip) && !my_id_addr.family) {
    my_id = config.nfacctd_bgp_ip;
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
  int ret = FALSE, shutdown_msglen;
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

    /* draft-ietf-idr-shutdown-04 */
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

int bgp_parse_notification_msg(struct bgp_msg_data *bmd, char *pkt, u_int8_t *res_maj, u_int8_t *res_min, char *shutdown_msg, u_int8_t shutdown_msglen)
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

  /* draft-ietf-idr-shutdown-04 */
  if (bn->bgpn_major == BGP_NOTIFY_CEASE &&
      (bn->bgpn_minor == BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN || bn->bgpn_minor == BGP_NOTIFY_CEASE_ADMIN_RESET)) {
    if (rem_len) {
      pkt_ptr = (pkt + BGP_MIN_NOTIFICATION_MSG_SIZE);
      bnsm = (struct bgp_notification_shutdown_msg *) pkt_ptr;

      if (bnsm->bgpnsm_len <= rem_len && bnsm->bgpnsm_len <= BGP_NOTIFY_CEASE_SM_LEN &&
	  bnsm->bgpnsm_len < shutdown_msglen) {
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
  struct bgp_peer *peer = bmd->peer;
  struct bgp_header bhdr;
  u_char *startp, *endp;
  struct bgp_attr attr;
  u_int16_t attribute_len;
  u_int16_t update_len;
  u_int16_t withdraw_len;
  u_int16_t end, tmp;
  struct bgp_nlri update;
  struct bgp_nlri withdraw;
  struct bgp_nlri mp_update;
  struct bgp_nlri mp_withdraw;
  int ret;

  if (!peer || !pkt) return ERR;

  /* Set initial values. */
  memset(&attr, 0, sizeof (struct bgp_attr));
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
    withdraw.nlri = pkt;
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
    ret = bgp_attr_parse(peer, &attr, pkt, attribute_len, &mp_update, &mp_withdraw);
    if (ret < 0) return ret;
    pkt += attribute_len;
  }

  update_len = end; end = 0;

  if (update_len > 0) {
    update.afi = AFI_IP;
    update.safi = SAFI_UNICAST;
    update.nlri = pkt;
    update.length = update_len;
  }

  /* NLRI parsing */
  if (withdraw.length) bgp_nlri_parse(bmd, NULL, &withdraw);
  if (update.length)  bgp_nlri_parse(bmd, &attr, &update);
	
  if (mp_update.length
	  && mp_update.afi == AFI_IP
	  && (mp_update.safi == SAFI_UNICAST || mp_update.safi == SAFI_MPLS_LABEL ||
	      mp_update.safi == SAFI_MPLS_VPN))
    bgp_nlri_parse(bmd, &attr, &mp_update);

  if (mp_withdraw.length
	  && mp_withdraw.afi == AFI_IP
	  && (mp_withdraw.safi == SAFI_UNICAST || mp_withdraw.safi == SAFI_MPLS_LABEL ||
	      mp_withdraw.safi == SAFI_MPLS_VPN))
    bgp_nlri_parse (bmd, NULL, &mp_withdraw);

#if defined ENABLE_IPV6
  if (mp_update.length
	  && mp_update.afi == AFI_IP6
	  && (mp_update.safi == SAFI_UNICAST || mp_update.safi == SAFI_MPLS_LABEL ||
	      mp_update.safi == SAFI_MPLS_VPN))
    bgp_nlri_parse(bmd, &attr, &mp_update);

  if (mp_withdraw.length
	  && mp_withdraw.afi == AFI_IP6
	  && (mp_withdraw.safi == SAFI_UNICAST || mp_withdraw.safi == SAFI_MPLS_LABEL ||
	      mp_withdraw.safi == SAFI_MPLS_VPN))
    bgp_nlri_parse(bmd, NULL, &mp_withdraw);
#endif

  /* Receipt of End-of-RIB can be processed here; being a silent
	 BGP receiver only, honestly it doesn't matter to us */

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
int bgp_attr_parse(struct bgp_peer *peer, struct bgp_attr *attr, char *ptr, int len, struct bgp_nlri *mp_update, struct bgp_nlri *mp_withdraw)
{
  int to_the_end = len, ret;
  u_int8_t flag, type, *tmp, mp_nlri = 0;
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
      mp_nlri = TRUE;
      break;
    case BGP_ATTR_MP_UNREACH_NLRI:
      ret = bgp_attr_parse_mp_unreach(peer, attr_len, attr, ptr, mp_withdraw);
      mp_nlri = TRUE;
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
  else attr->ecommunity = (struct ecommunity *) ecommunity_parse(peer, ptr, len);

  return SUCCESS;
}

int bgp_attr_parse_lcommunity(struct bgp_peer *peer, u_int16_t len, struct bgp_attr *attr, char *ptr, u_int8_t flag)
{
  if (len == 0) attr->lcommunity = NULL;
  else attr->lcommunity = (struct lcommunity *) lcommunity_parse(peer, ptr, len);

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
  ptr += 4;

  return SUCCESS;
}

/* Origin attribute. */
int bgp_attr_parse_origin(struct bgp_peer *peer, u_int16_t len, struct bgp_attr *attr, char *ptr, u_char flag)
{
  if (len != 1) return ERR;

  memcpy(&attr->local_pref, ptr, 1);
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
#if defined ENABLE_IPV6
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
#endif
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
  mp_update->nlri = ptr;
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
  mp_withdraw->nlri = ptr;
  mp_withdraw->length = withdraw_len;

  return SUCCESS;
}


/* BGP UPDATE NLRI parsing */
int bgp_nlri_parse(struct bgp_msg_data *bmd, void *attr, struct bgp_nlri *info)
{
  struct bgp_peer *peer = bmd->peer;
  u_char *pnt;
  u_char *lim;
  u_char safi, label[3];
  struct prefix p;
  int psize, end;
  int ret;
  u_int32_t tmp32;
  u_int16_t tmp16;
  struct rd_ip  *rdi;
  struct rd_as  *rda;
  struct rd_as4 *rda4;
  rd_t rd;
  path_id_t path_id;

  memset(&p, 0, sizeof(struct prefix));
  memset(&rd, 0, sizeof(rd_t));
  memset(&path_id, 0, sizeof(path_id_t));

  pnt = info->nlri;
  lim = pnt + info->length;
  end = info->length;
  safi = info->safi;

  for (; pnt < lim; pnt += psize) {

    /* handle path identifier */
    if (peer->cap_add_paths) {
      memcpy(&path_id, pnt, 4);
      path_id = ntohl(path_id);
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

      // XXX: check address correctnesss now that we have it?
    }
    else if (info->safi == SAFI_MPLS_LABEL) { /* rfc3107 labeled unicast */
      if ((info->afi == AFI_IP && p.prefixlen > 56) || (info->afi == AFI_IP6 && p.prefixlen > 152)) return ERR;

      psize = ((p.prefixlen+7)/8);
      if (psize > end) return ERR;

      /* Fetch label (3) and prefix from NLRI packet */
      memcpy(label, pnt, 3);
      memcpy(&p.u.prefix, pnt+3, (psize-3));
      p.prefixlen -= 24;
    }
    else if (info->safi == SAFI_MPLS_VPN) { /* rfc4364 BGP/MPLS IP Virtual Private Networks */
      if ((info->afi == AFI_IP && p.prefixlen > 120) || (info->afi == AFI_IP6 && p.prefixlen > 216)) return ERR;

      psize = ((p.prefixlen+7)/8);
      if (psize > end) return ERR;

      /* Fetch label (3), RD (8) and prefix from NLRI packet */
      memcpy(label, pnt, 3);

      memcpy(&rd.type, pnt+3, 2);
      rd.type = ntohs(rd.type);
      switch(rd.type) {
      case RD_TYPE_AS: 
	rda = (struct rd_as *) &rd;
	memcpy(&tmp16, pnt+5, 2);
	memcpy(&tmp32, pnt+7, 4);
	rda->as = ntohs(tmp16);
	rda->val = ntohl(tmp32);
	break;
      case RD_TYPE_IP: 
	rdi = (struct rd_ip *) &rd;
	memcpy(&rdi->ip.s_addr, pnt+5, 4);
	memcpy(&tmp16, pnt+9, 2);
	rdi->val = ntohs(tmp16);
	break;
      case RD_TYPE_AS4: 
	rda4 = (struct rd_as4 *) &rd;
	memcpy(&tmp32, pnt+5, 4);
	memcpy(&tmp16, pnt+9, 2);
	rda4->as = ntohl(tmp32);
	rda4->val = ntohs(tmp16);
	break;
      default:
	return ERR;
	break;
      }
    
      memcpy(&p.u.prefix, pnt+11, (psize-11));
      p.prefixlen -= 88;
    }

    /* Let's do our job now! */
    if (attr)
      ret = bgp_process_update(bmd, &p, attr, info->afi, safi, &rd, &path_id, label);
    else
      ret = bgp_process_withdraw(bmd, &p, attr, info->afi, safi, &rd, &path_id, label);
  }

  return SUCCESS;
}

int bgp_process_update(struct bgp_msg_data *bmd, struct prefix *p, void *attr, afi_t afi, safi_t safi,
		       rd_t *rd, path_id_t *path_id, char *label)
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
    modulo = bms->route_info_modulo(peer, path_id, bms->table_per_peer_buckets);
    route = bgp_node_get(peer, inter_domain_routing_db->rib[afi][safi], p);

    /* Check previously received route. */
    for (ri = route->info[modulo]; ri; ri = ri->next) {
      if (ri->peer == peer) { 
        if (safi == SAFI_MPLS_VPN) {
	  if (ri->extra && !memcmp(&ri->extra->rd, rd, sizeof(rd_t)));
	  else continue;
        }

        if (peer->cap_add_paths) {
	  if (path_id && *path_id) {
	    if (ri->extra && *path_id == ri->extra->path_id);
	    else continue;
	  }
	  else {
	    if (!ri->extra || (ri->extra && !ri->extra->path_id));
	    else continue;
	  }
        }

	if (ri->extra && ri->extra->bmed.id) {
	  if (bms->bgp_extra_data_cmp && !(*bms->bgp_extra_data_cmp)(&bmd->extra, &ri->extra->bmed));
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
        bgp_info_extra_process(peer, ri, safi, path_id, rd, label);
        if (bms->bgp_extra_data_process) (*bms->bgp_extra_data_process)(&bmd->extra, ri);

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
      bgp_info_extra_process(peer, new, safi, path_id, rd, label);
      if (bms->bgp_extra_data_process) (*bms->bgp_extra_data_process)(&bmd->extra, new);
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
      bgp_info_extra_process(peer, ri, safi, path_id, rd, label);
      if (bms->bgp_extra_data_process) (*bms->bgp_extra_data_process)(&bmd->extra, ri);

      goto log_update;
    }
  }

  return SUCCESS;

log_update:
  {
    char event_type[] = "log";

    bgp_peer_log_msg(route, ri, afi, safi, event_type, bms->msglog_output, BGP_LOG_TYPE_UPDATE);
  }

  if (bms->skip_rib) {
    if (ri->extra) bgp_info_extra_free(peer, &ri->extra);
    bgp_attr_unintern(peer, ri->attr);
  }

  return SUCCESS;
}

int bgp_process_withdraw(struct bgp_msg_data *bmd, struct prefix *p, void *attr, afi_t afi, safi_t safi,
			 rd_t *rd, path_id_t *path_id, char *label)
{
  struct bgp_peer *peer = bmd->peer;
  struct bgp_rt_structs *inter_domain_routing_db;
  struct bgp_misc_structs *bms;
  struct bgp_node *route = NULL, route_local;
  struct bgp_info *ri = NULL, ri_local;
  u_int32_t modulo;

  if (!peer) return ERR;

  inter_domain_routing_db = bgp_select_routing_db(peer->type);
  bms = bgp_select_misc_db(peer->type);

  if (!inter_domain_routing_db || !bms) return ERR;

  if (!bms->skip_rib) {
    modulo = bms->route_info_modulo(peer, path_id, bms->table_per_peer_buckets);

    /* Lookup node. */
    route = bgp_node_get(peer, inter_domain_routing_db->rib[afi][safi], p);

    /* Check previously received route. */
    for (ri = route->info[modulo]; ri; ri = ri->next) {
      if (ri->peer == peer) {
        if (safi == SAFI_MPLS_VPN) {
          if (ri->extra && !memcmp(&ri->extra->rd, rd, sizeof(rd_t)));
          else continue;
        }

        if (peer->cap_add_paths) {
          if (path_id && *path_id) {
            if (ri->extra && *path_id == ri->extra->path_id);
            else continue;
          }
          else {
            if (!ri->extra || (ri->extra && !ri->extra->path_id));
            else continue;
          }
        }

        if (ri->extra && ri->extra->bmed.id) {
          if (bms->bgp_extra_data_cmp && !(*bms->bgp_extra_data_cmp)(&bmd->extra, &ri->extra->bmed));
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
      bgp_info_extra_process(peer, ri, safi, path_id, rd, label);
      if (bms->bgp_extra_data_process) (*bms->bgp_extra_data_process)(&bmd->extra, ri);
    }
  }

  if (ri && bms->msglog_backend_methods) {
    char event_type[] = "log";

    bgp_peer_log_msg(route, ri, afi, safi, event_type, bms->msglog_output, BGP_LOG_TYPE_WITHDRAW);
  }

  if (!bms->skip_rib) {
    /* Withdraw specified route from routing table. */
    if (ri) bgp_info_delete(peer, route, ri, modulo); 

    /* Unlock bgp_node_get() lock. */
    bgp_unlock_node(peer, route);
  }
  else {
    if (bms->msglog_backend_methods) {
      if (ri->extra) bgp_info_extra_free(peer, &ri->extra);
    }
  }

  return SUCCESS;
}

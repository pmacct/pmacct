/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2018 by Paolo Lucente
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
#define __TELEMETRY_MSG_C

/* includes */
#include "pmacct.h"
#include "../bgp/bgp.h"
#include "telemetry.h"
#if defined WITH_RABBITMQ
#include "amqp_common.h"
#endif
#ifdef WITH_KAFKA
#include "kafka_common.h"
#endif
#if defined WITH_ZMQ
#include "zmq_common.h"
#endif

/* Functions */
void telemetry_process_data(telemetry_peer *peer, struct telemetry_data *t_data, int data_decoder)
{
  telemetry_misc_structs *tms;

  if (!peer || !t_data) return;

  tms = bgp_select_misc_db(peer->type);

  if (!tms) return;

  if (tms->msglog_backend_methods) {
    char event_type[] = "log";

    if (!telemetry_validate_input_output_decoders(data_decoder, config.telemetry_msglog_output)) {
      telemetry_log_msg(peer, t_data, peer->buf.base, peer->msglen, data_decoder,
			telemetry_log_seq_get(&tms->log_seq), event_type,
			config.telemetry_msglog_output);
    }
  }

  if (tms->dump_backend_methods) { 
    if (!telemetry_validate_input_output_decoders(data_decoder, config.telemetry_dump_output)) {
      telemetry_dump_se_ll_append(peer, t_data, data_decoder);
    }
  }

  if (tms->msglog_backend_methods || tms->dump_backend_methods)
    telemetry_log_seq_increment(&tms->log_seq);
}

#if defined WITH_ZMQ
int telemetry_recv_zmq_generic(telemetry_peer *peer, u_int32_t len)
{
  int ret = 0;

  ret = p_zmq_recv_bin(&telemetry_zmq_host.sock, peer->buf.base, peer->buf.len);

  if (ret > 0) {
    peer->stats.packet_bytes += ret;
    peer->msglen = ret;
  }

  return ret;
}
#endif

int telemetry_recv_generic(telemetry_peer *peer, u_int32_t len)
{
  int ret = 0;
  sigset_t mask, oldmask;

  sigemptyset(&mask);
  sigemptyset(&oldmask);

  /* Block SIGCHLD so it doesn't kick us out of recv. */
  sigaddset(&mask, SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &mask, &oldmask) < 0) {
      return ret;
  }

  if (!len) {
    ret = recv(peer->fd, &peer->buf.base[peer->buf.truncated_len], (peer->buf.len - peer->buf.truncated_len), 0);
  }
  else {
    if (len <= (peer->buf.len - peer->buf.truncated_len)) { 
      ret = recv(peer->fd, &peer->buf.base[peer->buf.truncated_len], len, MSG_WAITALL);
    }
  }
  if (ret > 0) {
    peer->stats.packet_bytes += ret;
    peer->msglen = (ret + peer->buf.truncated_len);
  }

  /* Restore the original procmask. */
  sigprocmask(SIG_SETMASK, &oldmask, NULL);

  return ret;
}

void telemetry_basic_process_json(telemetry_peer *peer)
{
  int idx;

  for (idx = 0; idx < peer->msglen; idx++) {
    if (!isprint(peer->buf.base[idx])) peer->buf.base[idx] = '\0';
  }

  if (peer->buf.len >= (peer->msglen + 1)) {
    peer->buf.base[peer->msglen] = '\0';
    peer->msglen++;
  }
}

int telemetry_recv_json(telemetry_peer *peer, u_int32_t len, int *flags)
{
  int ret = 0;
  if (!flags) return ret;

  (*flags) = FALSE;

  if (!config.telemetry_zmq_address) ret = telemetry_recv_generic(peer, len);
#if defined WITH_ZMQ
  else ret = telemetry_recv_zmq_generic(peer, len);
#endif

  telemetry_basic_process_json(peer);

  if (ret) (*flags) = telemetry_basic_validate_json(peer);

  return ret;
}

int telemetry_recv_zjson(telemetry_peer *peer, telemetry_peer_z *peer_z, u_int32_t len, int *flags)
{
  int ret = 0;

#if defined (HAVE_ZLIB)
  if (!flags) return ret;
  (*flags) = FALSE;

  ret = telemetry_recv_generic(peer, len);


  if (ret > 0) { 
    int zret;

    memset(peer_z->inflate_buf, 0, sizeof(peer_z->inflate_buf));
    peer_z->stm.avail_out = (uInt) sizeof(peer_z->inflate_buf);
    peer_z->stm.next_out = (Bytef *) peer_z->inflate_buf;

    peer_z->stm.avail_in = (uInt) peer->msglen;
    peer_z->stm.next_in = (Bytef *) peer->buf.base;

    ret = FALSE;
    zret = inflate(&peer_z->stm, Z_NO_FLUSH);
    if (zret == Z_OK || zret == Z_STREAM_END) {
      strlcpy(peer->buf.base, peer_z->inflate_buf, peer->buf.len);
      peer->msglen = strlen(peer->buf.base) + 1;
      ret = peer->msglen;

      (*flags) = telemetry_basic_validate_json(peer);
      if (zret == Z_STREAM_END) {
        inflateReset(&peer_z->stm);
      }
    }
  }
#endif

  return ret;
}

int telemetry_recv_cisco_json(telemetry_peer *peer, int *flags)
{
  int ret = 0;
  u_int32_t len;

  ret = telemetry_recv_generic(peer, TELEMETRY_CISCO_HDR_LEN);
  if (ret <= 0) return ret;
  
  if (ret == TELEMETRY_CISCO_HDR_LEN) {
    len = telemetry_cisco_hdr_get_len(peer);
    ret = telemetry_recv_json(peer, len, flags);
  }
  
  return ret;
}

int telemetry_recv_cisco_zjson(telemetry_peer *peer, telemetry_peer_z *peer_z, int *flags)
{
  int ret = 0;
  u_int32_t len;
  if (!flags) return FALSE;
  *flags = FALSE;

  ret = telemetry_recv_generic(peer, TELEMETRY_CISCO_HDR_LEN);
  if (ret == TELEMETRY_CISCO_HDR_LEN) {
    len = telemetry_cisco_hdr_get_len(peer); 
    ret = telemetry_recv_zjson(peer, peer_z, len, flags); 
  }

  return ret;
}

int telemetry_recv_cisco(telemetry_peer *peer, int *flags, int *data_decoder)
{
  int ret = 0;
  u_int32_t type, len;

  if (!flags || !data_decoder) return ret;
  *flags = FALSE;
  *data_decoder = TELEMETRY_DATA_DECODER_UNKNOWN;

  ret = telemetry_recv_generic(peer, TELEMETRY_CISCO_HDR_LEN);
  if (ret == TELEMETRY_CISCO_HDR_LEN) {
    type = telemetry_cisco_hdr_get_type(peer);
    len = telemetry_cisco_hdr_get_len(peer);

    switch (type) {
    case TELEMETRY_CISCO_RESET_COMPRESSOR:
      ret = telemetry_recv_jump(peer, len, flags);
      (*data_decoder) = TELEMETRY_DATA_DECODER_UNKNOWN; /* XXX: JSON instead? */
      break;
    case TELEMETRY_CISCO_JSON:
      ret = telemetry_recv_json(peer, len, flags);
      (*data_decoder) = TELEMETRY_DATA_DECODER_JSON;
      break;
    case TELEMETRY_CISCO_GPB_COMPACT:
      ret = telemetry_recv_generic(peer, len);
      (*data_decoder) = TELEMETRY_DATA_DECODER_GPB;
      break;
    case TELEMETRY_CISCO_GPB_KV:
      ret = telemetry_recv_generic(peer, len);
      (*data_decoder) = TELEMETRY_DATA_DECODER_GPB;
      break;
    }
  }

  return ret;
}

int telemetry_recv_jump(telemetry_peer *peer, u_int32_t len, int *flags)
{
  int ret = 0;
  if (!flags) return ret;

  ret = telemetry_recv_generic(peer, len);

  (*flags) = ERR;

  return ret;
}

int telemetry_recv_cisco_gpb(telemetry_peer *peer)
{
  int ret = 0;
  u_int32_t len;

  if (!peer) return ret;

  ret = telemetry_recv_generic(peer, TELEMETRY_CISCO_HDR_LEN);
  if (ret == TELEMETRY_CISCO_HDR_LEN) {
    len = telemetry_cisco_hdr_get_len(peer);
    ret = telemetry_recv_generic(peer, len);
  }

  return ret;
}

int telemetry_recv_cisco_gpb_kv(telemetry_peer *peer, int *flags)
{
  int ret = 0;
  u_int32_t len;

  ret = telemetry_recv_generic(peer, TELEMETRY_CISCO_HDR_LEN);
  if (ret == TELEMETRY_CISCO_HDR_LEN) {
    len = telemetry_cisco_hdr_get_len(peer);
    ret = telemetry_recv_generic(peer, len);
  }

  return ret;
}

int telemetry_basic_validate_json(telemetry_peer *peer)
{
  if (peer->buf.base[peer->buf.truncated_len] != '{') {
    peer->stats.msg_errors++;
    return ERR;
  }
  else
    return FALSE;
}

#if defined (WITH_ZMQ)
#if defined (WITH_JANSSON)
int telemetry_decode_zmq_peer(struct telemetry_data *t_data, void *zh, char *buf, int buflen, struct sockaddr *addr, socklen_t *addr_len)
{
  json_t *json_obj, *telemetry_node_json, *telemetry_node_port_json;
  json_error_t json_err;
  struct p_zmq_host *zmq_host = zh;
  struct host_addr telemetry_node;
  u_int16_t telemetry_node_port;
  int bytes, ret = SUCCESS;

  if (!zmq_host || !buf || !buflen || !addr || !addr_len) return ERR;

  bytes = p_zmq_recv_bin(&zmq_host->sock, buf, buflen);
  if (bytes > 0) {
    buf[bytes] = '\0';
    json_obj = json_loads(buf, 0, &json_err);
  }

  if (json_obj) {
    if (!json_is_object(json_obj)) {
      Log(LOG_WARNING, "WARN ( %s/%s ): telemetry_decode_zmq_peer(): json_is_object() failed.\n", config.name, t_data->log_str);
      ret = ERR;
      goto exit_lane;
    }
    else {
      telemetry_node_json = json_object_get(json_obj, "telemetry_node");
      if (telemetry_node_json == NULL) {
	Log(LOG_WARNING, "WARN ( %s/%s ): telemetry_decode_zmq_peer(): no 'telemetry_node' element.\n", config.name, t_data->log_str);
	ret = ERR;
	goto exit_lane;
      }
      else {
	const char *telemetry_node_str;

	telemetry_node_str = json_string_value(telemetry_node_json);
	str_to_addr(telemetry_node_str, &telemetry_node);
	json_decref(telemetry_node_json);
      }

      telemetry_node_port_json = json_object_get(json_obj, "telemetry_node_port");
      if (telemetry_node_port_json == NULL) {
	Log(LOG_WARNING, "WARN ( %s/%s ): telemetry_decode_zmq_peer(): no 'telemetry_node_port' element.\n", config.name, t_data->log_str);
	ret = ERR;
	goto exit_lane;
      }
      else {
	telemetry_node_port = json_integer_value(telemetry_node_port_json);
	json_decref(telemetry_node_port_json);
      }

      (*addr_len) = addr_to_sa(addr, &telemetry_node, telemetry_node_port);
    }

    exit_lane:
    json_decref(json_obj);
  }
  else {
    Log(LOG_WARNING, "WARN ( %s/%s ): telemetry_decode_zmq_peer(): invalid telemetry node JSON received: %s.\n", config.name, t_data->log_str, json_err.text);
    ret = ERR;
  }

  return ret;
}
#else
int telemetry_decode_zmq_peer(struct telemetry_data *t_data, void *zh, char *buf, int buflen, struct sockaddr *addr, socklen_t *addr_len)
{
  Log(LOG_ERR, "ERROR ( %s/%s ): telemetry_decode_zmq_peer() requires --enable-zmq. Terminating.\n", config.name, t_data->log_str);
  exit_all(1);
}
#endif
#endif

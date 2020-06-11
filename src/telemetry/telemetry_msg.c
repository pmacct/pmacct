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

/* includes */
#include "pmacct.h"
#include "addr.h"
#include "bgp/bgp.h"
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

  ret = p_zmq_recv_bin(&telemetry_zmq_host.sock, peer->buf.base, peer->buf.tot_len);

  if (ret > 0) {
    peer->stats.packet_bytes += ret;
    peer->msglen = ret;
  }

  return ret;
}
#endif

#if defined WITH_KAFKA
int telemetry_recv_kafka_generic(telemetry_peer *peer, u_int32_t len)
{
  int ret = 0;

  ret = p_kafka_consume_data(&telemetry_kafka_host, peer->buf.kafka_msg, (u_char *)peer->buf.base, peer->buf.tot_len);

  if (ret > 0) {
    peer->stats.packet_bytes += ret;
    peer->msglen = ret;
  }

  peer->buf.kafka_msg = NULL;

  return ret;
}
#endif

int telemetry_recv_generic(telemetry_peer *peer, u_int32_t len)
{
  int ret = 0;

  if (!len) {
    ret = recv(peer->fd, &peer->buf.base[peer->buf.cur_len], (peer->buf.tot_len - peer->buf.cur_len), 0);
  }
  else {
    if (len <= (peer->buf.tot_len - peer->buf.cur_len)) { 
      ret = pm_recv(peer->fd, &peer->buf.base[peer->buf.cur_len], len, MSG_WAITALL, DEFAULT_SLOTH_SLEEP_TIME);
    }
  }
  if (ret > 0) {
    peer->stats.packet_bytes += ret;
    peer->msglen = (ret + peer->buf.cur_len);
  }

  return ret;
}

void telemetry_basic_process_json(telemetry_peer *peer)
{
  if (config.telemetry_decoder_id == TELEMETRY_DECODER_CISCO_V0 && config.telemetry_port_udp) {
    peer->msglen -= TELEMETRY_CISCO_HDR_LEN_V0;
    memmove(peer->buf.base, &peer->buf.base[TELEMETRY_CISCO_HDR_LEN_V0], peer->msglen);
  }
  else if (config.telemetry_decoder_id == TELEMETRY_DECODER_CISCO_V1 && config.telemetry_port_udp) {
    peer->msglen -= TELEMETRY_CISCO_HDR_LEN_V1;
    memmove(peer->buf.base, &peer->buf.base[TELEMETRY_CISCO_HDR_LEN_V1], peer->msglen);
  }

  peer->buf.base[peer->msglen] = '\0';
}

int telemetry_recv_json(telemetry_peer *peer, u_int32_t len, int *flags)
{
  int ret = 0;
  if (!flags) return ret;

  (*flags) = FALSE;

  if (!zmq_input && !kafka_input) {
    ret = telemetry_recv_generic(peer, len);
  }
#if defined WITH_ZMQ
  else if (zmq_input) {
    ret = telemetry_recv_zmq_generic(peer, len);
  }
#endif
#if defined WITH_KAFKA
  else if (kafka_input) {
    ret = telemetry_recv_kafka_generic(peer, len);
  }
#endif

  telemetry_basic_process_json(peer);

  if (ret) (*flags) = telemetry_basic_validate_json(peer);

  return ret;
}

int telemetry_recv_gpb(telemetry_peer *peer, u_int32_t len)
{
  int ret = 0;

  ret = telemetry_recv_generic(peer, len);

  return ret;
}

int telemetry_recv_cisco_v0(telemetry_peer *peer, int *flags, int *data_decoder)
{
  int ret = 0;
  u_int32_t type, len;

  if (!flags || !data_decoder) return ret;
  *flags = FALSE;
  *data_decoder = TELEMETRY_DATA_DECODER_UNKNOWN;

  ret = telemetry_recv_generic(peer, TELEMETRY_CISCO_HDR_LEN_V0);
  if (ret == TELEMETRY_CISCO_HDR_LEN_V0) {
    type = telemetry_cisco_hdr_v0_get_type(peer);
    len = telemetry_cisco_hdr_v0_get_len(peer);

    /* MSG_WAITALL does not apply to UDP */
    if (config.telemetry_port_udp) len = 0;

    ret = telemetry_recv_cisco(peer, flags, data_decoder, type, len);
  }

  return ret;
}

int telemetry_recv_cisco_v1(telemetry_peer *peer, int *flags, int *data_decoder)
{
  int ret = 0;
  u_int32_t type, len, encap;

  if (!flags || !data_decoder) return ret;
  *flags = FALSE;
  *data_decoder = TELEMETRY_DATA_DECODER_UNKNOWN;

  ret = telemetry_recv_generic(peer, TELEMETRY_CISCO_HDR_LEN_V1);
  if (ret == TELEMETRY_CISCO_HDR_LEN_V1) {
    type = telemetry_cisco_hdr_v1_get_type(peer);
    len = telemetry_cisco_hdr_v1_get_len(peer);
    encap = telemetry_cisco_hdr_v1_get_encap(peer);

    /* MSG_WAITALL does not apply to UDP */
    if (config.telemetry_port_udp) len = 0;

    if (type == TELEMETRY_CISCO_V1_TYPE_DATA) {
      switch (encap) {
      case TELEMETRY_CISCO_V1_ENCAP_GPB:
      case TELEMETRY_CISCO_V1_ENCAP_GPV_CPT:
	encap = TELEMETRY_CISCO_GPB_COMPACT;
	break;
      case TELEMETRY_CISCO_V1_ENCAP_GPB_KV:
	encap = TELEMETRY_CISCO_GPB_KV;
	break;
      case TELEMETRY_CISCO_V1_ENCAP_JSON:
	encap = TELEMETRY_CISCO_JSON;
	break;
      default:
	return ret;
      }

      ret = telemetry_recv_cisco(peer, flags, data_decoder, encap, len);
    }
  }

  return ret;
}

int telemetry_recv_cisco(telemetry_peer *peer, int *flags, int *data_decoder, u_int32_t type, u_int32_t len)
{
  int ret = 0;

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
  default:
    ret = telemetry_recv_jump(peer, len, flags);
    (*data_decoder) = TELEMETRY_DATA_DECODER_UNKNOWN;
    break;
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

int telemetry_basic_validate_json(telemetry_peer *peer)
{
  if (peer->buf.base[peer->buf.cur_len] != '{') {
    peer->stats.msg_errors++;
    return ERR;
  }
  else
    return FALSE;
}

#if defined (WITH_JANSSON)
int telemetry_decode_producer_peer(struct telemetry_data *t_data, void *h, u_char *buf, size_t buflen, struct sockaddr *addr, socklen_t *addr_len)
{
  json_t *json_obj = NULL, *telemetry_node_json, *telemetry_node_port_json;
  json_error_t json_err;
  struct host_addr telemetry_node;
  u_int16_t telemetry_node_port = 0;
  int bytes = 0, ret = SUCCESS;

  if (!buf || !buflen || !addr || !addr_len) return ERR;

#if defined WITH_ZMQ
  if (zmq_input) {
    struct p_zmq_host *zmq_host = h;

    bytes = p_zmq_recv_bin(&zmq_host->sock, buf, buflen);
  }
#endif
#if defined WITH_KAFKA
  else if (kafka_input) {
    struct p_kafka_host *kafka_host = h;

    bytes = p_kafka_consume_data(kafka_host, t_data->kafka_msg, buf, buflen);
  }
#endif

  if (bytes > 0) {
    buf[bytes] = '\0';
    json_obj = json_loads((char *)buf, 0, &json_err);

    if (json_obj) {
      if (!json_is_object(json_obj)) {
	Log(LOG_WARNING, "WARN ( %s/%s ): telemetry_decode_producer_peer(): json_is_object() failed.\n", config.name, t_data->log_str);
	ret = ERR;
	goto exit_lane;
      }
      else {
	/* v1 */
	telemetry_node_json = json_object_get(json_obj, "telemetry_node");

	/* v2, v3 */
	if (!telemetry_node_json) {
	  json_t *collector_json = NULL, *grpc_json = NULL;

	  collector_json = json_object_get(json_obj, "collector");
	  if (collector_json) grpc_json = json_object_get(collector_json, "grpc");
	  if (grpc_json) telemetry_node_json = json_object_get(grpc_json, "grpcPeer");
	}

	if (!telemetry_node_json) {
	  Log(LOG_WARNING, "WARN ( %s/%s ): telemetry_decode_producer_peer(): no 'telemetry_node' element.\n", config.name, t_data->log_str);
	  ret = ERR;
	  goto exit_lane;
	}
	else {
	  const char *telemetry_node_str;

	  telemetry_node_str = json_string_value(telemetry_node_json);
	  str_to_addr(telemetry_node_str, &telemetry_node);
	}

	telemetry_node_port_json = json_object_get(json_obj, "telemetry_node_port");
	if (telemetry_node_port_json) telemetry_node_port = json_integer_value(telemetry_node_port_json);

	(*addr_len) = addr_to_sa(addr, &telemetry_node, telemetry_node_port);
      }

      exit_lane:
      json_decref(json_obj);
    }
    else {
      Log(LOG_WARNING, "WARN ( %s/%s ): telemetry_decode_producer_peer(): invalid telemetry node JSON received: %s.\n", config.name, t_data->log_str, json_err.text);
      if (config.debug) Log(LOG_DEBUG, "DEBUG ( %s/%s ): %s\n", config.name, t_data->log_str, buf);
      ret = ERR;
    }
  }
  else {
    ret = ERR;
  }

  return ret;
}
#else
int telemetry_decode_producer_peer(struct telemetry_data *t_data, void *h, u_char *buf, size_t buflen, struct sockaddr *addr, socklen_t *addr_len)
{
  Log(LOG_ERR, "ERROR ( %s/%s ): telemetry_decode_producer_peer() requires --enable-jansson. Terminating.\n", config.name, t_data->log_str);
  exit_gracefully(1);

  return 0;
}
#endif

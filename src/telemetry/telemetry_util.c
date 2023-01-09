/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2023 by Paolo Lucente
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
#include "bgp/bgp.h"
#include "telemetry.h"
#if defined WITH_RABBITMQ
#include "amqp_common.h"
#endif
#ifdef WITH_KAFKA
#include "kafka_common.h"
#endif

/* Functions */
int telemetry_peer_init(telemetry_peer *peer, int type)
{
  return bgp_peer_init(peer, type);
}

void telemetry_peer_close(telemetry_peer *peer, int type)
{
  telemetry_dump_se_ll *tdsell;
  telemetry_misc_structs *tms;

  if (!peer) return;

  tms = bgp_select_misc_db(peer->type);

  if (!tms) return;
 
  if (tms->dump_file || tms->dump_amqp_routing_key || tms->dump_kafka_topic) {
    tdsell = (telemetry_dump_se_ll *) peer->bmp_se;

    if (tdsell && tdsell->start) telemetry_dump_se_ll_destroy(tdsell);

    free(peer->bmp_se);
    peer->bmp_se = NULL;
  }

  if (config.telemetry_port_udp) {
    telemetry_peer_cache tpc;

    memcpy(&tpc.addr, &peer->addr, sizeof(struct host_addr));
    pm_tdelete(&tpc, &telemetry_peers_cache, telemetry_tpc_addr_cmp);

    peer->fd = ERR; /* dirty trick to prevent close() a valid fd in bgp_peer_close() */
  }

  bgp_peer_close(peer, type, FALSE, FALSE, FALSE, FALSE, NULL);
}

u_int32_t telemetry_cisco_hdr_v0_get_len(telemetry_peer *peer)
{
  u_int32_t len;

  memcpy(&len, (peer->buf.base + 8), 4);
  len = ntohl(len);

  return len;
}

u_int32_t telemetry_cisco_hdr_v0_get_type(telemetry_peer *peer)
{
  u_int32_t type;

  memcpy(&type, peer->buf.base, 4);
  type = ntohl(type);

  return type;
}

u_int32_t telemetry_cisco_hdr_v1_get_len(telemetry_peer *peer)
{
  u_int32_t len;

  memcpy(&len, (peer->buf.base + 8), 4);
  len = ntohl(len);

  return len;
}

u_int16_t telemetry_cisco_hdr_v1_get_type(telemetry_peer *peer)
{
  u_int16_t type;

  memcpy(&type, peer->buf.base, 2);
  type = ntohs(type);

  return type;
}

u_int16_t telemetry_cisco_hdr_v1_get_encap(telemetry_peer *peer)
{
  u_int16_t encap;

  memcpy(&encap, (peer->buf.base + 2), 2);
  encap = ntohs(encap);

  return encap;
}

int telemetry_tpc_addr_cmp(const void *a, const void *b)
{
  return host_addr_cmp(&((telemetry_peer_cache *)a)->addr, &((telemetry_peer_cache *)b)->addr);
}

void telemetry_link_misc_structs(telemetry_misc_structs *tms)
{
#if defined WITH_RABBITMQ
  tms->msglog_amqp_host = &telemetry_daemon_msglog_amqp_host;
#endif
#if defined WITH_KAFKA
  tms->msglog_kafka_host = &telemetry_daemon_msglog_kafka_host;
#endif
  tms->max_peers = config.telemetry_max_peers;
  tms->peers = telemetry_peers;
  tms->peers_cache = NULL;
  tms->peers_port_cache = NULL;
  tms->xconnects = NULL;
  tms->dump_file = config.telemetry_dump_file;
  tms->dump_amqp_routing_key = config.telemetry_dump_amqp_routing_key;
  tms->dump_amqp_routing_key_rr = config.telemetry_dump_amqp_routing_key_rr;
  tms->dump_kafka_topic = config.telemetry_dump_kafka_topic;
  tms->dump_kafka_topic_rr = config.telemetry_dump_kafka_topic_rr;
  tms->dump_kafka_partition_key = config.telemetry_dump_kafka_partition_key;
  tms->msglog_file = config.telemetry_msglog_file;
  tms->msglog_output = config.telemetry_msglog_output;
  tms->msglog_amqp_routing_key = config.telemetry_msglog_amqp_routing_key;
  tms->msglog_amqp_routing_key_rr = config.telemetry_msglog_amqp_routing_key_rr;
  tms->msglog_kafka_topic = config.telemetry_msglog_kafka_topic;
  tms->msglog_kafka_topic_rr = config.telemetry_msglog_kafka_topic_rr;
  tms->msglog_kafka_partition_key = config.telemetry_msglog_kafka_partition_key;
  tms->peer_str = malloc(strlen("telemetry_node") + 1);
  strcpy(tms->peer_str, "telemetry_node");
  tms->peer_port_str = malloc(strlen("telemetry_node_port") + 1);
  strcpy(tms->peer_port_str, "telemetry_node_port");

  tms->tag = &telemetry_logdump_tag;
  tms->tag_map = config.telemetry_tag_map;
}

int telemetry_validate_input_output_decoders(int input, int output)
{
  if (input == TELEMETRY_DATA_DECODER_GPB) {
    if (output == PRINT_OUTPUT_JSON) return FALSE;
    /* else if (output == PRINT_OUTPUT_GPB) return FALSE; */
  }
  else if (input == TELEMETRY_DATA_DECODER_JSON) {
    if (output == PRINT_OUTPUT_JSON) return FALSE;
    /* else if (output == PRINT_OUTPUT_GPB) return ERR; */
  }
  else if (input == TELEMETRY_DATA_DECODER_UNKNOWN) {
    if (output == PRINT_OUTPUT_JSON) return FALSE;
  }
  else if (input == TELEMETRY_DATA_DECODER_JSON_STRING) {
    if (output == PRINT_OUTPUT_JSON) return FALSE;
  }

  return ERR;
}

void telemetry_log_peer_stats(telemetry_peer *peer, struct telemetry_data *t_data)
{
  Log(LOG_INFO, "INFO ( %s/%s ): [%s:%u] pkts=%llu pktBytes=%llu msgBytes=%llu msgErrors=%llu\n",
	config.name, t_data->log_str, peer->addr_str, peer->tcp_port,
	(unsigned long long)peer->stats.packets, (unsigned long long)peer->stats.packet_bytes,
	(unsigned long long)peer->stats.msg_bytes, (unsigned long long)peer->stats.msg_errors);

  t_data->global_stats.packets += peer->stats.packets;
  t_data->global_stats.packet_bytes += peer->stats.packet_bytes;
  t_data->global_stats.msg_bytes += peer->stats.msg_bytes;
  t_data->global_stats.msg_errors += peer->stats.msg_errors;

  peer->stats.packets = 0;
  peer->stats.packet_bytes = 0;
  peer->stats.msg_bytes = 0;
  peer->stats.msg_errors = 0;
}

void telemetry_log_global_stats(struct telemetry_data *t_data)
{
  Log(LOG_INFO, "INFO ( %s/%s ): [Total] pkts=%llu pktBytes=%llu msgBytes=%llu msgErrors=%llu\n",
        config.name, t_data->log_str, (unsigned long long)t_data->global_stats.packets,
	(unsigned long long)t_data->global_stats.packet_bytes, (unsigned long long)t_data->global_stats.msg_bytes,
	(unsigned long long)t_data->global_stats.msg_errors);

  t_data->global_stats.packets = 0;
  t_data->global_stats.packet_bytes = 0;
  t_data->global_stats.msg_bytes = 0;
  t_data->global_stats.msg_errors = 0;
}

#ifdef WITH_KAFKA
void telemetry_init_kafka_host(void *kh)
{
  struct p_kafka_host *kafka_host = kh;

  p_kafka_init_host(kafka_host, config.telemetry_kafka_config_file);
  p_kafka_connect_to_consume(kafka_host);
  p_kafka_set_broker(kafka_host, config.telemetry_kafka_broker_host, config.telemetry_kafka_broker_port);
  p_kafka_set_topic(kafka_host, config.telemetry_kafka_topic);
  p_kafka_set_content_type(kafka_host, PM_KAFKA_CNT_TYPE_STR);
  p_kafka_manage_consumer(kafka_host, TRUE);
}
#endif

#ifdef WITH_UNYTE_UDP_NOTIF
int create_socket_unyte_udp_notif(struct telemetry_data *t_data, char *address, char *port)
{
  uint64_t receive_buf_size;
  struct addrinfo *addr_info;
  struct addrinfo hints;
  int rc;

  memset(&hints, 0, sizeof(hints));

  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;

  /* Using getaddrinfo to support both IPv4 and IPv6 */
  rc = getaddrinfo(address, port, &hints, &addr_info);

  if (rc != 0) {
    Log(LOG_ERR, "ERROR ( %s/%s ): create_socket_unyte_udp_notif(): getaddrinfo error: %s\n", config.name, t_data->log_str, gai_strerror(rc));
    exit_gracefully(1);
  }

  Log(LOG_INFO, "INFO ( %s/%s ): create_socket_unyte_udp_notif(): family=%s port=%d\n",
      config.name, t_data->log_str, (addr_info->ai_family == AF_INET) ? "IPv4" : "IPv6",
      ntohs(((struct sockaddr_in *)addr_info->ai_addr)->sin_port));

  /* create socket on UDP protocol */
  int sockfd = socket(addr_info->ai_family, addr_info->ai_socktype, addr_info->ai_protocol);

  /* handle error */
  if (sockfd < 0) {
    Log(LOG_ERR, "ERROR ( %s/%s ): create_socket_unyte_udp_notif(): cannot create socket\n", config.name, t_data->log_str);
    exit_gracefully(1);
  }

  /* Use SO_REUSEPORT to be able to launch multiple collector on the same address */
#if (defined HAVE_SO_REUSEPORT)
  int optval = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(int)) < 0) {
    Log(LOG_ERR, "ERROR ( %s/%s ): create_socket_unyte_udp_notif(): cannot set SO_REUSEPORT option on socket\n", config.name, t_data->log_str);
    exit_gracefully(1);
  }
#endif

#if (defined HAVE_SO_BINDTODEVICE)
  if (config.telemetry_udp_notif_interface)  {
    rc = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, config.telemetry_udp_notif_interface, (socklen_t) strlen(config.telemetry_udp_notif_interface));
    if (rc < 0) Log(LOG_ERR, "WARN ( %s/%s ): setsockopt() failed for SO_BINDTODEVICE (errno: %d).\n", config.name, t_data->log_str, errno);
  }
#endif

  if (config.telemetry_udp_notif_ipv6_only) {
    int yes=1;

    rc = setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &yes, (socklen_t) sizeof(yes));
    if (rc < 0) Log(LOG_ERR, "WARN ( %s/%s ): setsockopt() failed for IPV6_V6ONLY (errno: %d).\n", config.name, t_data->log_str, errno);
  }

  /* Setting socket buffer to default 20 MB */
  if (!config.telemetry_pipe_size) {
    receive_buf_size = DEFAULT_SK_BUFF_SIZE;
  }
  else {
    receive_buf_size = config.telemetry_pipe_size;
  }

  if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &receive_buf_size, sizeof(receive_buf_size)) < 0) {
    Log(LOG_ERR, "ERROR ( %s/%s ): create_socket_unyte_udp_notif(): cannot set buffer size\n", config.name, t_data->log_str);
    exit_gracefully(1);
  }

  if (bind(sockfd, addr_info->ai_addr, (int)addr_info->ai_addrlen) == -1) {
    Log(LOG_ERR, "ERROR ( %s/%s ): create_socket_unyte_udp_notif(): bind() failed\n", config.name, t_data->log_str);
    close(sockfd);
    exit_gracefully(1);
  }

  /* free addr_info after usage */
  freeaddrinfo(addr_info);

  return sockfd;
}
#endif

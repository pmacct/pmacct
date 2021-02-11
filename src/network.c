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
    along with this program; if no, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include "pmacct.h"
#include "addr.h"
#include "network.h"
#include "thread_pool.h"

/* Global variables */
#ifdef WITH_GNUTLS
xflow_status_table_t dtls_status_table;
#endif

struct tunnel_handler tunnel_registry[TUNNEL_REGISTRY_STACKS][TUNNEL_REGISTRY_ENTRIES];

int parse_proxy_header(int fd, struct host_addr *addr, u_int16_t *port)
{
  const char v2sig[12] = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";
  char ip_address[INET6_ADDRSTRLEN];
  size_t size = 0;
  proxy_protocol_header hdr;

  addr_to_str(ip_address, addr);

  int ret = recv(fd, &hdr, sizeof(hdr), MSG_PEEK);

  /* 16 bytes can detect both V1 and V2 protocols */
  if (ret < 16) {
    return ERR;
  }

  if (memcmp(hdr.v1.line, "PROXY", 5) == 0) {
    Log(LOG_DEBUG, "DEBUG ( %s/%s ): Proxy Protocol V1\n", config.name, config.type);

    char *end = memchr(hdr.v1.line, '\r', ret - 1);
    if (!end || end[1] != '\n')  {
      return ERR;
    }

    (*end) = '\0';

    /* V1 Header contains string: PROXY TCP4 <src ip> <dst ip> <src port> <dst port>\r\n */
    Log(LOG_INFO, "INFO ( %s/%s ): Replacing: %s:%u\n", config.name, config.type, ip_address, *port);

    /* Find the Source IP Address */
    char *s = &hdr.v1.line[11];
    char *e = strchr(s, ' ');
    snprintf(ip_address, INET6_ADDRSTRLEN, "%s", s);

    /* Find the Source TCP Port */
    s = e + 1;
    e = strchr(s, ' ');
    s = e + 1;
    *port = strtoul(s, 0, 10);

    Log(LOG_INFO, "INFO ( %s/%s ):            with Proxy Protocol V1 containing: %s:%u\n", config.name, config.type, ip_address, *port);
    str_to_addr(ip_address, addr);

    /* Consume the proxy protocol header for real, skip header + CRLF */
    size = (end + 2 - hdr.v1.line);
  }
  else if (memcmp(&hdr.v2, v2sig, 12) == 0) {
    Log(LOG_DEBUG, "DEBUG ( %s/%s ): Proxy Protocol V2\n", config.name, config.type);

    size = (16 + ntohs(hdr.v2.len));
    if (ret < size) {
      return ERR;
    }

    if (((hdr.v2.ver_cmd & 0xF0) == 0x20) && ((hdr.v2.ver_cmd & 0x0F) == 0x01)) {
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): Proxy Protocol PROXY command\n", config.name, config.type);

      if (hdr.v2.fam == 0x11) {
        Log(LOG_DEBUG, "DEBUG ( %s/%s ): Proxy Protocol TCP/IPv4\n", config.name, config.type);

        /* Replace IP address string originally obtained from socket */
        Log(LOG_INFO, "INFO ( %s/%s ): Replacing: %s:%u\n", config.name, config.type, ip_address, *port);
        addr->family = AF_INET;
        memcpy(&addr->address.ipv4.s_addr, &hdr.v2.addr.ip4.src_addr, sizeof(hdr.v2.addr.ip4.src_addr));
        *port = ntohs(hdr.v2.addr.ip4.src_port);

        addr_to_str(ip_address, addr);
        Log(LOG_INFO, "INFO ( %s/%s ):            with Proxy Protocol V2 containing: %s:%u\n", config.name, config.type, ip_address, *port);
      }
      else {
        Log(LOG_DEBUG, "DEBUG ( %s/%s ): Proxy Protocol (TODO) Unsupported family: %u\n", config.name, config.type, hdr.v2.fam);
      }
    }
    else if (((hdr.v2.ver_cmd & 0xF0) == 0x20) && ((hdr.v2.ver_cmd & 0x0F) == 0x00)) {
      /* LOCAL Command. Health Check. Use real conection endpoints. */
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): Proxy Protocol LOCAL command\n", config.name, config.type);
    }
  }
  else {
    Log(LOG_DEBUG, "DEBUG ( %s/%s ): Not Proxy Protocol\n", config.name, config.type);
  }

  if (size > 0) {
    /* Consume the proxy protocol header for real */
    ret = recv(fd, &hdr, size, 0);
  }

  return 0;
}

/* Computing the internet checksum (RFC 1071) */
u_int16_t pm_checksum(u_int16_t *addr, int len, u_int32_t *prev_sum, int last)
{
  int count = len;
  u_int32_t sum = 0;
  u_int16_t answer = 0;

  if (prev_sum) {
    sum = (*prev_sum);
  }

  /* Sum up 2-byte values until none or only one byte left */
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  /* Add left-over byte, if any */
  if (count > 0) {
    sum += *(u_int8_t *) addr;
  }

  if (last) {
    /* Fold 32-bit sum into 16 bits; we lose information by doing this
       sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits) */
    while (sum >> 16) {
      sum = (sum & 0xffff) + (sum >> 16);
    }

    /* Making one-complement of it */
    answer = ~sum;
  }

  if (prev_sum) {
    (*prev_sum) = sum;
  }

  return (answer);
}

/* Build IPv6 UDP pseudo-header and call checksum function (Section 8.1 of RFC 2460). */
u_int16_t pm_udp6_checksum(struct ip6_hdr *ip6hdr, struct pm_udphdr *udphdr, u_char *payload, int payload_len)
{
  u_char buf[2];
  u_int32_t sum = 0;
  u_int16_t answer = 0;

  /* Copy source IP address into buf (128 bits) */
  pm_checksum ((u_int16_t *)&ip6hdr->ip6_src.s6_addr, sizeof (ip6hdr->ip6_src.s6_addr), &sum, FALSE);

  /* Seed destination IP address (128 bits) */
  pm_checksum ((u_int16_t *)&ip6hdr->ip6_dst.s6_addr, sizeof (ip6hdr->ip6_dst.s6_addr), &sum, FALSE);

  /* Seed UDP length (32 bits) */
  pm_checksum ((u_int16_t *)&udphdr->uh_ulen, sizeof (udphdr->uh_ulen), &sum, FALSE);

  /* Seed next header field (8 + 8 bits) */
  memset(buf, 0, sizeof(buf));
  buf[1] = ip6hdr->ip6_nxt;
  pm_checksum ((u_int16_t *)buf, 2, &sum, FALSE);

  /* Seed CUDP source port (16 bits) */
  pm_checksum ((u_int16_t *)&udphdr->uh_sport, sizeof (udphdr->uh_sport), &sum, FALSE);

  /* Seed UDP destination port (16 bits) */
  pm_checksum ((u_int16_t *)&udphdr->uh_dport, sizeof (udphdr->uh_dport), &sum, FALSE);

  /* Seed UDP length again (16 bits) */
  pm_checksum ((u_int16_t *)&udphdr->uh_ulen, sizeof (udphdr->uh_ulen), &sum, FALSE);

  /* Seed payload and take into account padding (16-bit boundary) */
  if (payload_len % 2) {
    pm_checksum ((u_int16_t *)payload, (payload_len - 1), &sum, FALSE);

    buf[0] = payload[payload_len];
    buf[1] = '\0';
    answer = pm_checksum ((u_int16_t *) buf, 2, &sum, TRUE);
  }
  else {
    answer = pm_checksum ((u_int16_t *)payload, payload_len, &sum, TRUE);
  }

  return answer;
}

#ifdef WITH_GNUTLS
void pm_dtls_init(pm_dtls_glob_t *dtls_globs, char *files_path)
{
  char cafile[LONGLONGSRVBUFLEN];
  char certfile[LONGLONGSRVBUFLEN], keyfile[LONGLONGSRVBUFLEN];
  int ret;

  gnutls_global_init();

  if (config.debug) {
    gnutls_global_set_log_function(pm_dtls_server_log);
    gnutls_global_set_log_level(4711);
  }

  gnutls_certificate_allocate_credentials(&dtls_globs->x509_cred);

  strcpy(cafile, files_path);
  strcat(cafile, "/");
  strcat(cafile, PM_GNUTLS_CAFILE);
  gnutls_certificate_set_x509_trust_file(dtls_globs->x509_cred, cafile, GNUTLS_X509_FMT_PEM);

  strcpy(certfile, files_path);
  strcat(certfile, "/");
  strcat(certfile, PM_GNUTLS_CERTFILE);

  strcpy(keyfile, files_path);
  strcat(keyfile, "/");
  strcat(keyfile, PM_GNUTLS_KEYFILE);

  ret = gnutls_certificate_set_x509_key_file(dtls_globs->x509_cred, certfile, keyfile, GNUTLS_X509_FMT_PEM);
  if (ret < 0) {
    Log(LOG_ERR, "ERROR ( %s/%s ): No DTLS certificate or key were found\n", config.name, config.type);
    exit_gracefully(1);
  }

  gnutls_certificate_set_known_dh_params(dtls_globs->x509_cred, GNUTLS_SEC_PARAM_MEDIUM);
  gnutls_priority_init2(&dtls_globs->priority_cache, "%SERVER_PRECEDENCE", NULL, GNUTLS_PRIORITY_INIT_DEF_APPEND);
  gnutls_key_generate(&dtls_globs->cookie_key, GNUTLS_COOKIE_KEY_SIZE);
}

void pm_dtls_client_init(pm_dtls_peer_t *peer, int fd, struct sockaddr_storage *sock, socklen_t sock_len, char *verify_cert)
{
  int ret;

  if (!peer) {
    Log(LOG_ERR, "ERROR ( %s/%s ): DTLS struct not found.\n", config.name, config.type);
    exit_gracefully(1);
  }

  memset(peer, 0, sizeof(pm_dtls_peer_t));

  gnutls_init(&peer->session, GNUTLS_CLIENT | GNUTLS_DATAGRAM);
  gnutls_set_default_priority(peer->session);
  gnutls_credentials_set(peer->session, GNUTLS_CRD_CERTIFICATE, config.dtls_globs.x509_cred);

  if (verify_cert) {
    gnutls_server_name_set(peer->session, GNUTLS_NAME_DNS, verify_cert, strlen(verify_cert));
    gnutls_session_set_verify_cert(peer->session, verify_cert, 0);
  }

  gnutls_handshake_set_timeout(peer->session, PM_DTLS_TIMEOUT_HS); // XXX
  gnutls_dtls_set_timeouts(peer->session, PM_DTLS_TIMEOUT_RETRANS, PM_DTLS_TIMEOUT_TOTAL);
  gnutls_dtls_set_mtu(peer->session, PM_DTLS_MTU); // XXX: PMTU?

  gnutls_transport_set_int(peer->session, fd);
  peer->conn.fd = fd;

  memcpy(&peer->conn.peer, sock, sock_len);
  peer->conn.peer_len = sock_len;

  /* starting async rx to collect DTLS feedback messages, ie. disconnects */
  peer->conn.async_rx = allocate_thread_pool(1);
  assert(peer->conn.async_rx);
  send_to_pool(peer->conn.async_rx, pm_dtls_client_recv_async, peer);

  /* Perform the TLS handshake */
  do {
    ret = gnutls_handshake(peer->session);
    peer->conn.stage = PM_DTLS_STAGE_HANDSHAKE;
  }
  while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);

  if (ret < 0) {
    Log(LOG_ERR, "ERROR ( %s/%s ): [dtls] handshake: %s\n", config.name, config.type, gnutls_strerror(ret));
    pm_dtls_server_bye(peer);
  }
  else {
    char *desc;

    desc = gnutls_session_get_desc(peer->session);
    Log(LOG_INFO, "INFO ( %s/%s ): [dtls] handshake: %s\n", config.name, config.type, desc);
    gnutls_free(desc);

    peer->conn.stage = PM_DTLS_STAGE_UP;
  }
}

ssize_t pm_dtls_server_recv(gnutls_transport_ptr_t p, void *data, size_t len)
{
  pm_dtls_conn_t *conn = p;
  struct sockaddr_storage client;
  socklen_t clen;
  int ret;

  memset(&client, 0, sizeof(client));
  clen = sizeof(client);

  ret = recvfrom(conn->fd, data, len, 0, (struct sockaddr *) &client, &clen);

  /* validate message is received from the expected source */
  ipv4_mapped_to_ipv4(&client);

  if (clen == conn->peer_len && !memcmp(&client, &conn->peer, clen)) {
    return ret;
  }

  return ERR;
}

ssize_t pm_dtls_server_send(gnutls_transport_ptr_t p, const void *data, size_t len)
{
  pm_dtls_conn_t *conn = p;

  return sendto(conn->fd, data, len, 0, (struct sockaddr *) &conn->peer, conn->peer_len);
}

ssize_t pm_dtls_client_send(pm_dtls_peer_t *peer, const void *data, size_t len)
{
  int ret = 0;

  if (peer->conn.stage == PM_DTLS_STAGE_UP) {
    ret = gnutls_record_send(peer->session, data, len);

    if (ret < 0) {
      Log(LOG_WARNING, "WARN ( %s/%s ): pm_dtls_client_send() failed: %s\n", config.name, config.type, gnutls_strerror(ret));
      pm_dtls_client_bye(peer);
    }
  }

  return ret;
}

int pm_dtls_server_select(gnutls_transport_ptr_t p, unsigned int ms)
{
  return 1;
}

int pm_dtls_client_recv_async(pm_dtls_peer_t *peer)
{
  int ret = 0, buflen = PM_DTLS_MTU;
  char buf[buflen];

  for (;;) {
    if (peer->conn.stage == PM_DTLS_STAGE_UP) {
      ret = gnutls_record_recv(peer->session, buf, buflen);

      if (ret == 0) {
	/* Peer has closed the DTLS connection */
	peer->conn.do_reconnect = TRUE;
	Log(LOG_INFO, "INFO ( %s/%s ): [dtls] recv_async: server closed connection.\n", config.name, config.type);
	return ERR;
      }
      else if (ret < 0) {
	/* Error */
	peer->conn.do_reconnect = TRUE;
	Log(LOG_ERR, "ERROR ( %s/%s ): [dtls] recv_async: %s\n", config.name, config.type, gnutls_strerror(ret));
	return ERR;
      }

      if (ret > 0) {
	/* OK: noop */
      }
    }
    else {
      sleep(1);
    }
  }

  return SUCCESS;
}

void pm_dtls_server_log(int level, const char *str)
{
  Log(LOG_DEBUG, "DEBUG ( %s/%s ): [dtls] %d | %s", config.name, config.type, level, str);
}

void pm_dtls_server_bye(pm_dtls_peer_t *peer)
{
  struct xflow_status_entry *entry;
  int idx;

  if (peer) {
    if (peer->conn.fd) {
      gnutls_bye(peer->session, GNUTLS_SHUT_WR);
      gnutls_deinit(peer->session);

      memset(peer, 0, sizeof(pm_dtls_peer_t));
    }
  }
  else {
    for (idx = 0; idx < XFLOW_STATUS_TABLE_SZ; idx++) {
      entry = dtls_status_table.t[idx];

      if (entry) {
	next:
	if (entry->dtls.conn.fd) {
	  gnutls_bye(entry->dtls.session, GNUTLS_SHUT_WR);
	  gnutls_deinit(entry->dtls.session);

	  memset(peer, 0, sizeof(pm_dtls_peer_t));
	}

	if (entry->next) {
	  entry = entry->next;
	  goto next;
	}
      }
    }
  }
}

void pm_dtls_client_bye(pm_dtls_peer_t *peer)
{
  gnutls_bye(peer->session, GNUTLS_SHUT_WR);
  gnutls_deinit(peer->session);

  peer->conn.stage = PM_DTLS_STAGE_DOWN;
  peer->conn.do_reconnect = FALSE;

  if (peer->conn.async_rx) deallocate_thread_pool((thread_pool_t **) &peer->conn.async_rx);
  if (peer->conn.async_tx) deallocate_thread_pool((thread_pool_t **) &peer->conn.async_tx);
}

int pm_dtls_server_process(int dtls_sock, struct sockaddr_storage *client, socklen_t clen, u_char *dtls_packet, int len, void *st)
{
  int hash = hash_status_table(0, (struct sockaddr *) client, XFLOW_STATUS_TABLE_SZ);
  xflow_status_table_t *status_table = st;
  struct xflow_status_entry *entry = NULL;
  int dtls_ret = 0, ret = 0;

  if (hash >= 0) {
    entry = search_status_table(status_table, (struct sockaddr *) client, 0, 0, hash, XFLOW_STATUS_TABLE_MAX_ENTRIES);
    if (entry) {
      if (entry->dtls.session) {
        /* Finalizing Hello stage */
	if (entry->dtls.conn.stage == PM_DTLS_STAGE_HELLO) {
	  dtls_ret = gnutls_dtls_cookie_verify(&config.dtls_globs.cookie_key, client, sizeof(struct sockaddr_storage),
					       dtls_packet, len, &entry->dtls.prestate);
	  if (dtls_ret < 0) {
	    Log(LOG_ERR, "ERROR ( %s/core ): [dtls] hello: %s\n", config.name, gnutls_strerror(dtls_ret));
	    pm_dtls_server_bye(&entry->dtls);
	  }
	  else {
	    gnutls_dtls_prestate_set(entry->dtls.session, &entry->dtls.prestate);
	    entry->dtls.conn.stage = PM_DTLS_STAGE_HANDSHAKE;
	  }
	}

	/* Handshake */
	if (entry->dtls.conn.stage == PM_DTLS_STAGE_HANDSHAKE) {
	  do {
	    dtls_ret = gnutls_handshake(entry->dtls.session);
	  }
	  while (dtls_ret < 0 && !gnutls_error_is_fatal(dtls_ret));

	  if (dtls_ret < 0) {
	    Log(LOG_ERR, "ERROR ( %s/core ): [dtls] handshake: %s\n", config.name, gnutls_strerror(dtls_ret));
	    pm_dtls_server_bye(&entry->dtls);
	  }
	  else {
	    entry->dtls.conn.stage = PM_DTLS_STAGE_UP;
	  }
	}

	/* Data */
	if (entry->dtls.conn.stage == PM_DTLS_STAGE_UP) {
	  ret = gnutls_record_recv_seq(entry->dtls.session, dtls_packet, PKT_MSG_SIZE, entry->dtls.conn.seq);

	  if (ret < 0) {
	    if (!gnutls_error_is_fatal(ret)) {
	      Log(LOG_WARNING, "WARN ( %s/core ): [dtls] data: %s\n", config.name, gnutls_strerror(dtls_ret));
	    }
	    else {
	      Log(LOG_ERR, "ERROR ( %s/core ): [dtls] data: %s\n", config.name, gnutls_strerror(dtls_ret));
	      pm_dtls_server_bye(&entry->dtls);
	    }
	  }
	  else {
	    /* All good */
	    if (config.debug) {
	      u_char hexbuf[2 * LARGEBUFLEN];

	      serialize_hex(dtls_packet, hexbuf, ret);

	      Log(LOG_DEBUG, "DEBUG ( %s/core ): [dtls] data received: seq=%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x len=%d hex=%s\n",
		  config.name, entry->dtls.conn.seq[0], entry->dtls.conn.seq[1], entry->dtls.conn.seq[2],
		  entry->dtls.conn.seq[3], entry->dtls.conn.seq[4], entry->dtls.conn.seq[5], entry->dtls.conn.seq[6],
		  entry->dtls.conn.seq[7], ret, hexbuf);
	    }

	    /* EOF */
	    if (ret == 0) {
	      pm_dtls_server_bye(&entry->dtls);
	    }
	  }
	}

	if (entry->dtls.conn.stage == PM_DTLS_STAGE_UP) {
	  return ret;
	}
      }
      else {
	gnutls_init(&entry->dtls.session, GNUTLS_SERVER | GNUTLS_DATAGRAM);
	gnutls_handshake_set_timeout(entry->dtls.session, PM_DTLS_TIMEOUT_HS); // XXX
        gnutls_dtls_set_timeouts(entry->dtls.session, PM_DTLS_TIMEOUT_RETRANS, PM_DTLS_TIMEOUT_TOTAL);
	gnutls_dtls_set_mtu(entry->dtls.session, PM_DTLS_MTU); // XXX: PMTU?
	gnutls_priority_set(entry->dtls.session, config.dtls_globs.priority_cache);
	gnutls_credentials_set(entry->dtls.session, GNUTLS_CRD_CERTIFICATE, config.dtls_globs.x509_cred);

	entry->dtls.conn.fd = dtls_sock;
	memcpy(&entry->dtls.conn.peer, client, clen);
	entry->dtls.conn.peer_len = clen;
	gnutls_transport_set_ptr(entry->dtls.session, &entry->dtls.conn);
	gnutls_transport_set_pull_function(entry->dtls.session, pm_dtls_server_recv);
	gnutls_transport_set_pull_timeout_function(entry->dtls.session, pm_dtls_server_select);
	gnutls_transport_set_push_function(entry->dtls.session, pm_dtls_server_send);

	/* Sending Hello with cookie */
	dtls_ret = gnutls_dtls_cookie_send(&config.dtls_globs.cookie_key, client, sizeof(struct sockaddr_storage),
					   &entry->dtls.prestate, (gnutls_transport_ptr_t) &entry->dtls.conn,
					   pm_dtls_server_send);
	if (dtls_ret < 0) {
	  Log(LOG_ERR, "ERROR ( %s/core ): [dtls] cookie: %s\n", config.name, gnutls_strerror(dtls_ret));
	  pm_dtls_server_bye(&entry->dtls);
	}
	else {
	  entry->dtls.conn.stage = PM_DTLS_STAGE_HELLO;
	}

	/* discard peeked data */
	recv(dtls_sock, (unsigned char *) dtls_packet, PKT_MSG_SIZE, 0);
      }
    }
  }

  return FALSE;
}
#endif

/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2016 by Paolo Lucente
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
#include "telemetry.h"
#if defined WITH_RABBITMQ
#include "amqp_common.h"
#endif
#ifdef WITH_KAFKA
#include "kafka_common.h"
#endif

/* Functions */
void telemetry_process_data(telemetry_peer *peer, struct telemetry_data *t_data)
{
  telemetry_misc_structs *tms;

  if (!peer || !t_data) return;

  tms = bgp_select_misc_db(peer->type);

  if (!tms) return;

  if (tms->msglog_backend_methods) {
    char event_type[] = "log";

    telemetry_log_msg(peer, t_data, peer->buf.base, peer->msglen, event_type, config.telemetry_msglog_output);
  }

  if (tms->dump_backend_methods)
    telemetry_dump_se_ll_append(peer, t_data);
}

int telemetry_recv_generic(telemetry_peer *peer, u_int32_t len)
{
  int ret = 0;

  if (!len) {
    ret = recv(peer->fd, &peer->buf.base[peer->buf.truncated_len], (peer->buf.len - peer->buf.truncated_len), 0);
    peer->msglen = (ret + peer->buf.truncated_len);
  }
  else {
    if (len <= (peer->buf.len - peer->buf.truncated_len)) { 
      ret = recv(peer->fd, &peer->buf.base[peer->buf.truncated_len], len, MSG_WAITALL);
      peer->msglen = (ret + peer->buf.truncated_len);
    }
  }

  return ret;
}

void telemetry_basic_process_json(telemetry_peer *peer)
{
  int idx;

  for (idx = 0; idx < peer->msglen; idx++) {
    if (!isprint(peer->buf.base[idx])) peer->buf.base[idx] = '\0';
  }

  if (peer->buf.len >= (peer->msglen + 1)) {
    peer->buf.base[peer->msglen + 1] = '\0';
    peer->msglen++;
  }
}

int telemetry_recv_json(telemetry_peer *peer, u_int32_t len, int *flags)
{
  int ret = 0, idx;

  (*flags) = FALSE;
  ret = telemetry_recv_generic(peer, len);

  telemetry_basic_process_json(peer);

  if (ret) (*flags) = telemetry_basic_validate_json(peer);

  return ret;
}

int telemetry_recv_zjson(telemetry_peer *peer, telemetry_peer_z *peer_z, u_int32_t len, int *flags)
{
  int ret = 0, idx;

#if defined (HAVE_ZLIB)
  (*flags) = FALSE;
  memset(peer_z->inflate_buf, 0, sizeof(peer_z->inflate_buf));
  peer_z->stm.avail_out = (uInt) sizeof(peer_z->inflate_buf);
  peer_z->stm.next_out = (Bytef *) peer_z->inflate_buf;

  ret = telemetry_recv_generic(peer, len);

  peer_z->stm.avail_in = (uInt) peer->msglen;
  peer_z->stm.next_in = (Bytef *) peer->buf.base;

  if (ret > 0) { 
    if (inflate(&peer_z->stm, Z_NO_FLUSH) != Z_OK) ret = FALSE;
    else {
      strlcpy(peer->buf.base, peer_z->inflate_buf, peer->buf.len);
      peer->msglen = strlen(peer->buf.base) + 1;

      (*flags) = telemetry_basic_validate_json(peer);
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

  ret = telemetry_recv_generic(peer, TELEMETRY_CISCO_HDR_LEN);
  if (ret > 0) {
    len = telemetry_cisco_hdr_get_len(peer); 
    ret = telemetry_recv_zjson(peer, peer_z, len, flags); 
  }

  return ret;
}

int telemetry_basic_validate_json(telemetry_peer *peer)
{
  if (peer->buf.base[peer->buf.truncated_len] != '{')
    return ERR;
  else
    return FALSE;
}

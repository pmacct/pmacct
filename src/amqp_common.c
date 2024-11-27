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

#define __AMQP_COMMON_C

/* includes */
#include "amqp_common.h"
#include "pmacct-data.h"
#include "pmacct.h"

/* Functions */
void p_amqp_init_host(struct p_amqp_host* amqp_host) {
  if (amqp_host) {
    memset(amqp_host, 0, sizeof(struct p_amqp_host));
    p_amqp_set_frame_max(amqp_host, AMQP_DEFAULT_FRAME_SIZE);
    p_amqp_set_heartbeat_interval(amqp_host, AMQP_DEFAULT_HEARTBEAT);
    P_broker_timers_set_retry_interval(&amqp_host->btimers, AMQP_DEFAULT_RETRY);
  }
}

void p_amqp_set_user(struct p_amqp_host* amqp_host, char* user) {
  if (amqp_host)
    amqp_host->user = user;
}

void p_amqp_set_passwd(struct p_amqp_host* amqp_host, char* passwd) {
  if (amqp_host)
    amqp_host->passwd = passwd;
}

void p_amqp_set_exchange(struct p_amqp_host* amqp_host, char* exchange) {
  if (amqp_host)
    amqp_host->exchange = exchange;
}

void p_amqp_set_routing_key(struct p_amqp_host* amqp_host, char* routing_key) {
  if (amqp_host)
    amqp_host->routing_key = routing_key;
}

void p_amqp_unset_routing_key(struct p_amqp_host* amqp_host) {
  if (amqp_host)
    amqp_host->routing_key = NULL;
}

char* p_amqp_get_routing_key(struct p_amqp_host* amqp_host) {
  if (amqp_host)
    return amqp_host->routing_key;

  return NULL;
}

void p_amqp_init_routing_key_rr(struct p_amqp_host* amqp_host) {
  if (amqp_host)
    memset(&amqp_host->rk_rr, 0, sizeof(struct p_table_rr));
}

void p_amqp_set_routing_key_rr(struct p_amqp_host* amqp_host, int rk_rr) {
  if (amqp_host)
    amqp_host->rk_rr.max = rk_rr;
}

int p_amqp_get_routing_key_rr(struct p_amqp_host* amqp_host) {
  if (amqp_host)
    return amqp_host->rk_rr.max;

  return FALSE;
}

void p_amqp_set_exchange_type(struct p_amqp_host* amqp_host,
                              char* exchange_type) {
  if (amqp_host && exchange_type) {
    lower_string(exchange_type);
    amqp_host->exchange_type = exchange_type;
  }
}

void p_amqp_set_host(struct p_amqp_host* amqp_host, char* host) {
  if (amqp_host)
    amqp_host->host = host;
}

void p_amqp_set_vhost(struct p_amqp_host* amqp_host, char* vhost) {
  if (amqp_host)
    amqp_host->vhost = vhost;
}

void p_amqp_set_frame_max(struct p_amqp_host* amqp_host, u_int32_t opt) {
  if (amqp_host) {
    if (opt > PM_AMQP_MIN_FRAME_SIZE)
      amqp_host->frame_max = opt;
  }
}

void p_amqp_set_heartbeat_interval(struct p_amqp_host* amqp_host, int opt) {
  if (amqp_host) {
    amqp_host->heartbeat_interval = opt;
  }
}

void p_amqp_set_persistent_msg(struct p_amqp_host* amqp_host, int opt) {
  if (amqp_host)
    amqp_host->persistent_msg = opt;
}

void p_amqp_set_content_type_json(struct p_amqp_host* amqp_host) {
  if (amqp_host) {
    amqp_host->msg_props._flags = AMQP_BASIC_CONTENT_TYPE_FLAG;
    amqp_host->msg_props.content_type = amqp_cstring_bytes("application/json");
  }
}

void p_amqp_set_content_type_binary(struct p_amqp_host* amqp_host) {
  if (amqp_host) {
    amqp_host->msg_props._flags = AMQP_BASIC_CONTENT_TYPE_FLAG;
    amqp_host->msg_props.content_type =
        amqp_cstring_bytes("application/octet-stream");
  }
}

int p_amqp_get_sockfd(struct p_amqp_host* amqp_host) {
  if (amqp_host) {
    if (!P_broker_timers_get_last_fail(&amqp_host->btimers))
      return amqp_get_sockfd(amqp_host->conn);
  }

  return ERR;
}

int p_amqp_connect_to_publish(struct p_amqp_host* amqp_host) {
  amqp_host->conn = amqp_new_connection();

  amqp_host->socket = amqp_tcp_socket_new(amqp_host->conn);
  if (!amqp_host->socket) {
    Log(LOG_ERR,
        "ERROR ( %s/%s ): Connection failed to RabbitMQ: "
        "p_amqp_connect_to_publish(): no socket\n",
        config.name, config.type);
    p_amqp_close(amqp_host, TRUE);
    return ERR;
  }

  amqp_host->status = amqp_socket_open(amqp_host->socket, amqp_host->host,
                                       5672 /* default port */);

  if (amqp_host->status != AMQP_STATUS_OK) {
    Log(LOG_ERR,
        "ERROR ( %s/%s ): Connection failed to RabbitMQ: "
        "p_amqp_connect_to_publish(): unable to open socket\n",
        config.name, config.type);
    p_amqp_close(amqp_host, TRUE);
    return ERR;
  }

  amqp_host->ret =
      amqp_login(amqp_host->conn, amqp_host->vhost, 0, amqp_host->frame_max,
                 amqp_host->heartbeat_interval, AMQP_SASL_METHOD_PLAIN,
                 amqp_host->user, amqp_host->passwd);
  if (amqp_host->ret.reply_type != AMQP_RESPONSE_NORMAL) {
    Log(LOG_ERR,
        "ERROR ( %s/%s ): Connection failed to RabbitMQ: "
        "p_amqp_connect_to_publish(): login\n",
        config.name, config.type);
    p_amqp_close(amqp_host, TRUE);
    return ERR;
  }

  amqp_channel_open(amqp_host->conn, 1);

  amqp_host->ret = amqp_get_rpc_reply(amqp_host->conn);
  if (amqp_host->ret.reply_type != AMQP_RESPONSE_NORMAL) {
    Log(LOG_ERR,
        "ERROR ( %s/%s ): Connection failed to RabbitMQ: "
        "p_amqp_connect_to_publish(): unable to open channel\n",
        config.name, config.type);
    p_amqp_close(amqp_host, TRUE);
    return ERR;
  }

#if AMQP_VERSION_MAJOR <= 0 && AMQP_VERSION_MINOR <= 5 && \
    AMQP_VERSION_PATCH <= 2
  amqp_exchange_declare(
      amqp_host->conn, 1, amqp_cstring_bytes(amqp_host->exchange),
      amqp_cstring_bytes(amqp_host->exchange_type), 0, 0, amqp_empty_table);
#else
  amqp_exchange_declare(amqp_host->conn, 1,
                        amqp_cstring_bytes(amqp_host->exchange),
                        amqp_cstring_bytes(amqp_host->exchange_type), 0, 0, 0,
                        0, amqp_empty_table);
#endif

  amqp_host->ret = amqp_get_rpc_reply(amqp_host->conn);
  if (amqp_host->ret.reply_type != AMQP_RESPONSE_NORMAL) {
    const char* err_msg;

    switch (amqp_host->ret.reply_type) {
      case AMQP_RESPONSE_NONE:
        err_msg = "Missing RPC reply type";
        break;
      case AMQP_RESPONSE_LIBRARY_EXCEPTION:
        err_msg = "Client library exception";
        break;
      case AMQP_RESPONSE_SERVER_EXCEPTION:
        err_msg = "Server generated an exception";
        break;
      default:
        err_msg = "Unknown";
        break;
    }

    Log(LOG_ERR, "ERROR ( %s/%s ): Handshake with RabbitMQ failed: %s\n",
        config.name, config.type, err_msg);
    p_amqp_close(amqp_host, TRUE);
    return ERR;
  }

  // XXX: to be removed
  amqp_host->msg_props._flags = AMQP_BASIC_CONTENT_TYPE_FLAG;
  amqp_host->msg_props.content_type = amqp_cstring_bytes("application/json");

  if (amqp_host->persistent_msg) {
    amqp_host->msg_props._flags |= AMQP_BASIC_DELIVERY_MODE_FLAG;
    amqp_host->msg_props.delivery_mode = 2; /* persistent delivery */
  }

  Log(LOG_DEBUG,
      "DEBUG ( %s/%s ): Connection successful to RabbitMQ: "
      "p_amqp_connect_to_publish()\n",
      config.name, config.type);

  P_broker_timers_unset_last_fail(&amqp_host->btimers);
  return SUCCESS;
}

int p_amqp_connect_to_consume(struct p_amqp_host* amqp_host) {
  amqp_host->conn = amqp_new_connection();

  amqp_host->socket = amqp_tcp_socket_new(amqp_host->conn);
  if (!amqp_host->socket) {
    Log(LOG_ERR,
        "ERROR ( %s/%s ): Connection failed to RabbitMQ: "
        "p_amqp_connect_to_consume(): no socket\n",
        config.name, config.type);
    p_amqp_close(amqp_host, TRUE);
    return ERR;
  }

  amqp_host->status = amqp_socket_open(amqp_host->socket, amqp_host->host,
                                       5672 /* default port */);

  if (amqp_host->status != AMQP_STATUS_OK) {
    Log(LOG_ERR,
        "ERROR ( %s/%s ): Connection failed to RabbitMQ: "
        "p_amqp_connect_to_consume(): unable to open socket\n",
        config.name, config.type);
    p_amqp_close(amqp_host, TRUE);
    return ERR;
  }

  amqp_host->ret =
      amqp_login(amqp_host->conn, amqp_host->vhost, 0, amqp_host->frame_max,
                 amqp_host->heartbeat_interval, AMQP_SASL_METHOD_PLAIN,
                 amqp_host->user, amqp_host->passwd);
  if (amqp_host->ret.reply_type != AMQP_RESPONSE_NORMAL) {
    Log(LOG_ERR,
        "ERROR ( %s/%s ): Connection failed to RabbitMQ: "
        "p_amqp_connect_to_consume(): login\n",
        config.name, config.type);
    p_amqp_close(amqp_host, TRUE);
    return ERR;
  }

  amqp_channel_open(amqp_host->conn, 1);
  amqp_host->ret = amqp_get_rpc_reply(amqp_host->conn);
  if (amqp_host->ret.reply_type != AMQP_RESPONSE_NORMAL) {
    Log(LOG_ERR,
        "ERROR ( %s/%s ): Connection failed to RabbitMQ: "
        "p_amqp_connect_to_consume(): unable to open channel\n",
        config.name, config.type);
    p_amqp_close(amqp_host, TRUE);
    return ERR;
  }

#if AMQP_VERSION_MAJOR <= 0 && AMQP_VERSION_MINOR <= 5 && \
    AMQP_VERSION_PATCH <= 2
  amqp_exchange_declare(
      amqp_host->conn, 1, amqp_cstring_bytes(amqp_host->exchange),
      amqp_cstring_bytes(amqp_host->exchange_type), 0, 0, amqp_empty_table);
#else
  amqp_exchange_declare(amqp_host->conn, 1,
                        amqp_cstring_bytes(amqp_host->exchange),
                        amqp_cstring_bytes(amqp_host->exchange_type), 0, 1, 0,
                        0, amqp_empty_table);
#endif
  amqp_host->ret = amqp_get_rpc_reply(amqp_host->conn);
  if (amqp_host->ret.reply_type != AMQP_RESPONSE_NORMAL) {
    Log(LOG_ERR,
        "ERROR ( %s/%s ): Connection failed to RabbitMQ: "
        "p_amqp_connect_to_consume(): amqp_exchange_declare()\n",
        config.name, config.type);
    p_amqp_close(amqp_host, TRUE);
    return ERR;
  }

  {
    amqp_queue_declare_ok_t* ret_qd;

    ret_qd = amqp_queue_declare(amqp_host->conn, 1, amqp_empty_bytes, 0, 0, 1,
                                1, amqp_empty_table);
    amqp_host->ret = amqp_get_rpc_reply(amqp_host->conn);

    if (amqp_host->ret.reply_type != AMQP_RESPONSE_NORMAL) {
      Log(LOG_ERR,
          "ERROR ( %s/%s ): Connection failed to RabbitMQ: "
          "p_amqp_connect_to_consume(): queue declare\n",
          config.name, config.type);
      p_amqp_close(amqp_host, TRUE);
      return ERR;
    } else {
      amqp_host->queue = amqp_bytes_malloc_dup(ret_qd->queue);
      if (!amqp_host->queue.bytes) {
        Log(LOG_ERR,
            "ERROR ( %s/%s ): Connection failed to RabbitMQ: "
            "p_amqp_connect_to_consume(): amqp_bytes_malloc_dup()\n",
            config.name, config.type);
        p_amqp_close(amqp_host, TRUE);
        return ERR;
      }
    }
  }

  amqp_queue_bind(amqp_host->conn, 1, amqp_host->queue,
                  amqp_cstring_bytes(amqp_host->exchange),
                  amqp_cstring_bytes(amqp_host->routing_key), amqp_empty_table);
  amqp_host->ret = amqp_get_rpc_reply(amqp_host->conn);
  if (amqp_host->ret.reply_type != AMQP_RESPONSE_NORMAL) {
    Log(LOG_ERR,
        "ERROR ( %s/%s ): Connection failed to RabbitMQ: "
        "p_amqp_connect_to_consume(): queue bind\n",
        config.name, config.type);
    p_amqp_close(amqp_host, TRUE);
    return ERR;
  }

  amqp_basic_consume(amqp_host->conn, 1, amqp_host->queue, amqp_empty_bytes, 0,
                     1, 0, amqp_empty_table);
  amqp_host->ret = amqp_get_rpc_reply(amqp_host->conn);
  if (amqp_host->ret.reply_type != AMQP_RESPONSE_NORMAL) {
    Log(LOG_ERR,
        "ERROR ( %s/%s ): Connection failed to RabbitMQ: "
        "p_amqp_connect_to_consume(): basic consume\n",
        config.name, config.type);
    p_amqp_close(amqp_host, TRUE);
    return ERR;
  }

  Log(LOG_DEBUG,
      "DEBUG ( %s/%s ): Connection successful to RabbitMQ: "
      "p_amqp_connect_to_consume()\n",
      config.name, config.type);

  P_broker_timers_unset_last_fail(&amqp_host->btimers);
  return SUCCESS;
}

int p_amqp_publish_string(struct p_amqp_host* amqp_host, char* json_str) {
  if (p_amqp_is_alive(amqp_host) == ERR) {
    p_amqp_close(amqp_host, TRUE);
    return ERR;
  }

  amqp_host->status = amqp_basic_publish(
      amqp_host->conn, 1, amqp_cstring_bytes(amqp_host->exchange),
      amqp_cstring_bytes(amqp_host->routing_key), 0, 0, &amqp_host->msg_props,
      amqp_cstring_bytes(json_str));

  if (amqp_host->status) {
    Log(LOG_ERR,
        "ERROR ( %s/%s ): Connection failed to RabbitMQ: "
        "p_amqp_publish_string() [E=%s RK=%s DM=%u]\n",
        config.name, config.type, amqp_host->exchange, amqp_host->routing_key,
        amqp_host->msg_props.delivery_mode);
    p_amqp_close(amqp_host, TRUE);
    return ERR;
  } else {
    if (config.debug)
      Log(LOG_DEBUG,
          "DEBUG ( %s/%s ): publishing to RabbitMQ: p_amqp_publish_string() "
          "[E=%s RK=%s DM=%u]: %s\n",
          config.name, config.type, amqp_host->exchange, amqp_host->routing_key,
          amqp_host->msg_props.delivery_mode, json_str);
  }

  return SUCCESS;
}

int p_amqp_publish_binary(struct p_amqp_host* amqp_host,
                          void* data,
                          u_int32_t data_len) {
  amqp_bytes_t pdata;

  if (p_amqp_is_alive(amqp_host) == ERR) {
    p_amqp_close(amqp_host, TRUE);
    return ERR;
  }

  memset(&pdata, 0, sizeof(pdata));
  pdata.len = data_len;
  pdata.bytes = data;

  amqp_host->status = amqp_basic_publish(
      amqp_host->conn, 1, amqp_cstring_bytes(amqp_host->exchange),
      amqp_cstring_bytes(amqp_host->routing_key), 0, 0, &amqp_host->msg_props,
      pdata);

  if (amqp_host->status) {
    Log(LOG_ERR,
        "ERROR ( %s/%s ): Connection failed to RabbitMQ: "
        "p_amqp_publish_binary() [E=%s RK=%s DM=%u]\n",
        config.name, config.type, amqp_host->exchange, amqp_host->routing_key,
        amqp_host->msg_props.delivery_mode);
    p_amqp_close(amqp_host, TRUE);
    return ERR;
  } else {
    if (config.debug)
      Log(LOG_DEBUG,
          "DEBUG ( %s/%s ): publishing to RabbitMQ: p_amqp_publish_binary() "
          "[E=%s RK=%s DM=%u]\n",
          config.name, config.type, amqp_host->exchange, amqp_host->routing_key,
          amqp_host->msg_props.delivery_mode);
  }

  return SUCCESS;
}

int p_amqp_consume_binary(struct p_amqp_host* amqp_host,
                          void* data,
                          u_int32_t data_len) {
  amqp_envelope_t envelope;
  amqp_frame_t frame;
  size_t size;

  if (!amqp_host || !data || !data_len)
    ERR;

  memset(data, 0, data_len);

  if (p_amqp_is_alive(amqp_host) == ERR) {
    p_amqp_close(amqp_host, TRUE);
    return ERR;
  }

  amqp_maybe_release_buffers(amqp_host->conn);

  amqp_host->ret = amqp_consume_message(amqp_host->conn, &envelope, NULL, 0);
  if (amqp_host->ret.reply_type != AMQP_RESPONSE_NORMAL) {
    if (amqp_host->ret.reply_type == AMQP_RESPONSE_SERVER_EXCEPTION ||
        (amqp_host->ret.reply_type == AMQP_RESPONSE_LIBRARY_EXCEPTION &&
         (amqp_host->ret.library_error & AMQP_STATUS_SOCKET_ERROR))) {
      Log(LOG_ERR,
          "ERROR ( %s/%s ): Connection failed to RabbitMQ: "
          "p_amqp_consume_binary(): socket error [E=%s RK=%s]\n",
          config.name, config.type, amqp_host->exchange,
          amqp_host->routing_key);
      p_amqp_close(amqp_host, TRUE);
      return ERR;
    }

    if (amqp_host->ret.reply_type == AMQP_RESPONSE_LIBRARY_EXCEPTION &&
        amqp_host->ret.library_error == AMQP_STATUS_UNEXPECTED_STATE) {
      if (amqp_simple_wait_frame(amqp_host->conn, &frame) != AMQP_STATUS_OK) {
        Log(LOG_ERR,
            "ERROR ( %s/%s ): Connection failed to RabbitMQ: "
            "p_amqp_consume_binary(): wait frame [E=%s RK=%s]\n",
            config.name, config.type, amqp_host->exchange,
            amqp_host->routing_key);
        p_amqp_close(amqp_host, TRUE);
        return ERR;
      }

      if (frame.frame_type == AMQP_FRAME_METHOD) {
        amqp_message_t message;

        Log(LOG_DEBUG,
            "DEBUG ( %s/%s ): p_amqp_consume_binary(): frame payload method "
            "'%x' [E=%s RK=%s]\n",
            config.name, config.type, frame.payload.method.id,
            amqp_host->exchange, amqp_host->routing_key);

        switch (frame.payload.method.id) {
          case AMQP_BASIC_RETURN_METHOD:
            amqp_host->ret =
                amqp_read_message(amqp_host->conn, frame.channel, &message, 0);
            if (amqp_host->ret.reply_type != AMQP_RESPONSE_NORMAL) {
              Log(LOG_ERR,
                  "ERROR ( %s/%s ): Connection failed to RabbitMQ: "
                  "p_amqp_consume_binary(): read mandatory message [E=%s "
                  "RK=%s]\n",
                  config.name, config.type, amqp_host->exchange,
                  amqp_host->routing_key);
              p_amqp_close(amqp_host, TRUE);
              return ERR;
            }

            amqp_destroy_message(&message);

            break;
          case AMQP_BASIC_ACK_METHOD:
          case AMQP_CHANNEL_CLOSE_METHOD:
          case AMQP_CONNECTION_CLOSE_METHOD:
          default:
            break;
        }
      }
    }
  } else {
    if (data && data_len) {
      // XXX: brief check over content type and/or properties?

      memcpy(data, envelope.message.body.bytes,
             MIN(envelope.message.body.len, data_len));
    }

    amqp_destroy_envelope(&envelope);

    if (config.debug)
      Log(LOG_DEBUG,
          "DEBUG ( %s/%s ): receive from RabbitMQ: p_amqp_consume_binary() "
          "[E=%s RK=%s]\n",
          config.name, config.type, amqp_host->exchange,
          amqp_host->routing_key);
  }

  return SUCCESS;
}

void p_amqp_close(struct p_amqp_host* amqp_host, int set_fail) {
  if (amqp_host->conn) {
    if (amqp_get_socket(amqp_host->conn))
      amqp_connection_close(amqp_host->conn, AMQP_REPLY_SUCCESS);

    if (set_fail) {
      Log(LOG_ERR,
          "ERROR ( %s/%s ): Connection failed to RabbitMQ: p_amqp_close()\n",
          config.name, config.type);
      P_broker_timers_set_last_fail(&amqp_host->btimers, time(NULL));
    }
    amqp_destroy_connection(amqp_host->conn);
    amqp_host->conn = NULL;
  }
}

int p_amqp_is_alive(struct p_amqp_host* amqp_host) {
  if (amqp_host->status == AMQP_STATUS_OK && amqp_host->conn &&
      (amqp_get_sockfd(amqp_host->conn) >= 0))
    return SUCCESS;
  else
    return ERR;
}

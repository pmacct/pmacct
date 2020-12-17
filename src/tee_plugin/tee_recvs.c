/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2019 by Paolo Lucente
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

#include "pmacct.h"
#ifdef WITH_KAFKA
#include "kafka_common.h"
#endif
#ifdef WITH_ZMQ
#include "zmq_common.h"
#endif
#include "tee_plugin.h"
#include "tee_recvs.h"

int tee_recvs_map_id_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  struct tee_receivers *table = (struct tee_receivers *) req->key_value_table; 
  int pool_idx;
  u_int32_t pool_id;
  char *endptr = NULL;

  if (table && table->pools) {
    if (table->num < config.tee_max_receiver_pools) {
      pool_id = strtoull(value, &endptr, 10);

      if (!pool_id || pool_id > UINT32_MAX) {
        Log(LOG_ERR, "ERROR ( %s/%s ): [%s] Invalid Pool ID specified.\n", config.name, config.type, filename);
        return TRUE;
      }

      /* Ensure no pool ID duplicates */
      for (pool_idx = 0; pool_idx < table->num; pool_idx++) {
	if (pool_id == table->pools[table->num].id) {
	  Log(LOG_ERR, "ERROR ( %s/%s ): [%s] Duplicate Pool ID specified: %u.\n", config.name, config.type, filename, pool_id);
	  return TRUE;
	}
      }

      table->pools[table->num].id = pool_id;
    }
    else {
      Log(LOG_ERR, "ERROR ( %s/%s ): [%s] Maximum amount of receivers pool reached: %u.\n", config.name, config.type, filename, config.tee_max_receiver_pools);
      return TRUE;
    }
  }
  else {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] Receivers table not allocated.\n", config.name, config.type, filename);
    return TRUE;
  }

  return FALSE;
}

int tee_recvs_map_ip_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  struct tee_receivers *table = (struct tee_receivers *) req->key_value_table;
  struct tee_receiver *target = NULL;
  int recv_idx;
  char *str_ptr, *token;

  if (table && table->pools && table->pools[table->num].receivers) {
    str_ptr = value;
    recv_idx = 0;

    while ((token = extract_token(&str_ptr, ','))) {
      if (recv_idx < config.tee_max_receivers) {
	target = &table->pools[table->num].receivers[recv_idx];
	target->dest_len = sizeof(target->dest);
	if (!Tee_parse_hostport(token, (struct sockaddr *)&target->dest, &target->dest_len, FALSE)) recv_idx++;
	else Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Invalid receiver %s.\n",
		config.name, config.type, filename, token);
      }
      else {
	Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Maximum amount of receivers pool reached %u.\n",
		config.name, config.type, filename, config.tee_max_receiver_pools);
	break;
      }
    }

    if (!recv_idx) {
      Log(LOG_ERR, "ERROR ( %s/%s ): [%s] No valid receivers.\n", config.name, config.type, filename);
      return TRUE;
    }
    else table->pools[table->num].num = recv_idx;
  }
  else {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] Receivers table not allocated.\n", config.name, config.type, filename);
    return TRUE;
  }

  return FALSE;
}

int tee_recvs_map_tag_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  struct tee_receivers *table = (struct tee_receivers *) req->key_value_table;
  int ret;

  if (table && table->pools) ret = load_tags(filename, &table->pools[table->num].tag_filter, value);
  else {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] Receivers table not allocated.\n", config.name, config.type, filename);
    return TRUE;
  }

  if (!ret) return TRUE;
  else return FALSE;
}

int tee_recvs_map_balance_alg_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  struct tee_receivers *table = (struct tee_receivers *) req->key_value_table;

  if (table && table->pools) {
    if (!strncmp(value, "rr", 2)) {
      table->pools[table->num].balance.type = TEE_BALANCE_RR;
      table->pools[table->num].balance.func = Tee_rr_balance;
    }
    else if (!strncmp(value, "hash-agent", 10)) {
      table->pools[table->num].balance.type = TEE_BALANCE_HASH_AGENT;
      table->pools[table->num].balance.func = Tee_hash_agent_balance;
    }
	else if (!strncmp(value, "hash-crc32", 10)) {
      table->pools[table->num].balance.type = TEE_BALANCE_HASH_AGENT;
      table->pools[table->num].balance.func = Tee_hash_agent_crc32;
	}
    else if (!strncmp(value, "hash-tag", 8)) {
      table->pools[table->num].balance.type = TEE_BALANCE_HASH_TAG;
      table->pools[table->num].balance.func = Tee_hash_tag_balance;
    }
    else {
      table->pools[table->num].balance.func = NULL;
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Unknown balance algorithm '%s'. Ignoring.\n", config.name, config.type, filename, value);
    }
  }
  else {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] Receivers table not allocated.\n", config.name, config.type, filename);
    return TRUE;
  }

  return FALSE;
}

int tee_recvs_map_src_port_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  struct tee_receivers *table = (struct tee_receivers *) req->key_value_table;
  int port;

  if (table && table->pools) {
    port = atoi(value);

    if (port <= UINT16_MAX) table->pools[table->num].src_port = port; 
    else {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Invalid source port specified '%s'. Ignoring.\n", config.name, config.type, filename, value);
    }
  }
  else {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] Receivers table not allocated.\n", config.name, config.type, filename);
    return TRUE;
  }

  return FALSE;
}

#ifdef WITH_KAFKA
int tee_recvs_map_kafka_broker_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  struct tee_receivers *table = (struct tee_receivers *) req->key_value_table;

  if (table && table->pools) {
    int len = sizeof(table->pools[table->num].kafka_broker); 

    memset(table->pools[table->num].kafka_broker, 0, len);
    strlcpy(table->pools[table->num].kafka_broker, value, len);
    table->pools[table->num].kafka_broker[len] = '\0';
  }
  else {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] Receivers table not allocated.\n", config.name, config.type, filename);
    return TRUE;
  }

  return FALSE;
}

int tee_recvs_map_kafka_topic_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  struct tee_receivers *table = (struct tee_receivers *) req->key_value_table;

  if (table && table->pools) {
    int len = sizeof(table->pools[table->num].kafka_topic);

    memset(table->pools[table->num].kafka_topic, 0, len);
    strlcpy(table->pools[table->num].kafka_topic, value, len);
    table->pools[table->num].kafka_topic[len] = '\0';
  } 
  else {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] Receivers table not allocated.\n", config.name, config.type, filename);
    return TRUE;
  }

  return FALSE;
}
#endif

#ifdef WITH_ZMQ
int tee_recvs_map_zmq_address_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  struct tee_receivers *table = (struct tee_receivers *) req->key_value_table;

  if (table && table->pools) {
    int len = sizeof(table->pools[table->num].zmq_address);

    memset(table->pools[table->num].zmq_address, 0, len);
    strlcpy(table->pools[table->num].zmq_address, value, len);
    table->pools[table->num].zmq_address[len] = '\0';
  }
  else {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] Receivers table not allocated.\n", config.name, config.type, filename);
    return TRUE;
  }

  return FALSE;
}
#endif

void tee_recvs_map_validate(char *filename, int lineno, struct plugin_requests *req)
{
  struct tee_receivers *table = (struct tee_receivers *) req->key_value_table;
  int valid = FALSE, emit_methods = 0;

  if (table && table->pools && table->pools[table->num].receivers) {
    /* Check: emit to either IP address(es) or Kafka broker(s) or ZeroMQ queue */
    if (table->pools[table->num].num > 0) emit_methods++;
    if (strlen(table->pools[table->num].kafka_broker)) emit_methods++;
    if (strlen(table->pools[table->num].zmq_address)) emit_methods++;

    if (emit_methods > 1) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] 'ip', 'kafka_broker' and 'zmq_address' are mutual exclusive. Line ignored.\n",
	  config.name, config.type, filename, lineno);
      valid = FALSE;
      goto zero_entry;
    }

    if (!emit_methods) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] 'ip' or 'kafka_broker' or 'zmq_address' must be specified. Line ignored.\n",
	  config.name, config.type, filename, lineno);
      valid = FALSE;
      goto zero_entry;
    }

    /* Check: valid pool ID */
    if (table->pools[table->num].id > 0) valid = TRUE;
    else {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] Invalid pool 'id' specified. Line ignored.\n",
	  config.name, config.type, filename, lineno);
      valid = FALSE;
      goto zero_entry;
    }

    if (table->pools[table->num].num > 0) valid = TRUE;

    /*
       Check: if emitting to Kafka:
       a) make sure we have both broker string and topic,
       b) balance-alg is not set, tee_transparent is set to true
    */
#ifdef WITH_KAFKA
    if (strlen(table->pools[table->num].kafka_broker)) {
      if (!config.tee_transparent) {
	Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] tee_transparent must be set to 'true' when emitting to Kafka. Line ignored.\n",
	    config.name, config.type, filename, lineno);
	valid = FALSE;
	goto zero_entry;
      }

      if (table->pools[table->num].balance.func) {
	Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] 'balance-alg' is not compatible with emitting to Kafka. Line ignored.\n",
	    config.name, config.type, filename, lineno);
	valid = FALSE;
	goto zero_entry;
      }

      if (!strlen(table->pools[table->num].kafka_topic)) {
	Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] 'kafka_topic' missing. Line ignored.\n",
	    config.name, config.type, filename, lineno);
	valid = FALSE;
	goto zero_entry;
      }

      valid = TRUE;
    }
#endif

    /*
       Check: if emitting via ZeroMQ:
       a) make sure we have an address string,
       b) balance-alg is not set, tee_transparent is set to true
    */
#ifdef WITH_ZMQ
    if (strlen(table->pools[table->num].zmq_address)) {
      if (!config.tee_transparent) {
	Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] tee_transparent must be set to 'true' when emitting via ZeroMQ. Line ignored.\n",
	    config.name, config.type, filename, lineno);
	valid = FALSE;
	goto zero_entry;
      }

      if (table->pools[table->num].balance.func) {
	Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] 'balance-alg' is not compatible with emitting via ZeroMQ. Line ignored.\n",
	    config.name, config.type, filename, lineno);
	valid = FALSE;
	goto zero_entry;
      }

      valid = TRUE;
    }
#endif

    if (valid) table->num++;
    else {
      zero_entry:

      table->pools[table->num].id = 0;
      table->pools[table->num].num = 0;
      table->pools[table->num].src_port = 0;
      memset(table->pools[table->num].receivers, 0, config.tee_max_receivers*sizeof(struct tee_receiver));
      memset(&table->pools[table->num].tag_filter, 0, sizeof(struct pretag_filter));
      memset(&table->pools[table->num].balance, 0, sizeof(struct tee_balance));

#ifdef WITH_KAFKA
      memset(&table->pools[table->num].kafka_host, 0, sizeof(struct p_kafka_host));
      memset(&table->pools[table->num].kafka_broker, 0, sizeof(table->pools[table->num].kafka_broker));
      memset(&table->pools[table->num].kafka_topic, 0, sizeof(table->pools[table->num].kafka_topic));
#endif

#ifdef WITH_ZMQ
      memset(&table->pools[table->num].zmq_host, 0, sizeof(struct p_zmq_host));
      memset(&table->pools[table->num].zmq_address, 0, sizeof(table->pools[table->num].zmq_address));
#endif
    }
  }
}

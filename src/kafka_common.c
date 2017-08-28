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

#define __KAFKA_COMMON_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "kafka_common.h"

/* Functions */
void p_kafka_init_host(struct p_kafka_host *kafka_host, char *config_file)
{
  if (kafka_host) {
    memset(kafka_host, 0, sizeof(struct p_kafka_host));
    P_broker_timers_set_retry_interval(&kafka_host->btimers, PM_KAFKA_DEFAULT_RETRY);
    p_kafka_set_config_file(kafka_host, config_file);

    kafka_host->cfg = rd_kafka_conf_new();
    if (kafka_host->cfg) {
      rd_kafka_conf_set_log_cb(kafka_host->cfg, p_kafka_logger);
      rd_kafka_conf_set_error_cb(kafka_host->cfg, p_kafka_msg_error);
      rd_kafka_conf_set_dr_cb(kafka_host->cfg, p_kafka_msg_delivered);
      rd_kafka_conf_set_opaque(kafka_host->cfg, kafka_host);
      p_kafka_apply_global_config(kafka_host);

      if (config.debug) {
	const char **res;
	size_t res_len, idx;

	res = rd_kafka_conf_dump(kafka_host->cfg, &res_len);
	for (idx = 0; idx < res_len; idx += 2)
	  Log(LOG_DEBUG, "DEBUG ( %s/%s ): librdkafka global config: %s = %s\n", config.name, config.type, res[idx], res[idx + 1]);

	rd_kafka_conf_dump_free(res, res_len);
      }
    }
  }
}

void p_kafka_unset_topic(struct p_kafka_host *kafka_host)
{
  if (kafka_host && kafka_host->topic) {
    rd_kafka_topic_destroy(kafka_host->topic);
    kafka_host->topic = NULL;
  }
}

void p_kafka_set_topic(struct p_kafka_host *kafka_host, char *topic)
{
  if (kafka_host) {
    kafka_host->topic_cfg = rd_kafka_topic_conf_new();
    p_kafka_apply_topic_config(kafka_host);

    if (config.debug) {
      const char **res;
      size_t res_len, idx;

      res = rd_kafka_topic_conf_dump(kafka_host->topic_cfg, &res_len);
      for (idx = 0; idx < res_len; idx += 2)
        Log(LOG_DEBUG, "DEBUG ( %s/%s ): librdkafka '%s' topic config: %s = %s\n", config.name, config.type, topic, res[idx], res[idx + 1]);

      rd_kafka_conf_dump_free(res, res_len);
    }

    /* destroy current allocation before making a new one */
    if (kafka_host->topic) p_kafka_unset_topic(kafka_host);

    if (kafka_host->rk && kafka_host->topic_cfg) {
      kafka_host->topic = rd_kafka_topic_new(kafka_host->rk, topic, kafka_host->topic_cfg);
      kafka_host->topic_cfg = NULL; /* rd_kafka_topic_new() destroys conf as per rdkafka.h */
    }
  }
}

char *p_kafka_get_topic(struct p_kafka_host *kafka_host)
{
  if (kafka_host && kafka_host->topic) return rd_kafka_topic_name(kafka_host->topic);

  return NULL;
}

/* XXX: is round-robin feature overlapping with kafka partitions? */
void p_kafka_init_topic_rr(struct p_kafka_host *kafka_host)
{
  if (kafka_host) memset(&kafka_host->topic_rr, 0, sizeof(struct p_table_rr));
}

void p_kafka_set_topic_rr(struct p_kafka_host *kafka_host, int topic_rr)
{
  if (kafka_host) kafka_host->topic_rr.max = topic_rr;
}

int p_kafka_get_topic_rr(struct p_kafka_host *kafka_host)
{
  if (kafka_host) return kafka_host->topic_rr.max;

  return FALSE;
}

void p_kafka_set_broker(struct p_kafka_host *kafka_host, char *host, int port)
{
  int ret, multiple_brokers = FALSE;

  if (strchr(host, ',')) multiple_brokers = TRUE;

  if (kafka_host && kafka_host->rk) {
    /* if host is a comma-separated list of brokers, assume port is part of the definition */
    if (multiple_brokers) snprintf(kafka_host->broker, SRVBUFLEN, "%s", host);
    else {
      if (host && port) snprintf(kafka_host->broker, SRVBUFLEN, "%s:%u", host, port);
    }

    if ((ret = rd_kafka_brokers_add(kafka_host->rk, kafka_host->broker)) == 0) {
      Log(LOG_WARNING, "WARN ( %s/%s ): Invalid 'kafka_broker_host' or 'kafka_broker_port' specified (%s).\n",
	  config.name, config.type, kafka_host->broker);
    }
    else Log(LOG_DEBUG, "DEBUG ( %s/%s ): %u broker(s) successfully added.\n", config.name, config.type, ret); 
  }
}

void p_kafka_set_content_type(struct p_kafka_host *kafka_host, int content_type)
{
  if (kafka_host) kafka_host->content_type = content_type;
}

int p_kafka_get_content_type(struct p_kafka_host *kafka_host)
{
  if (kafka_host) return kafka_host->content_type;

  return FALSE;
}

void p_kafka_set_partition(struct p_kafka_host *kafka_host, int partition)
{
  if (kafka_host) {
    if (!partition) kafka_host->partition = RD_KAFKA_PARTITION_UA; 
    else if (partition == FALSE_NONZERO) kafka_host->partition = 0;
    else kafka_host->partition = partition;
  }
}

int p_kafka_get_partition(struct p_kafka_host *kafka_host)
{
  if (kafka_host) return kafka_host->partition;

  return FALSE;
}

void p_kafka_set_key(struct p_kafka_host *kafka_host, char *key, int key_len)
{
  if (kafka_host) {
    kafka_host->key = key;
    kafka_host->key_len = key_len;
  }
}

char *p_kafka_get_key(struct p_kafka_host *kafka_host)
{
  if (kafka_host) return kafka_host->key;

  return NULL;
}

void p_kafka_set_fallback(struct p_kafka_host *kafka_host, char *fallback)
{
  int res;
  char errstr[SRVBUFLEN];

  if (kafka_host && kafka_host->cfg && fallback) {
    res = rd_kafka_conf_set(kafka_host->cfg, "api.version.request", "false", errstr, sizeof(errstr));
    if (res != RD_KAFKA_CONF_OK)
      Log(LOG_WARNING, "WARN ( %s/%s ): p_kafka_set_fallback(): api.version.request=false failed: %s\n",
	  config.name, config.type, errstr);

    res = rd_kafka_conf_set(kafka_host->cfg, "broker.version.fallback", fallback, errstr, sizeof(errstr));
    if (res != RD_KAFKA_CONF_OK)
      Log(LOG_WARNING, "WARN ( %s/%s ): p_kafka_set_fallback(): broker.version.fallback=%s failed: %s\n",
	  config.name, config.type, fallback, errstr);
  }
}

void p_kafka_set_config_file(struct p_kafka_host *kafka_host, char *config_file)
{
  if (kafka_host) {
    kafka_host->config_file = config_file;
  }
}

void p_kafka_get_version()
{
  printf("rdkafka %s\n", rd_kafka_version_str());
}

int p_kafka_parse_config_entry(char *buf, char *type, char **key, char **value)
{
  char *value_ptr, *token;
  int index, type_match = FALSE;

  if (buf && type && key && value) {
    value_ptr = buf;
    (*key) = NULL;
    (*value) = NULL;
    index = 0;

    while (token = extract_token(&value_ptr, ',')) {
      index++;
      trim_spaces(token);

      if (index == 1) {
	lower_string(token);
	if (!strcmp(token, type)) type_match = TRUE;
	else break;
      }
      else if (index == 2) {
	(*key) = token;
	break;
      }
    }

    if (strlen(value_ptr)) {
      trim_spaces(value_ptr);
      (*value) = value_ptr;
      index++;
    }

    if (type_match && index != 3) return ERR;
  }
  else return ERR;

  return type_match;
}

void p_kafka_apply_global_config(struct p_kafka_host *kafka_host)
{
  FILE *file;
  char buf[SRVBUFLEN], errstr[SRVBUFLEN], *key, *value;
  int lineno = 1, ret;

  if (kafka_host && kafka_host->config_file && kafka_host->cfg) {
    if ((file = fopen(kafka_host->config_file, "r")) == NULL) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] file not found. librdkafka global config not loaded.\n", config.name, config.type, kafka_host->config_file);
      return;
    }
    else Log(LOG_INFO, "INFO ( %s/%s ): [%s] Reading librdkafka global config.\n", config.name, config.type, kafka_host->config_file);

    while (!feof(file)) {
      if (fgets(buf, SRVBUFLEN, file)) {
	if ((ret = p_kafka_parse_config_entry(buf, "global", &key, &value)) > 0) {
	  ret = rd_kafka_conf_set(kafka_host->cfg, key, value, errstr, sizeof(errstr));
	  if (ret != RD_KAFKA_CONF_OK) {
	    Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] key=%s value=%s failed: %s\n",
		config.name, config.type, kafka_host->config_file, lineno, key, value, errstr);
	  }
        }
	else {
	  if (ret == ERR) {
	    Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] Line malformed. Ignored.", config.name, config.type, kafka_host->config_file, lineno);
	    continue;
	  }
	}
      }

      lineno++;
    }

    fclose(file);
  }
}

void p_kafka_apply_topic_config(struct p_kafka_host *kafka_host)
{
  FILE *file;
  char buf[SRVBUFLEN], errstr[SRVBUFLEN], *key, *value;
  int lineno = 1, ret;

  if (kafka_host && kafka_host->config_file && kafka_host->topic_cfg) {
    if ((file = fopen(kafka_host->config_file, "r")) == NULL) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] file not found. librdkafka topic configuration not loaded.\n", config.name, config.type, kafka_host->config_file);
      return;
    }
    else Log(LOG_INFO, "INFO ( %s/%s ): [%s] Reading librdkafka topic configuration.\n", config.name, config.type, kafka_host->config_file);

    while (!feof(file)) {
      if (fgets(buf, SRVBUFLEN, file)) {
        if ((ret = p_kafka_parse_config_entry(buf, "topic", &key, &value)) > 0) {
          ret = rd_kafka_topic_conf_set(kafka_host->topic_cfg, key, value, errstr, sizeof(errstr));
          if (ret != RD_KAFKA_CONF_OK) {
            Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] key=%s value=%s failed: %s\n",
                config.name, config.type, kafka_host->config_file, lineno, key, value, errstr);
          }
        }
        else {
          if (ret == ERR) {
            Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] Line malformed. Ignored.", config.name, config.type, kafka_host->config_file, lineno);
            continue;
          }
        }
      }

      lineno++;
    }

    fclose(file);
  }
}

void p_kafka_logger(const rd_kafka_t *rk, int level, const char *fac, const char *buf)
{
  struct timeval tv;

  gettimeofday(&tv, NULL);

  Log(LOG_DEBUG, "DEBUG ( %s/%s ): RDKAFKA-%i-%s: %s: %s\n", config.name, config.type, level, fac, rd_kafka_name(rk), buf);
}

void p_kafka_msg_delivered(rd_kafka_t *rk, void *payload, size_t len, int error_code, void *opaque, void *msg_opaque)
{
  struct p_kafka_host *kafka_host = (struct p_kafka_host *) opaque; 

  if (error_code) {
    Log(LOG_ERR, "ERROR ( %s/%s ): Kafka message delivery failed: %s\n", config.name, config.type, rd_kafka_err2str(error_code));
  }
  else {
    if (config.debug) {
      if (p_kafka_get_content_type(kafka_host) == PM_KAFKA_CNT_TYPE_STR) {
        char *payload_str = (char *) payload;
	char saved = payload_str[len];

	payload_str[len] = '\0';
        Log(LOG_DEBUG, "DEBUG ( %s/%s ): Kafka message delivery successful (%zd bytes): %s\n", config.name, config.type, len, payload);
	payload_str[len] = saved;
      }
      else {
	Log(LOG_DEBUG, "DEBUG ( %s/%s ): Kafka message delivery successful (%zd bytes)\n", config.name, config.type, len);
      }
    }
  }
}

void p_kafka_msg_error(rd_kafka_t *rk, int err, const char *reason, void *opaque)
{
  kafkap_ret_err_cb = ERR;
}

int p_kafka_connect_to_produce(struct p_kafka_host *kafka_host)
{
  if (kafka_host) {
    kafka_host->rk = rd_kafka_new(RD_KAFKA_PRODUCER, kafka_host->cfg, kafka_host->errstr, sizeof(kafka_host->errstr));
    if (!kafka_host->rk) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Failed to create new Kafka producer: %s\n", config.name, config.type, kafka_host->errstr);
      p_kafka_close(kafka_host, TRUE);
      return ERR;
    }

    if (config.debug) rd_kafka_set_log_level(kafka_host->rk, LOG_DEBUG);
  }
  else return ERR;

  return SUCCESS;
}

int p_kafka_produce_data(struct p_kafka_host *kafka_host, void *data, u_int32_t data_len)
{
  int ret = SUCCESS;

  kafkap_ret_err_cb = FALSE;

  if (kafka_host && kafka_host->rk && kafka_host->topic) {
    ret = rd_kafka_produce(kafka_host->topic, kafka_host->partition, RD_KAFKA_MSG_F_COPY,
			   data, data_len, kafka_host->key, kafka_host->key_len, NULL);

    if (ret == ERR) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Failed to produce to topic %s partition %i: %s\n", config.name, config.type,
          rd_kafka_topic_name(kafka_host->topic), kafka_host->partition, rd_kafka_err2str(rd_kafka_errno2err(errno)));
      p_kafka_close(kafka_host, TRUE);
    }
  }
  else return ERR;

  rd_kafka_poll(kafka_host->rk, 0);

  return ret; 
}

void p_kafka_close(struct p_kafka_host *kafka_host, int set_fail)
{
  if (kafka_host && !validate_truefalse(set_fail)) { 
    if (set_fail) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Connection failed to Kafka: p_kafka_close()\n", config.name, config.type);
      P_broker_timers_set_last_fail(&kafka_host->btimers, time(NULL));
    }
    else {
      /* Wait for messages to be delivered */
      if (kafka_host->rk) p_kafka_check_outq_len(kafka_host);
    }

    if (kafka_host->topic) {
      rd_kafka_topic_destroy(kafka_host->topic);
      kafka_host->topic = NULL;
    }

    if (kafka_host->rk) {
      rd_kafka_destroy(kafka_host->rk);
      kafka_host->rk = NULL;
    }
  }
}

int p_kafka_check_outq_len(struct p_kafka_host *kafka_host)
{
  int outq_len = 0, old_outq_len = 0;

  if (kafka_host->rk) {
    while ((outq_len = rd_kafka_outq_len(kafka_host->rk)) > 0) {
      if (!old_outq_len) {
	old_outq_len = outq_len;
      }
      else {
        if (outq_len == old_outq_len) {
	  Log(LOG_ERR, "ERROR ( %s/%s ): Connection failed to Kafka: p_kafka_check_outq_len()\n", config.name, config.type);
          p_kafka_close(kafka_host, TRUE);
	  return outq_len; 
	}
      }

      rd_kafka_poll(kafka_host->rk, 100);
      sleep(1);
    }
  }
  else return ERR;

  return SUCCESS;
}

#if defined WITH_JANSSON
int write_and_free_json_kafka(void *kafka_log, void *obj)
{
  char *orig_kafka_topic = NULL, dyn_kafka_topic[SRVBUFLEN];
  struct p_kafka_host *alog = (struct p_kafka_host *) kafka_log;
  int ret = ERR;

  char *tmpbuf = NULL;
  json_t *json_obj = (json_t *) obj;

  tmpbuf = json_dumps(json_obj, JSON_PRESERVE_ORDER);
  json_decref(json_obj);

  if (tmpbuf) {
    if (alog->topic_rr.max) {
      orig_kafka_topic = p_kafka_get_topic(alog);
      P_handle_table_dyn_rr(dyn_kafka_topic, SRVBUFLEN, orig_kafka_topic, &alog->topic_rr);
      p_kafka_set_topic(alog, dyn_kafka_topic);
    }

    ret = p_kafka_produce_data(alog, tmpbuf, strlen(tmpbuf));
    free(tmpbuf);

    if (alog->topic_rr.max) p_kafka_set_topic(alog, orig_kafka_topic);
  }

  return ret;
}
#else
int write_and_free_json_kafka(void *kafka_log, void *obj)
{
  if (config.debug) Log(LOG_DEBUG, "DEBUG ( %s/%s ): write_and_free_json_kafka(): JSON object not created due to missing --enable-jansson\n", config.name, config.type);
}
#endif

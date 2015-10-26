/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2015 by Paolo Lucente
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
void p_kafka_init_host(struct p_kafka_host *kafka_host)
{
  if (kafka_host) {
    memset(kafka_host, 0, sizeof(struct p_kafka_host));
    P_broker_timers_set_retry_interval(&kafka_host->btimers, PM_KAFKA_DEFAULT_RETRY);

    kafka_host->cfg = rd_kafka_conf_new();
    if (kafka_host->cfg) {
      rd_kafka_conf_set_error_cb(kafka_host->cfg, p_kafka_msg_error);
      rd_kafka_conf_set_dr_cb(kafka_host->cfg, p_kafka_msg_delivered);
      rd_kafka_conf_set_opaque(kafka_host->cfg, kafka_host);
    }
  }
}

void p_kafka_set_topic(struct p_kafka_host *kafka_host, char *topic)
{
  if (kafka_host) {
    kafka_host->topic_cfg = rd_kafka_topic_conf_new();

    if (kafka_host->rk && kafka_host->topic_cfg) {
      kafka_host->topic = rd_kafka_topic_new(kafka_host->rk, topic, kafka_host->topic_cfg);
    }
  }
}

void p_kafka_unset_topic(struct p_kafka_host *kafka_host)
{
  if (kafka_host) {
    if (kafka_host->topic_cfg) rd_kafka_topic_conf_destroy(kafka_host->topic_cfg);
    if (kafka_host->topic) rd_kafka_topic_destroy(kafka_host->topic); 
  }
}

char *p_kafka_get_topic(struct p_kafka_host *kafka_host)
{
  if (kafka_host && kafka_host->topic) return rd_kafka_topic_name(kafka_host->topic);

  return NULL;
}

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
  if (kafka_host && kafka_host->rk) {
    if (host && port) snprintf(kafka_host->broker, SRVBUFLEN, "%s:%u", host, port);

    if (rd_kafka_brokers_add(kafka_host->rk, kafka_host->broker) == 0) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Invalid 'kafka_broker_host' or 'kafka_broker_port' specified (%s). Exiting.\n",
	  config.name, config.type, kafka_host->broker);
      exit_plugin(1);
    }
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

void p_kafka_logger(const rd_kafka_t *rk, int level, const char *fac, const char *buf)
{
  struct timeval tv;

  gettimeofday(&tv, NULL);

  Log(LOG_DEBUG, "DEBUG ( %s/%s ): %u.%03u RDKAFKA-%i-%s: %s: %s\n", config.name, config.type, (int)tv.tv_sec,
	(int)(tv.tv_usec / 1000), level, fac, rd_kafka_name(rk), buf);
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

    rd_kafka_set_logger(kafka_host->rk, p_kafka_logger);
    if (config.debug) rd_kafka_set_log_level(kafka_host->rk, LOG_DEBUG);
  }

  return SUCCESS;
}

int p_kafka_produce_string(struct p_kafka_host *kafka_host, char *json_str)
{
  int ret;

  kafkap_ret_err_cb = FALSE;

  if (kafka_host && kafka_host->rk && kafka_host->topic) {
    ret = rd_kafka_produce(kafka_host->topic, kafka_host->partition, RD_KAFKA_MSG_F_COPY,
			   json_str, strlen(json_str), NULL, 0, NULL);

    /* Poll to handle delivery reports; timeout_ms set to minimum possible blocking value */
    rd_kafka_poll(kafka_host->rk, 1);
    if (ret == ERR || kafkap_ret_err_cb == ERR) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Failed to produce to topic %s partition %i: %s\n", config.name, config.type,
          rd_kafka_topic_name(kafka_host->topic), kafka_host->partition, rd_kafka_err2str(rd_kafka_errno2err(errno)));
      p_kafka_close(kafka_host, TRUE);
      return ERR;
    }
  }
  else return ERR;

  return SUCCESS; 
}

void p_kafka_close(struct p_kafka_host *kafka_host, int set_fail)
{
  if (kafka_host) { 
    if (set_fail) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Connection failed to Kafka: p_kafka_close()\n", config.name, config.type);
      P_broker_timers_set_last_fail(&kafka_host->btimers, time(NULL));
    }
    else {
      /* Wait for messages to be delivered */
      if (kafka_host->rk) while (rd_kafka_outq_len(kafka_host->rk) > 0) rd_kafka_poll(kafka_host->rk, 100);
    }

    if (kafka_host->topic) rd_kafka_topic_destroy(kafka_host->topic);
    if (kafka_host->rk) rd_kafka_destroy(kafka_host->rk);
  }
}

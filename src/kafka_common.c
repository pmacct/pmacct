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
    kafka_host->cfg = rd_kafka_conf_new();
    p_kafka_set_retry_interval(kafka_host, PM_KAFKA_DEFAULT_RETRY);
  }
}

void p_kafka_set_retry_interval(struct p_kafka_host *kafka_host, int interval)
{
  if (kafka_host) kafka_host->retry_interval = interval;
}

int p_kafka_get_retry_interval(struct p_kafka_host *kafka_host)
{
  if (kafka_host) return kafka_host->retry_interval;

  return ERR;
}

void p_kafka_set_topic(struct p_kafka_host *kafka_host, char *topic)
{
  if (kafka_host && kafka_host->rk) {
    kafka_host->topic_cfg = rd_kafka_topic_conf_new();
    rd_kafka_topic_new(kafka_host->rk, topic, kafka_host->topic_cfg);
  }
}

void p_kafka_unset_topic(struct p_kafka_host *kafka_host)
{
  if (kafka_host && kafka_host->rk) {
    rd_kafka_topic_conf_destroy(kafka_host->topic_cfg);
    rd_kafka_topic_destroy(kafka_host->topic); 
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

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

#ifndef KAFKA_COMMON_H
#define KAFKA_COMMON_H


/* includes */
#include <librdkafka/rdkafka.h>
#include "plugin_common.h"
#ifdef WITH_SERDES
#include <libserdes/serdes-avro.h>
#endif

/* defines */
#define PM_KAFKA_ERRSTR_LEN		512
#define PM_KAFKA_DEFAULT_RETRY		60
#define PM_KAFKA_LONGLONG_RETRY		INT_MAX
#define PM_KAFKA_OUTQ_LEN_RETRIES	3

#define PM_KAFKA_CNT_TYPE_STR		1
#define PM_KAFKA_CNT_TYPE_BIN		2

/* structures */
struct p_kafka_host {
  char broker[SRVBUFLEN];
  char errstr[PM_KAFKA_ERRSTR_LEN];
  u_int8_t content_type;

  rd_kafka_t *rk;
  rd_kafka_conf_t *cfg;
  rd_kafka_topic_t *topic;
  rd_kafka_topic_conf_t *topic_cfg;
  char *config_file;
  int partition;
  char *key;
  int key_len;
  struct p_table_rr topic_rr;

#ifdef WITH_SERDES
  serdes_schema_t *sd_schema[MAX_AVRO_SCHEMA];
#endif

  struct p_broker_timers btimers;
};

/* prototypes */
extern void p_kafka_init_host(struct p_kafka_host *, char *);
extern void p_kafka_init_topic_rr(struct p_kafka_host *);

extern void p_kafka_set_broker(struct p_kafka_host *, char *, int);
extern void p_kafka_set_topic(struct p_kafka_host *, char *);
extern void p_kafka_set_topic_rr(struct p_kafka_host *, int);
extern void p_kafka_set_content_type(struct p_kafka_host *, int);
extern void p_kafka_set_partition(struct p_kafka_host *, int);
extern void p_kafka_set_key(struct p_kafka_host *, char *, int);
extern void p_kafka_set_config_file(struct p_kafka_host *, char *);

extern rd_kafka_t *p_kafka_get_handler(struct p_kafka_host *);
extern char *p_kafka_get_broker(struct p_kafka_host *);
extern char *p_kafka_get_topic(struct p_kafka_host *);
extern int p_kafka_get_topic_rr(struct p_kafka_host *);
extern int p_kafka_get_content_type(struct p_kafka_host *);
extern int p_kafka_get_partition(struct p_kafka_host *);
extern void p_kafka_set_dynamic_partitioner(struct p_kafka_host *);
extern char *p_kafka_get_key(struct p_kafka_host *);
extern void p_kafka_get_version();

extern void p_kafka_unset_topic(struct p_kafka_host *);

extern int p_kafka_parse_config_entry(char *, char *, char **, char **);
extern void p_kafka_apply_global_config(struct p_kafka_host *);
extern void p_kafka_apply_topic_config(struct p_kafka_host *);

extern void p_kafka_logger(const rd_kafka_t *, int, const char *, const char *);
extern void p_kafka_msg_delivered(rd_kafka_t *, void *, size_t, int, void *, void *);
extern void p_kafka_msg_error(rd_kafka_t *, int, const char *, void *);
extern int p_kafka_stats(rd_kafka_t *, char *, size_t, void *);

extern int p_kafka_connect_to_produce(struct p_kafka_host *);
extern int p_kafka_produce_data(struct p_kafka_host *, void *, size_t);
extern int p_kafka_produce_data_to_part(struct p_kafka_host *, void *, size_t, int);

extern int p_kafka_connect_to_consume(struct p_kafka_host *);
extern int p_kafka_manage_consumer(struct p_kafka_host *, int);
extern int p_kafka_consume_poller(struct p_kafka_host *, void **, int);
extern int p_kafka_consume_data(struct p_kafka_host *, void *, u_char *, size_t);

extern void p_kafka_close(struct p_kafka_host *, int);
extern int p_kafka_check_outq_len(struct p_kafka_host *);

extern int write_and_free_json_kafka(void *, void *);
extern int write_binary_kafka(void *, void *, size_t);

/* global vars */
extern struct p_kafka_host kafkap_kafka_host;
extern struct p_kafka_host bgp_daemon_msglog_kafka_host;
extern struct p_kafka_host bgp_table_dump_kafka_host;
extern struct p_kafka_host bmp_daemon_msglog_kafka_host;
extern struct p_kafka_host bmp_dump_kafka_host;
extern struct p_kafka_host sfacctd_counter_kafka_host;
extern struct p_kafka_host telemetry_kafka_host;
extern struct p_kafka_host telemetry_daemon_msglog_kafka_host;
extern struct p_kafka_host telemetry_dump_kafka_host;
extern struct p_kafka_host nfacctd_kafka_host;

extern int kafkap_ret_err_cb;
extern int dyn_partition_key;

extern char default_kafka_broker_host[];
extern int default_kafka_broker_port;
extern char default_kafka_topic[];
#endif //KAFKA_COMMON_H

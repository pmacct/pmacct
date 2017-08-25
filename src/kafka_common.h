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

/* includes */
#include <librdkafka/rdkafka.h>
#define __PLUGIN_COMMON_EXPORT
#include "plugin_common.h"
#undef  __PLUGIN_COMMON_EXPORT

/* defines */
#define PM_KAFKA_ERRSTR_LEN	512
#define PM_KAFKA_DEFAULT_RETRY	60
#define PM_KAFKA_LONGLONG_RETRY	INT_MAX

#define PM_KAFKA_CNT_TYPE_STR	1
#define PM_KAFKA_CNT_TYPE_BIN	2

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

  struct p_broker_timers btimers;
};

/* prototypes */
#if (!defined __KAFKA_COMMON_C)
#define EXT extern
#else
#define EXT
#endif
EXT void p_kafka_init_host(struct p_kafka_host *, char *);
EXT void p_kafka_init_topic_rr(struct p_kafka_host *);

EXT void p_kafka_set_broker(struct p_kafka_host *, char *, int);
EXT void p_kafka_set_topic(struct p_kafka_host *, char *);
EXT void p_kafka_set_topic_rr(struct p_kafka_host *, int);
EXT void p_kafka_set_content_type(struct p_kafka_host *, int);
EXT void p_kafka_set_partition(struct p_kafka_host *, int);
EXT void p_kafka_set_key(struct p_kafka_host *, char *, int);
EXT void p_kafka_set_fallback(struct p_kafka_host *, char *);
EXT void p_kafka_set_config_file(struct p_kafka_host *, char *);

EXT char *p_kafka_get_topic(struct p_kafka_host *);
EXT int p_kafka_get_topic_rr(struct p_kafka_host *);
EXT int p_kafka_get_content_type(struct p_kafka_host *);
EXT int p_kafka_get_partition(struct p_kafka_host *);
EXT char *p_kafka_get_key(struct p_kafka_host *);
EXT void p_kafka_get_version();

EXT void p_kafka_unset_topic(struct p_kafka_host *);

EXT int p_kafka_parse_config_entry(char *, char *, char **, char **);
EXT void p_kafka_apply_global_config(struct p_kafka_host *);
EXT void p_kafka_apply_topic_config(struct p_kafka_host *);

EXT void p_kafka_logger(const rd_kafka_t *, int, const char *, const char *);
EXT void p_kafka_msg_delivered(rd_kafka_t *, void *, size_t, int, void *, void *);
EXT void p_kafka_msg_error(rd_kafka_t *, int, const char *, void *);
EXT int p_kafka_connect_to_produce(struct p_kafka_host *);
EXT int p_kafka_produce_data(struct p_kafka_host *, void *, u_int32_t);
EXT void p_kafka_close(struct p_kafka_host *, int);
EXT int p_kafka_check_outq_len(struct p_kafka_host *);

EXT int write_and_free_json_kafka(void *, void *);

/* global vars */
EXT struct p_kafka_host kafkap_kafka_host;
EXT struct p_kafka_host bgp_daemon_msglog_kafka_host;
EXT struct p_kafka_host bgp_table_dump_kafka_host;
EXT struct p_kafka_host bmp_daemon_msglog_kafka_host;
EXT struct p_kafka_host bmp_dump_kafka_host;
EXT struct p_kafka_host sfacctd_counter_kafka_host;
EXT struct p_kafka_host telemetry_daemon_msglog_kafka_host;
EXT struct p_kafka_host telemetry_dump_kafka_host;

EXT int kafkap_ret_err_cb;

static char default_kafka_broker_host[] = "127.0.0.1";
static int default_kafka_broker_port = 9092;
static int default_kafka_partition = RD_KAFKA_PARTITION_UA;
static char default_kafka_topic[] = "pmacct.acct";
#undef EXT

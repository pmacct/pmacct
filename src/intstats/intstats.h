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

#include <pthread.h>

/* defines */
#define STATS_REFRESH_TIME_DEFAULT  60
#define STATS_SRC_PORT_DEFAULT      8124
#define STATS_DST_HOST_DEFAULT      "127.0.0.1"
#define STATS_DST_PORT_DEFAULT      8125

#define STATS_TYPE_INT              0
#define STATS_TYPE_LONGINT          1
#define STATS_TYPE_FLOAT            2
#define STATS_TYPE_STRING           3

#define STATSD_FMT_COUNTER    0
#define STATSD_FMT_GAUGE      1
#define STATSD_FMT_SAMPLING   2
#define STATSD_FMT_TIMING     3

#define STATS_LABEL_LEN	     128

struct intstats_data {
  int is_thread;
  char *log_str;
  time_t now;
};

struct metric_type {
  char label[STATS_LABEL_LEN];
  int type;
  int statsd_fmt; /* counter, gauge, etc */
  u_int64_t id;
  int plugin_id;
};

struct metric {
  struct metric_type type;
  union {
    int int_value;
    u_int64_t long_value;
    float float_value;
    char *string_value;
  };
  struct metric *next;
};

struct active_thread {
  pthread_t *thread;
  struct active_thread *next;
};

static const struct metric_type _metrics_types_matrix[] = {
 { "plugin_queues_total_size", STATS_TYPE_INT, STATSD_FMT_COUNTER, METRICS_INT_PLUGIN_QUEUES_TOT_SZ, PLUGIN_ID_CORE},
 { "plugin_queues_used_size", STATS_TYPE_INT, STATSD_FMT_COUNTER, METRICS_INT_PLUGIN_QUEUES_USED_SZ, PLUGIN_ID_CORE},
 { "plugin_queues_used_count", STATS_TYPE_INT, STATSD_FMT_COUNTER, METRICS_INT_PLUGIN_QUEUES_USED_CNT, PLUGIN_ID_CORE},
 { "plugin_queues_fill_rate", STATS_TYPE_FLOAT, STATSD_FMT_GAUGE, METRICS_INT_PLUGIN_QUEUES_FILL_RATE, PLUGIN_ID_CORE},
 { "nfacctd_received_packets", STATS_TYPE_INT, STATSD_FMT_COUNTER, METRICS_INT_NFACCTD_RCV_PKT, PLUGIN_ID_CORE},
 { "nfacctd_templates_count", STATS_TYPE_INT, STATSD_FMT_COUNTER, METRICS_INT_NFACCTD_TPL_CNT, PLUGIN_ID_CORE},
 { "nfacctd_udp_tx_queue", STATS_TYPE_INT, STATSD_FMT_COUNTER, METRICS_INT_NFACCTD_UDP_TX_QUEUE, PLUGIN_ID_CORE},
 { "nfacctd_udp_rx_queue", STATS_TYPE_INT, STATSD_FMT_COUNTER, METRICS_INT_NFACCTD_UDP_RX_QUEUE, PLUGIN_ID_CORE},
 { "nfacctd_udp_app_drop_count", STATS_TYPE_INT, STATSD_FMT_COUNTER, METRICS_INT_NFACCTD_UDP_APP_DROP_CNT, PLUGIN_ID_CORE},
 { "nfacctd_udp_sock_drop_count", STATS_TYPE_INT, STATSD_FMT_COUNTER, METRICS_INT_NFACCTD_UDP_SOCK_DROP_CNT, PLUGIN_ID_CORE},
 { "kafka_flush_count", STATS_TYPE_INT, STATSD_FMT_GAUGE, METRICS_INT_KAFKA_FLUSH_CNT, PLUGIN_ID_KAFKA},
 { "kafka_flush_msg_sent", STATS_TYPE_INT, STATSD_FMT_COUNTER, METRICS_INT_KAFKA_FLUSH_MSG_SENT, PLUGIN_ID_KAFKA},
 { "kafka_flush_msg_err", STATS_TYPE_INT, STATSD_FMT_COUNTER, METRICS_INT_KAFKA_FLUSH_MSG_ERR, PLUGIN_ID_KAFKA},
 { "kafka_flush_time", STATS_TYPE_INT, STATSD_FMT_TIMING, METRICS_INT_KAFKA_FLUSH_TIME, PLUGIN_ID_KAFKA},
 { "", -1, -1, -1, PLUGIN_ID_UNKNOWN}
};

/* functions */
#if (!defined __INTSTATSD_C)
#define EXT extern
#else
#define EXT
#endif
EXT void intstats_wrapper();
EXT void intstats_daemon(void *);
EXT void intstats_prepare_thread(struct intstats_data *);

EXT void insert_active_thread(pthread_t *);
EXT void reset_metrics_values(struct metric *);
EXT void plugin_buffers_generate_stats(struct metric *);

EXT struct metric *met;
#undef EXT

/*  
 * pmacct (Promiscuous mode IP Accounting package)
 *
 * Copyright (c) 2003-2020 Paolo Lucente <paolo@pmacct.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "addr.h"
#include "thread_pool.h"

/* Global variables */
thread_pool_t *redis_pool;

/* Functions */
void p_redis_thread_wrapper(struct p_redis_host *redis_host)
{
  /* initialize threads pool */
  redis_pool = allocate_thread_pool(1);

  assert(redis_pool);
  assert(redis_host);

  Log(LOG_DEBUG, "DEBUG ( %s ): %d thread(s) initialized\n", redis_host->log_id, 1);

  /* giving a kick to the Redis thread */
  send_to_pool(redis_pool, p_redis_master_produce_thread, redis_host);
}

int p_redis_master_produce_thread(void *rh)
{
  struct p_redis_host *redis_host = rh;
  unsigned int ret = 0, period = 0;

  p_redis_connect(redis_host, TRUE);

  for (;;) {
    if (!ret) {
      (*redis_host->th_hdlr)(redis_host);
      period = PM_REDIS_DEFAULT_REFRESH_TIME;
    }
    else {
      period = ret;
    }

    ret = sleep(period);
  }

  return SUCCESS;
}

void p_redis_init(struct p_redis_host *redis_host, char *log_id, redis_thread_handler th_hdlr)
{
  if (!redis_host || !log_id || !th_hdlr) return;

  memset(redis_host, 0, sizeof(struct p_redis_host));

  if (config.redis_host) {
    p_redis_set_log_id(redis_host, log_id);
    p_redis_set_db(redis_host, config.redis_db);
    p_redis_set_exp_time(redis_host, PM_REDIS_DEFAULT_EXP_TIME);
    p_redis_set_thread_handler(redis_host, th_hdlr);
 
    if (!config.cluster_name) {
      Log(LOG_ERR, "ERROR ( %s ): redis_host requires cluster_name to be specified. Exiting...\n\n", redis_host->log_id);
      exit_gracefully(1);
    }

    if (!config.cluster_id) {
      Log(LOG_ERR, "ERROR ( %s ): redis_host requires cluster_id to be specified. Exiting...\n\n", redis_host->log_id);
      exit_gracefully(1);
    }

    p_redis_thread_wrapper(redis_host);
  }
}

int p_redis_connect(struct p_redis_host *redis_host, int fatal)
{
  struct sockaddr_storage dest;
  socklen_t dest_len = sizeof(dest);
  char dest_str[INET6_ADDRSTRLEN];
  int dest_port = PM_REDIS_DEFAULT_PORT;

  time_t now = time(NULL);

  assert(redis_host);

  if (config.redis_host) {
    if (now >= (redis_host->last_conn + PM_REDIS_DEFAULT_CONN_RETRY)) {
      redis_host->last_conn = now;

      /* round of parsing and validation */
      parse_hostport(config.redis_host, (struct sockaddr *)&dest, &dest_len);
      sa_to_str(dest_str, sizeof(dest_str), (struct sockaddr *)&dest);
      sa_to_port(&dest_port, (struct sockaddr *)&dest);

      redis_host->ctx = redisConnect(dest_str, dest_port);

      if (redis_host->ctx == NULL || redis_host->ctx->err) {
	if (redis_host->ctx) {
	  if (fatal) {
	    Log(LOG_ERR, "ERROR ( %s ): Connection error: %s\n", redis_host->log_id, redis_host->ctx->errstr);
	    exit_gracefully(1);
	  }
	  else {
	    return ERR;
	  }
	}
	else {
	  Log(LOG_ERR, "ERROR ( %s ): Connection error: can't allocate redis context\n", redis_host->log_id);
          exit_gracefully(1);
	}
      }
      else {
	Log(LOG_DEBUG, "DEBUG ( %s ): Connection successful\n", redis_host->log_id);
      }
    }
  }

  return SUCCESS;
}

void p_redis_close(struct p_redis_host *redis_host)
{
  redisFree(redis_host->ctx);
}

void p_redis_set_string(struct p_redis_host *redis_host, char *resource, char *value, int expire)
{
  if (expire > 0) {
    redis_host->reply = redisCommand(redis_host->ctx, "SETEX %s%s%d%s%s %d %s", config.cluster_name, PM_REDIS_DEFAULT_SEP,
				     config.cluster_id, PM_REDIS_DEFAULT_SEP, resource, redis_host->exp_time, value);
  }
  else {
    redis_host->reply = redisCommand(redis_host->ctx, "SET %s%s%d%s%s %s", config.cluster_name, PM_REDIS_DEFAULT_SEP,
				     config.cluster_id, PM_REDIS_DEFAULT_SEP, resource, value);
  }

  p_redis_process_reply(redis_host);
}

void p_redis_set_int(struct p_redis_host *redis_host, char *resource, int value, int expire)
{
  if (expire > 0) {
    redis_host->reply = redisCommand(redis_host->ctx, "SETEX %s%s%d%s%s %d %d", config.cluster_name, PM_REDIS_DEFAULT_SEP,
				     config.cluster_id, PM_REDIS_DEFAULT_SEP, resource, redis_host->exp_time, value);
  }
  else {
    redis_host->reply = redisCommand(redis_host->ctx, "SET %s%s%d%s%s %d", config.cluster_name, PM_REDIS_DEFAULT_SEP,
				     config.cluster_id, PM_REDIS_DEFAULT_SEP, resource, value);
  }

  p_redis_process_reply(redis_host);
}

void p_redis_ping(struct p_redis_host *redis_host)
{
  redis_host->reply = redisCommand(redis_host->ctx, "PING");
  p_redis_process_reply(redis_host);
}

void p_redis_select_db(struct p_redis_host *redis_host)
{
  char select_cmd[VERYSHORTBUFLEN];
  
  if (redis_host->db) {
    snprintf(select_cmd, sizeof(select_cmd), "SELECT %d", redis_host->db);
    redis_host->reply = redisCommand(redis_host->ctx, select_cmd);
    p_redis_process_reply(redis_host);
  }
}

void p_redis_process_reply(struct p_redis_host *redis_host)
{
  if (redis_host->reply) {
    if (redis_host->reply->type == REDIS_REPLY_ERROR) {
      Log(LOG_WARNING, "WARN ( %s ): reply='%s'\n", redis_host->log_id, redis_host->reply->str);
    }

    freeReplyObject(redis_host->reply);
  }
  else {
    p_redis_connect(redis_host, FALSE);
  }
}

void p_redis_set_log_id(struct p_redis_host *redis_host, char *log_id)
{
  if (redis_host) {
    strlcpy(redis_host->log_id, log_id, sizeof(redis_host->log_id));
    strncat(redis_host->log_id, "/redis", (sizeof(redis_host->log_id) - strlen(redis_host->log_id))); 
  }
}

void p_redis_set_db(struct p_redis_host *redis_host, int db)
{
  if (redis_host) redis_host->db = db;
}

void p_redis_set_exp_time(struct p_redis_host *redis_host, int exp_time)
{
  if (redis_host) redis_host->exp_time = exp_time;
}

void p_redis_set_thread_handler(struct p_redis_host *redis_host, redis_thread_handler th_hdlr)
{
  if (redis_host) redis_host->th_hdlr = th_hdlr;
}

void p_redis_thread_produce_common_core_handler(void *rh)
{
  struct p_redis_host *redis_host = rh;
  char buf[SRVBUFLEN], name_and_type[SHORTBUFLEN], daemon_type[VERYSHORTBUFLEN];

  switch (config.acct_type) {
  case ACCT_NF:
    snprintf(daemon_type, sizeof(daemon_type), "%s", "nfacctd");
    break;
  case ACCT_SF:
    snprintf(daemon_type, sizeof(daemon_type), "%s", "sfacctd");
    break;
  case ACCT_PM:
    if (config.uacctd_group) {
      snprintf(daemon_type, sizeof(daemon_type), "%s", "uacctd");
    }
    else {
      snprintf(daemon_type, sizeof(daemon_type), "%s", "pmacctd");
    }
    break;
  case ACCT_PMBGP:
    snprintf(daemon_type, sizeof(daemon_type), "%s", "pmbgpd");
    break;
  case ACCT_PMBMP:
    snprintf(daemon_type, sizeof(daemon_type), "%s", "pmbmpd");
    break;
  case ACCT_PMTELE:
    snprintf(daemon_type, sizeof(daemon_type), "%s", "pmtelemetryd");
    break;
  default:
    break;
  }
  p_redis_set_string(redis_host, "daemon_type", daemon_type, PM_REDIS_DEFAULT_EXP_TIME);

  snprintf(name_and_type, sizeof(name_and_type), "process%s%s%s%s", PM_REDIS_DEFAULT_SEP,
	   config.name, PM_REDIS_DEFAULT_SEP, config.type);
  p_redis_set_int(redis_host, name_and_type, TRUE, PM_REDIS_DEFAULT_EXP_TIME);

  if (config.acct_type < ACCT_FWPLANE_MAX) {
    if (config.nfacctd_isis) {
      snprintf(buf, sizeof(buf), "%s%sisis", name_and_type, PM_REDIS_DEFAULT_SEP);
      p_redis_set_int(redis_host, buf, TRUE, PM_REDIS_DEFAULT_EXP_TIME);
    }

    if (config.bgp_daemon) {
      snprintf(buf, sizeof(buf), "%s%sbgp", name_and_type, PM_REDIS_DEFAULT_SEP);
      p_redis_set_int(redis_host, buf, TRUE, PM_REDIS_DEFAULT_EXP_TIME);
    }

    if (config.bmp_daemon) {
      snprintf(buf, sizeof(buf), "%s%sbmp", name_and_type, PM_REDIS_DEFAULT_SEP);
      p_redis_set_int(redis_host, buf, TRUE, PM_REDIS_DEFAULT_EXP_TIME);
    }

    if (config.telemetry_daemon) {
      snprintf(buf, sizeof(buf), "%s%stelemetry", name_and_type, PM_REDIS_DEFAULT_SEP);
      p_redis_set_int(redis_host, buf, TRUE, PM_REDIS_DEFAULT_EXP_TIME);
    }
  }
}

void p_redis_thread_produce_common_plugin_handler(void *rh)
{
  struct p_redis_host *redis_host = rh;
  char name_and_type[SRVBUFLEN];

  snprintf(name_and_type, sizeof(name_and_type), "process%s%s%s%s", PM_REDIS_DEFAULT_SEP,
	   config.name, PM_REDIS_DEFAULT_SEP, config.type);
  p_redis_set_int(redis_host, name_and_type, TRUE, PM_REDIS_DEFAULT_EXP_TIME);
}

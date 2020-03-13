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
#include "redis_common.h"

/* Global variables */
struct p_redis_host nfacctd_redis_host;

/* Functions */
void p_redis_init(struct p_redis_host *redis_host, char *log_id, int async)
{
  if (!redis_host || !log_id) return;

  memset(redis_host, 0, sizeof(struct p_redis_host));

  if (config.redis_host) {
    p_redis_set_log_id(redis_host, log_id);
    p_redis_set_exp_time(redis_host, PM_REDIS_DEFAULT_EXP_TIME);
    p_redis_set_async(redis_host, async);
 
    if (!config.cluster_name) {
      Log(LOG_ERR, "ERROR ( %s ): redis_host requires cluster_name to be specified. Exiting...\n\n", redis_host->log_id);
      exit_gracefully(1);
    }

    if (!config.cluster_id) {
      Log(LOG_ERR, "ERROR ( %s ): redis_host requires cluster_id to be specified. Exiting...\n\n", redis_host->log_id);
      exit_gracefully(1);
    }

    p_redis_connect(redis_host, TRUE);
  }
}

int p_redis_connect(struct p_redis_host *redis_host, int fatal)
{
  time_t now = time(NULL);

  assert(redis_host);

  if (config.redis_host) {
    if (now >= (redis_host->last_conn + PM_REDIS_DEFAULT_CONN_RETRY)) {
      if (redis_host->last_conn && redis_host->ctx) {
	redisReconnect(redis_host->ctx);
      }
      else {
	if (redis_host->async) {
	  // XXX: work out async interface
	}
	else {
	  redis_host->ctx = redisConnect(config.redis_host, PM_REDIS_DEFAULT_PORT); 
	}
      }

      redis_host->last_conn = now;

      if (redis_host->ctx == NULL || redis_host->ctx->err) {
	if (redis_host->ctx) {
	  if (fatal) {
	    Log(LOG_ERR, "ERROR ( %s ): [redis] Connection error: %s\n", redis_host->log_id, redis_host->ctx->errstr);
	    exit_gracefully(1);
	  }
	  else {
	    return ERR;
	  }
	}
	else {
	  Log(LOG_ERR, "ERROR ( %s ): [redis] Connection error: can't allocate redis context\n", redis_host->log_id);
          exit_gracefully(1);
	}
      }
      else {
	Log(LOG_DEBUG, "DEBUG ( %s ): [redis] Connection successful\n", redis_host->log_id);
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
    redis_host->reply = redisCommand(redis_host->ctx, "SETEX %s_%d_%s %d %s", config.cluster_name, config.cluster_id,
				     resource, redis_host->exp_time, value);
  }
  else {
    redis_host->reply = redisCommand(redis_host->ctx, "SET %s_%d_%s %s", config.cluster_name, config.cluster_id,
				     resource, value);
  }

  p_redis_process_reply(redis_host);
}

void p_redis_set_int(struct p_redis_host *redis_host, char *resource, int value, int expire)
{
  if (expire >  0) {
    redis_host->reply = redisCommand(redis_host->ctx, "SETEX %s_%d_%s %d %d", config.cluster_name, config.cluster_id,
				     resource, redis_host->exp_time, value);
  }
  else {
    redis_host->reply = redisCommand(redis_host->ctx, "SET %s_%d_%s %d", config.cluster_name, config.cluster_id,
				     resource, value);
  }

  p_redis_process_reply(redis_host);
}

void p_redis_ping(struct p_redis_host *redis_host)
{
  redis_host->reply = redisCommand(redis_host->ctx, "PING");
  p_redis_process_reply(redis_host);
}

void p_redis_process_reply(struct p_redis_host *redis_host)
{
  if (redis_host->reply) {
    if (redis_host->reply->type == REDIS_REPLY_ERROR) {
      Log(LOG_WARNING, "WARN ( %s ): [redis] reply='%s'\n", redis_host->log_id, redis_host->reply->str);
    }

    freeReplyObject(redis_host->reply);
  }
  else {
    p_redis_connect(redis_host, FALSE);
  }
}

void p_redis_set_log_id(struct p_redis_host *redis_host, char *log_id)
{
  if (redis_host) strlcpy(redis_host->log_id, log_id, sizeof(redis_host->log_id));
}

void p_redis_set_exp_time(struct p_redis_host *redis_host, int exp_time)
{
  if (redis_host) redis_host->exp_time = exp_time;
}

void p_redis_set_async(struct p_redis_host *redis_host, int async)
{
  if (redis_host) redis_host->async = async;
}

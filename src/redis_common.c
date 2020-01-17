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

/* Functions */
void pm_redis_init_checks()
{
  if (config.redis_server) {
    if (!config.cluster_name) {
      Log(LOG_ERR, "ERROR ( %s/%s ): redis_server requires cluster_name to be specified. Exiting...\n\n", config.name, config.type);
      exit_gracefully(1);
    }

    if (!config.cluster_id) {
      Log(LOG_ERR, "ERROR ( %s/%s ): redis_server requires cluster_id to be specified. Exiting...\n\n", config.name, config.type);
      exit_gracefully(1);
    }
  }
}

/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2022 by Paolo Lucente
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
#include "pmacct-data.h"
#include "thread_pool.h"
#include <sys/time.h>
#include "kafka_common.h"
#include "ha.h"

/*Threads*/
thread_pool_t *bmp_bgp_ha_queue_mgmt_pool;
thread_pool_t *bmp_bgp_ha_queue_dump_pool;

/*Variables*/
int daemon_state = TRUE;                    // Local daemon state
int old_bmp_bgp_forwarding = FALSE;         // Previous state of global bmp_bgp_forwarding flag
int regenerate_timestamp = FALSE;           // Flag used to trigger refresh of daemon's local timestamp
int forced_mode = FALSE;                    // Flag that specifies whether HA daemon is in forced mode or automatic (timestamp-based) mode

struct p_redis_host *redis_host;
int redis_loop_num = 1;                     // Redis loop counter used for identifying first loop
char timestamp_local[SHORTBUFLEN];          // Local timestamp
char redis_key_id_string[SHORTBUFLEN] = "ha_daemon_startup_time";
char redis_local_key[SRVBUFLEN];

cdada_queue_t *bmp_bgp_ha_data_queue;       // Queue used for storing BMP/BGP messages
pthread_mutex_t mutex_queue;                // Mutex for locking the queue
int queue_dumping = FALSE;                  // Flag to ensure queue popping stops & daemon stays active when queue is being dumped to kafka!

struct p_kafka_host kafka_host;

/*------------------------------------------------------*/
/* Kafka Host initialization functions */
/*------------------------------------------------------*/
int bmp_ha_msglog_init_kafka_host(void)
{
  int ret;

  p_kafka_init_host(&kafka_host, config.bmp_daemon_msglog_kafka_config_file);
  ret = p_kafka_connect_to_produce(&kafka_host);

  if (!config.bmp_daemon_msglog_kafka_broker_host) config.bmp_daemon_msglog_kafka_broker_host = default_kafka_broker_host;
  if (!config.bmp_daemon_msglog_kafka_broker_port) config.bmp_daemon_msglog_kafka_broker_port = default_kafka_broker_port;
  if (!config.bmp_daemon_msglog_kafka_retry) config.bmp_daemon_msglog_kafka_retry = PM_KAFKA_DEFAULT_RETRY;

  p_kafka_set_broker(&kafka_host, config.bmp_daemon_msglog_kafka_broker_host, config.bmp_daemon_msglog_kafka_broker_port);
  p_kafka_set_topic(&kafka_host, config.bmp_daemon_msglog_kafka_topic);
  p_kafka_set_partition(&kafka_host, config.bmp_daemon_msglog_kafka_partition);
  p_kafka_set_key(&kafka_host, config.bmp_daemon_msglog_kafka_partition_key, config.bmp_daemon_msglog_kafka_partition_keylen);
  p_kafka_set_content_type(&kafka_host, PM_KAFKA_CNT_TYPE_STR);
  P_broker_timers_set_retry_interval(&kafka_host.btimers, config.bmp_daemon_msglog_kafka_retry);
#ifdef WITH_SERDES
  P_broker_timers_set_retry_interval(&kafka_host.sd_schema_timers, config.bmp_daemon_msglog_kafka_retry);
#endif

  return ret;
}

int bgp_ha_msglog_init_kafka_host()
{
  int ret;

  p_kafka_init_host(&kafka_host, config.bgp_daemon_msglog_kafka_config_file);
  ret = p_kafka_connect_to_produce(&kafka_host);

  if (!config.bgp_daemon_msglog_kafka_broker_host) config.bgp_daemon_msglog_kafka_broker_host = default_kafka_broker_host;
  if (!config.bgp_daemon_msglog_kafka_broker_port) config.bgp_daemon_msglog_kafka_broker_port = default_kafka_broker_port;
  if (!config.bgp_daemon_msglog_kafka_retry) config.bgp_daemon_msglog_kafka_retry = PM_KAFKA_DEFAULT_RETRY;

  p_kafka_set_broker(&kafka_host, config.bgp_daemon_msglog_kafka_broker_host, config.bgp_daemon_msglog_kafka_broker_port);
  p_kafka_set_topic(&kafka_host, config.bgp_daemon_msglog_kafka_topic);
  p_kafka_set_partition(&kafka_host, config.bgp_daemon_msglog_kafka_partition);
  p_kafka_set_key(&kafka_host, config.bgp_daemon_msglog_kafka_partition_key, config.bgp_daemon_msglog_kafka_partition_keylen);
  p_kafka_set_content_type(&kafka_host, PM_KAFKA_CNT_TYPE_STR);
  P_broker_timers_set_retry_interval(&kafka_host.btimers, config.bgp_daemon_msglog_kafka_retry);
#ifdef WITH_SERDES
  P_broker_timers_set_retry_interval(&kafka_host.sd_schema_timers, config.bgp_daemon_msglog_kafka_retry);
#endif

  return ret;
}

int bmp_bgp_ha_msglog_init_kafka_host(void)
{
  int ret;
  if (config.bmp_daemon) ret = bmp_ha_msglog_init_kafka_host();
  else if (config.bgp_daemon) ret = bgp_ha_msglog_init_kafka_host();
  return ret;
}

/*------------------------------------------------------*/
/* Cdada queuing Functions */
/*------------------------------------------------------*/
// A utility function to create a node
struct QNode *newNode(void *buf, size_t buf_len)
{
  struct QNode *temp = (struct QNode *)malloc(sizeof(struct QNode));
  temp->buf = buf;
  temp->buf_len = buf_len;
  struct timeval current_time;
  gettimeofday(&current_time, NULL);
  temp->timestamp = current_time.tv_sec * 1000000 + current_time.tv_usec;
  return temp;
}

// Function to add a key k to a queue
void enQueue(cdada_queue_t *ha_data_queue, void *buf, size_t buf_len)
{
  // Store key, key length and its timestamp in a struct
  struct QNode *temp = newNode(buf, buf_len);
  cdada_queue_push(ha_data_queue, temp);
}

void bmp_bgp_ha_enqueue(void *avro_buf, size_t avro_buf_len)
{
  int queue_size;

  // Prepare buffer void pointer for queuing
  void *buf_cpy = malloc(avro_buf_len);
  memcpy(buf_cpy, avro_buf, avro_buf_len);

  // Enqueue the BMP message
  pthread_mutex_lock(&mutex_queue);
  enQueue(bmp_bgp_ha_data_queue, buf_cpy, avro_buf_len);
  queue_size = cdada_queue_size(bmp_bgp_ha_data_queue);
  pthread_mutex_unlock(&mutex_queue);

  Log(LOG_DEBUG, "DEBUG ( %s/%s/ha ): BMP-BGP-HA - put data into queue. Queue size:%d.\n", config.name, config.type, queue_size);
}

/*-------------------------------------------------------------------------------*/
/* Thread 1: initialize queue and mutex + pop old messages */
/*-------------------------------------------------------------------------------*/
int bmp_bgp_ha_queue_pop(void *qh)
{
  for (;;){
    sleep(2);

    long long timestamp;
    struct timeval current_time;
    nodestruct nodes;
    gettimeofday(&current_time, NULL);                                
    timestamp = current_time.tv_sec * 1000000 + current_time.tv_usec;
  
    pthread_mutex_lock(&mutex_queue);
    cdada_queue_front(bmp_bgp_ha_data_queue, &nodes);

    while (!cdada_queue_empty(bmp_bgp_ha_data_queue) && (timestamp - nodes.timestamp > QUEUE_POP_THRESHOLD) && !queue_dumping) {
    
      // Pop queue entries older than QUEUE_POP_THRESHOLD
      cdada_queue_pop(bmp_bgp_ha_data_queue);

      int check_flag = !cdada_queue_empty(bmp_bgp_ha_data_queue) & (timestamp - nodes.timestamp > QUEUE_POP_THRESHOLD);
      Log(LOG_DEBUG, "DEBUG ( %s/%s/ha ): BMP-BGP-HA-MGMT-%d - delete one from queue (check=%d). Queue size: %d\n", 
            config.name, config.type, bmp_bgp_forwarding, check_flag, cdada_queue_size(bmp_bgp_ha_data_queue));
    
      cdada_queue_front(bmp_bgp_ha_data_queue, &nodes);
    }
    pthread_mutex_unlock(&mutex_queue);
  }
  return SUCCESS;
}

void bmp_bgp_ha_queue_mgmt_thread_wrapper(void)
{
  // Initialize mutex (needed for accessing queue, as libcdada is not thread safe)
  if (pthread_mutex_init(&mutex_queue, NULL)){
    Log(LOG_ERR, "ERROR ( %s/%s/ha ): BMP-BGP-HA mutex_init failed\n", config.name, config.type);
    return;
  }
  pthread_mutex_lock(&mutex_queue);
  bmp_bgp_ha_data_queue = cdada_queue_create(nodestruct);
  pthread_mutex_unlock(&mutex_queue);

  bmp_bgp_ha_queue_mgmt_pool = allocate_thread_pool(1);
  assert(bmp_bgp_ha_queue_mgmt_pool);
  Log(LOG_DEBUG, "DEBUG ( %s/%s/ha ): BMP-BGP-HA - %d queue-mgmt thread initialized\n", config.name, config.type, 1);
  send_to_pool(bmp_bgp_ha_queue_mgmt_pool, bmp_bgp_ha_queue_pop, NULL);
}


/*-------------------------------------------------------------------------------*/
/* Thread 2: dump the queue to kafka if daemon goes from stand-by to active */
/*-------------------------------------------------------------------------------*/
void bmp_bgp_ha_queue_dump_thread_wrapper(void)
{
  // Initialize threads pool
  bmp_bgp_ha_queue_dump_pool = allocate_thread_pool(1);
  assert(bmp_bgp_ha_queue_dump_pool);
  Log(LOG_DEBUG, "DEBUG ( %s/%s/ha ): BMP-BGP-HA -  %d queue-dump thread initialized\n", config.name, config.type, 1);
}

int bmp_bgp_ha_queue_dump(void)
{
  queue_dumping = TRUE;
  nodestruct dequeued_node;

  // Init Kafka host
  bmp_bgp_ha_msglog_init_kafka_host();
  int kafka_produce_ret;

  pthread_mutex_lock(&mutex_queue);
  cdada_queue_front(bmp_bgp_ha_data_queue, &dequeued_node);
  uint32_t queue_size = cdada_queue_size(bmp_bgp_ha_data_queue);

  while (queue_size)
  {
    kafka_produce_ret = write_binary_kafka(&kafka_host, dequeued_node.buf, dequeued_node.buf_len);
    Log(LOG_DEBUG, "DEBUG ( %s/%s/ha ): BMP-BGP-HA-%d - Producing message #%d from the queue. Kafka ret (0=OK):%d\n", 
                    config.name, config.type, bmp_bgp_forwarding, queue_size, kafka_produce_ret);

    // Pop the produced node from the queue
    cdada_queue_pop(bmp_bgp_ha_data_queue); 
    if (!cdada_queue_empty(bmp_bgp_ha_data_queue))
      cdada_queue_front(bmp_bgp_ha_data_queue, &dequeued_node);
    queue_size = cdada_queue_size(bmp_bgp_ha_data_queue);
  }

  pthread_mutex_unlock(&mutex_queue);
  Log(LOG_DEBUG, "DEBUG ( %s/%s/ha ): BMP-BGP-HA-%d - Finished producing messages - queue empty.\n", 
            config.name, config.type, bmp_bgp_forwarding);

  // Close kafka host
  p_kafka_close(&kafka_host, FALSE);

  queue_dumping = FALSE;
  return SUCCESS;
}

void bmp_bgp_ha_queue_dump_start(void)
{
  send_to_pool(bmp_bgp_ha_queue_dump_pool, bmp_bgp_ha_queue_dump, NULL);
}


/*------------------------------------------------------*/
/* Redis Handler and Functions */
/*------------------------------------------------------*/
/* Returns TRUE if active, FALSE if stand-by. */
bool bmp_bgp_ha_redis_check_daemon_state(struct p_redis_host *redis_host)
{ 
  struct p_redis_keys bmp_bgp_ha_redis_keys = {.keys_amount = 0};
  char timestamp_redis[SHORTBUFLEN];
  
  // Get all available keys storing bmp_bgp_ha timestamps from redis
  char keys_regex[SRVBUFLEN];
  snprintf(keys_regex, sizeof(keys_regex), "%s%s%d%s%s%s", config.cluster_name, PM_REDIS_DEFAULT_SEP, 
            config.cluster_id, PM_REDIS_DEFAULT_SEP, "*", redis_key_id_string);
  p_redis_get_keys(redis_host, keys_regex, &bmp_bgp_ha_redis_keys);
  
  // Get timestamps and compare to local
  for (int i = 0; i < bmp_bgp_ha_redis_keys.keys_amount; i++)
  {
    p_redis_get_string(redis_host, bmp_bgp_ha_redis_keys.keys[i], timestamp_redis);
    if ( (strtoll(timestamp_redis, NULL, 0)) < (strtoll(timestamp_local, NULL, 0)) ) return FALSE;    // return FALSE if there is a smaller timestamp
    else if ( (strtoll(timestamp_redis, NULL, 0)) == (strtoll(timestamp_local, NULL, 0)) ) continue;  // current daemon's timestamp
  }
  
  return TRUE;
}

/* Main loop */
void p_redis_thread_bmp_bgp_ha_handler(void *rh)
{
  struct p_redis_host *redis_host = rh;

  // Initialize the local timestamp (only at first loop/daemon startup)
  if (redis_loop_num == 1) {
    Log(LOG_INFO, "INFO ( %s/%s/ha/redis ): BMP-BGP-HA - Redis connection successful\n", config.name, config.type);
    struct timeval current_time;
    gettimeofday(&current_time, NULL);
    snprintf(timestamp_local, sizeof(timestamp_local), "%ld", current_time.tv_sec * 1000000 + current_time.tv_usec);
    Log(LOG_DEBUG, "DEBUG ( %s/%s/ha/redis ): BMP-BGP-HA - Daemon startup timestamp=%s\n", config.name, config.type, timestamp_local);
  }

  // Refresh the local timestamp if the regenerate_timestamp flag is set
  if (regenerate_timestamp){
    struct timeval current_time;
    gettimeofday(&current_time, NULL);
    snprintf(timestamp_local, sizeof(timestamp_local), "%ld", current_time.tv_sec * 1000000 + current_time.tv_usec);
    regenerate_timestamp = FALSE;
  }

  // Write the local timestamp to redis
  snprintf(redis_local_key, sizeof(redis_local_key), "%s%s%s", config.name, PM_REDIS_DEFAULT_SEP, redis_key_id_string);
  p_redis_set_string(redis_host, redis_local_key, timestamp_local, PM_REDIS_DEFAULT_EXP_TIME);

  // Refresh daemon state based on timestamp
  if (!forced_mode) daemon_state = bmp_bgp_ha_redis_check_daemon_state(redis_host);

  // Set global flag [pmacct-globals.c] according to current daemon state 
  bmp_bgp_forwarding = daemon_state | queue_dumping;  // prevent going stand-by if dumping
  if (queue_dumping && !daemon_state) { 
    Log(LOG_INFO, "DEBUG ( %s/%s/ha/redis ): BMP-BGP-HA Thread is dumping the queue: waiting before going stand-by...\n", config.name, config.type);
  }

  // Dump the queue when daemon becomes active and this is not the first connection
  if ( (bmp_bgp_forwarding && !old_bmp_bgp_forwarding) && redis_loop_num != 1 ){
    bmp_bgp_ha_queue_dump_start();
  }

  // Write the current collector status to Log on state change
  if ((bmp_bgp_forwarding != old_bmp_bgp_forwarding) || redis_loop_num == 1) {
    Log(LOG_INFO, "INFO ( %s/%s/ha/redis ): BMP-BGP-HA Daemon state: %s\n", config.name, config.type, (bmp_bgp_forwarding ? "ACTIVE" : "STANDBY"));
  }

  // Update loop variables
  old_bmp_bgp_forwarding = bmp_bgp_forwarding;
  redis_loop_num++;
  redis_loop_num = redis_loop_num % 62 + 2;           // result in range[2, 62]

  // Redirect to redis common handler
  p_redis_thread_produce_common_core_handler(redis_host);
}


/*-------------------------------------------------------------------------------*/
/* Signal handlers */
/*-------------------------------------------------------------------------------*/
void bmp_bgp_ha_regenerate_timestamp(int signum){
  regenerate_timestamp = TRUE;
  Log(LOG_INFO, "INFO ( %s/%s/ha ) : BMP-BGP-HA: Local startup timestamp reset triggered.\n", config.name, config.type);
  if (forced_mode) Log(LOG_INFO, "INFO ( %s/%s/ha/redis ): BMP-BGP-HA Daemon is in forced-mode (%s): startup timestamp has no influence on state!\n", 
                        config.name, config.type, (bmp_bgp_forwarding ? "ACTIVE" : "STANDBY"));
}

void bmp_bgp_ha_set_to_active(int signum){
  forced_mode = TRUE;
  daemon_state = TRUE;
  Log(LOG_INFO, "INFO ( %s/%s/ha ) : BMP-BGP-HA: Setting daemon to forced-active state.\n", config.name, config.type);
}

void bmp_bgp_ha_set_to_standby(int signum){
  forced_mode = TRUE;
  daemon_state = FALSE;
  Log(LOG_INFO, "INFO ( %s/%s/ha ) : BMP-BGP-HA: Setting daemon to forced-standby state.\n", config.name, config.type);
}

void bmp_bgp_ha_set_to_normal(int signum){
  if (forced_mode) Log(LOG_INFO, "INFO ( %s/%s/ha ) : BMP-BGP-HA: Setting daemon back to automatic timestamp-based mode.\n", config.name, config.type);
  else Log(LOG_INFO, "INFO ( %s/%s/ha ) : BMP-BGP-HA: Daemon is already in automatic timestamp-based mode (%s).\n", 
           config.name, config.type, (bmp_bgp_forwarding ? "ACTIVE" : "STANDBY"));
  forced_mode = FALSE;
}

/*-------------------------------------------------------------------------------*/
/* Main Function - called from core [nfacctd.c] */
/*-------------------------------------------------------------------------------*/
void bmp_bgp_ha_main(void){

    // Thread 1: initialize the queue+mutex_queue and pops old messages
    bmp_bgp_ha_queue_mgmt_thread_wrapper();
      
    // Thread 2: dump the queue if the daemon goes from stand-by to active
    bmp_bgp_ha_queue_dump_thread_wrapper();
}
// #include "pmacct-data.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include "pmacct.h"
#include "pmacct-data.h"
#include "thread_pool.h"
#include "cdada/queue.h"

thread_pool_t *dq_pool;
// A utility function to create a new linked list node.
struct QNode *newNode(void *k, size_t k_len)
{
  struct QNode *temp = (struct QNode *)malloc(sizeof(struct QNode));
  temp->key = k;
  temp->key_len = k_len;
  struct timeval current_time;
  gettimeofday(&current_time, NULL);                                      // Get time in micro second
  temp->timestamp = current_time.tv_sec * 1000000 + current_time.tv_usec; // Setting the time when redis connects as timestamp for this bmp session
  return temp;
}

// The function to add a key k to q
void enQueue(cdada_queue_t *ha_data_queue, void *k, size_t k_len)
{
  // Store key,key length and its timestamp in a struct
  struct QNode *temp = newNode(k, k_len);
  cdada_queue_push(ha_data_queue, temp);
}

void pm_ha_queue_thread_wrapper()
{
  if (pthread_mutex_init(&bmp_ha_struct.mutex_thr, NULL) || pthread_cond_init(&bmp_ha_struct.sig, NULL)){
    Log(LOG_ERR, "ERROR ( %s/%s ): mutex_init failed\n", config.name, config.type);
    return;
  }
  pthread_mutex_lock(&bmp_ha_struct.mutex_thr);
  bmp_ha_data_queue = cdada_queue_create(nodestruct);
  pthread_mutex_unlock(&bmp_ha_struct.mutex_thr);
  queue_thread_handler th_hdlr = &pm_ha_countdown_delete;

  dq_pool = allocate_thread_pool(1);
  send_to_pool(dq_pool, pm_ha_queue_produce_thread, th_hdlr);
  return;
}

int pm_ha_queue_produce_thread(void *qh)
{
  for (;;){
    pm_ha_countdown_delete();
  }
  return SUCCESS;
}

void pm_ha_countdown_delete()
{
  sleep(2); // per two second
  long long timestamp;
  struct timeval current_time;
  nodestruct nodes;
  gettimeofday(&current_time, NULL);                                // Get time in micro second
  timestamp = current_time.tv_sec * 1000000 + current_time.tv_usec; // Setting the time when redis connects as timestamp for this bmp session
  pthread_mutex_lock(&bmp_ha_struct.mutex_thr);
  int flag = cdada_queue_empty(bmp_ha_data_queue) ? 0 : 1;
  pthread_mutex_unlock(&bmp_ha_struct.mutex_thr);
  if (flag){
    pthread_mutex_lock(&bmp_ha_struct.mutex_thr);
    pthread_cond_wait(&bmp_ha_struct.sig, &bmp_ha_struct.mutex_thr);
    cdada_queue_front(bmp_ha_data_queue, &nodes);
    // while the data in the queue is expired by 2s
    while (cdada_queue_size(bmp_ha_data_queue) && (timestamp - nodes.timestamp > 2000000) && !bmp_ha_struct.queue_dump_flag){
      cdada_queue_pop(bmp_ha_data_queue);
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): Delete one from queue: %d %d %d %d \n", config.type, config.name, cdada_queue_size(bmp_ha_data_queue), !cdada_queue_empty(bmp_ha_data_queue), (timestamp - nodes.timestamp > 1999999), !bmp_ha_struct.queue_dump_flag);
      cdada_queue_front(bmp_ha_data_queue, &nodes);
    }
    pthread_mutex_unlock(&bmp_ha_struct.mutex_thr);
  }

  return;
}

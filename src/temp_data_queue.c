// #include "pmacct-data.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include "pmacct.h"
#include "pmacct-data.h"
#include "thread_pool.h"

// #include "temp_data_queue.h"

// #include <threads.h>

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
  // temp->next = NULL;
  return temp;
}

// The function to add a key k to q
void enQueue(struct pm_list *q, void *k, size_t k_len)
{
  // Store key,key length and its timestamp in a struct
  struct QNode *temp = newNode(k, k_len);
  pm_listnode_add(q, temp);
}

// Function to remove a key from given queue q
void deQueue(struct pm_list *q)
{
  struct QNode *temp = pm_listnode_head(q);
  pm_listnode_delete(q, temp);
}

void set_thrd(struct Queue *q_hd, queue_thread_handler th_hdlr)
{
  q_hd->th_hdlr = th_hdlr;
}

void queue_thread_wrapper()
{
  struct Queue *temp1;
  struct pm_list *temp = pm_list_new();

  pthread_mutex_lock(&mutex_thr);
  q = calloc(1, sizeof(struct pm_list));
  q = temp;
  pthread_mutex_unlock(&mutex_thr);

  temp1->th_hdlr = &countdown_delete;
  q_handler = temp1;
  Log(LOG_INFO, "Created queue\n");

  dq_pool = allocate_thread_pool(1);
  send_to_pool(dq_pool, queue_produce_thread, q_handler);
  return;
}

int queue_produce_thread(void *qh)
{

  struct Queue *q_hd = qh;
  for (;;)
  {
    countdown_delete();
  }
  return SUCCESS;
}

void countdown_delete()
{
  sleep(2); // per two second
  long long timestamp;
  struct timeval current_time;
  gettimeofday(&current_time, NULL);                                // Get time in micro second
  timestamp = current_time.tv_sec * 1000000 + current_time.tv_usec; // Setting the time when redis connects as timestamp for this bmp session

  pthread_mutex_lock(&mutex_thr);
  int flag = (q->tail == NULL && q->count) ? 0 : 1;
  pthread_mutex_unlock(&mutex_thr);

  if (flag)
  {
    pthread_mutex_lock(&mutex_thr);
    pthread_cond_wait(&sig, &mutex_thr);
    struct QNode *d_ptr = (struct QNode *)q->head->data;
    //while the data in the queue is expired by 2s
    while ((q->tail != NULL) && (timestamp - (d_ptr->timestamp) > 199999) && !queue_dump_flag)
    {
      // Check if data is expired
      deQueue(q); // delete if the 1 second countdown is over
      Log(LOG_INFO, "Delete one from queue\n");
      d_ptr = (struct QNode *)q->head->data;
    }
    pthread_mutex_unlock(&mutex_thr);
  }
  
  return;
}

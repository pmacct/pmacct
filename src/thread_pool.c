/*
    Thread pool implementation for pmacct
    Copyright (C) 2006 Francois Deppierraz
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

#define __THREAD_POOL_C

/* includes */
#include "pmacct.h"
#include "thread_pool.h"

#if THREAD_DEBUG
  int debug_pthread_mutex_lock(pthread_mutex_t *mutex) {
    printf("Locking mutex 0x%x\n", (unsigned int) mutex);
    fflush(stdout);
    return pthread_mutex_lock(mutex);
  }

  int debug_pthread_mutex_unlock(pthread_mutex_t *mutex) {
    printf("Unlocking mutex 0x%x\n", (unsigned int) mutex);
    fflush(stdout);
    return pthread_mutex_unlock(mutex);
  }

  #define pthread_mutex_lock    debug_pthread_mutex_lock
  #define pthread_mutex_unlock  debug_pthread_mutex_unlock
#endif


thread_pool_t *allocate_thread_pool(int count)
{
  int i, rc;
  thread_pool_t *pool;
  thread_pool_item_t *worker;

  // Allocate pool
  pool = malloc(sizeof(thread_pool_t));
  assert(pool);

  // Allocate pool mutex
  pool->mutex = malloc(sizeof (pthread_mutex_t));
  assert(pool->mutex);
  pthread_mutex_init(pool->mutex, NULL);
 
  // Allocate pool condition
  pool->cond = malloc(sizeof (pthread_cond_t));
  assert(pool->mutex);
  pthread_cond_init(pool->cond, NULL);
 
  pool->count = count;

  /* Threads lists */
  pool->free_list = NULL;

  for (i = 0; i < pool->count; i++) {
    worker = malloc(sizeof(thread_pool_item_t));
    assert(worker);

    worker->id = i;
    worker->owner = pool;

    worker->mutex = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(worker->mutex, NULL);

    worker->cond = malloc(sizeof(pthread_cond_t));
    pthread_cond_init(worker->cond, NULL);

    /* Default state */
    worker->go = -1;
    worker->quit = 0;
    worker->usage = 0;

    /* Create the thread */
    worker->thread = malloc(sizeof(pthread_t));
    rc = pthread_create(worker->thread, NULL, thread_runner, worker);

    if (rc) {
      printf("ERROR: thread creation failed: %s\n", strerror(rc));
    }

    // Wait for thread init
    pthread_mutex_lock(worker->mutex);
    while (worker->go != 0)
      pthread_cond_wait(worker->cond, worker->mutex);
    pthread_mutex_unlock(worker->mutex);

    // Add to free list
    worker->next = pool->free_list;
    pool->free_list = worker;
  }

  return pool;
}

void desallocate_thread_pool(thread_pool_t *pool)
{
  thread_pool_item_t *worker;

  while (worker) {
    /* Let him finish */
    pthread_mutex_lock(worker->mutex);
    worker->quit = 1;
    pthread_mutex_unlock(worker->mutex);

    pthread_join(*worker->thread, NULL);

    /* Free memory */
    pthread_mutex_destroy(worker->mutex);
    free(worker->mutex);

    pthread_cond_destroy(worker->cond);
    free(worker->cond);
 
    free(worker->thread);

    worker = worker->next;
    free(worker);
  }
  free(pool);
}

void *thread_runner(void *arg)
{
  thread_pool_item_t *self = (thread_pool_item_t *) arg;
#if DEBUG_TIMING
  struct mytimer t1;
#endif

  pthread_mutex_lock(self->mutex);
  self->go = 0;
  pthread_cond_signal(self->cond);
  pthread_mutex_unlock(self->mutex);

  while (!self->quit) {

    /* Wait for some work */
    pthread_mutex_lock(self->mutex);
    while (!self->go)
      pthread_cond_wait(self->cond, self->mutex);

#if DEBUG
    fprintf(stderr, "[R] Thread 0x%x is working\n", self);
#endif

#if DEBUG_TIMING
    start_timer(&t1);
#endif
    (*self->function)(self->data);
#if DEBUG_TIMING
    stop_timer(&t1, "function:0x%x", self);
#endif

#if DEBUG
    fprintf(stderr, "[R] Thread 0x%x has finished\n", self);
#endif

    self->usage++;
    self->go = 0;
    pthread_mutex_unlock(self->mutex);

    pthread_mutex_lock(self->owner->mutex);
    self->next = self->owner->free_list;
    self->owner->free_list = self;
    pthread_cond_signal(self->owner->cond);
    pthread_mutex_unlock(self->owner->mutex);
  }

  pthread_exit(NULL);
}

void send_to_pool(thread_pool_t *pool, void *function, struct packet_ptrs *data)
{
  thread_pool_item_t *worker;
#if DEBUG_TIMING
  struct mytimer t0;
#endif

#if DEBUG_TIMING
  start_timer(&t0);
#endif

  pthread_mutex_lock(pool->mutex);
  while (pool->free_list == NULL)
    pthread_cond_wait(pool->cond, pool->mutex);

  /* Get a free thread */
  worker = pool->free_list;
  pool->free_list = worker->next;
  pthread_mutex_unlock(pool->mutex);

  /* Give it some work to do */
  pthread_mutex_lock(worker->mutex);

  worker->function = function;
  worker->data = data;
  worker->go = 1;

  pthread_cond_signal(worker->cond);
  pthread_mutex_unlock(worker->mutex);

#if DEBUG_TIMING
  stop_timer(&t0, "send_to_pool:");
#endif
}

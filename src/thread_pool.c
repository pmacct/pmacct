/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2015 by Paolo Lucente
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

/*
    Original thread pool implementation for pmacct is:
    Copyright (C) 2006 Francois Deppierraz
*/

#define __THREAD_POOL_C

/* includes */
#include "pmacct.h"
#include "thread_pool.h"

thread_pool_t *allocate_thread_pool(int count)
{
  int i, rc;
  thread_pool_t *pool;
  thread_pool_item_t *worker;
  pthread_attr_t attr, *attr_ptr = NULL;

  if (count <= 0) {
    Log(LOG_WARNING, "WARN ( %s/%s ): allocate_thread_pool() requires count > 0\n", config.name, config.type);
    return NULL;
  }

  // Allocate pool
  pool = malloc(sizeof(thread_pool_t));
  assert(pool);

  // Allocate pool mutex
  pool->mutex = malloc(sizeof(pthread_mutex_t));
  assert(pool->mutex);
  pthread_mutex_init(pool->mutex, NULL);
 
  // Allocate pool condition
  pool->cond = malloc(sizeof(pthread_cond_t));
  assert(pool->cond);
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
    assert(worker->mutex);
    pthread_mutex_init(worker->mutex, NULL);

    worker->cond = malloc(sizeof(pthread_cond_t));
    assert(worker->cond);
    pthread_cond_init(worker->cond, NULL);

    /* Default state */
    worker->go = ERR;
    worker->quit = FALSE;
    worker->usage = FALSE;

    /* Create the thread */
    worker->thread = malloc(sizeof(pthread_t));
    assert(worker->thread);

    if (config.thread_stack) {
      rc = pthread_attr_init(&attr);
      if (rc) {
        Log(LOG_ERR, "ERROR ( %s/%s ): pthread_attr_init(): %s\n", config.name, config.type, strerror(rc));
        return NULL;
      }
      else {
        rc = pthread_attr_setstacksize(&attr, config.thread_stack);
        if (rc) {
          Log(LOG_ERR, "ERROR ( %s/%s ): pthread_attr_setstacksize(): %s\n", config.name, config.type, strerror(rc));
          return NULL;
	}
        else attr_ptr = &attr;
      }
    }

    rc = pthread_create(worker->thread, attr_ptr, thread_runner, worker);

    if (rc) {
      Log(LOG_ERR, "ERROR ( %s/%s ): pthread_create(): %s\n", config.name, config.type, strerror(rc));
      return NULL;
    }

    // Wait for thread init
    pthread_mutex_lock(worker->mutex);
    while (worker->go != 0) pthread_cond_wait(worker->cond, worker->mutex);
    pthread_mutex_unlock(worker->mutex);

    // Add to free list
    worker->next = pool->free_list;
    pool->free_list = worker;
  }

  return pool;
}

/* XXX: case not supported: thread running and not in pool->free_list
   at time of deallocate_thread_pool() execution; potential future need
   for a worker_list in thread_pool_t */
void deallocate_thread_pool(thread_pool_t **pool)
{
  thread_pool_t *pool_ptr = NULL;
  thread_pool_item_t *worker = NULL;

  if (!pool || !(*pool)) return;

  pool_ptr = (*pool); 
  worker = pool_ptr->free_list;

  while (worker) {
    /* Let him finish */
    pthread_mutex_lock(worker->mutex);
    worker->go = TRUE;
    worker->quit = TRUE;
    pthread_mutex_unlock(worker->mutex);

    pthread_cond_signal(worker->cond);
    pthread_join((*worker->thread), NULL);

    /* Free memory */
    pthread_mutex_destroy(worker->mutex);
    free(worker->mutex);

    pthread_cond_destroy(worker->cond);
    free(worker->cond);
 
    free(worker->thread);

    worker = worker->next;
    free(worker);
  }

  if (pool_ptr->mutex) free(pool_ptr->mutex);
  if (pool_ptr->cond) free(pool_ptr->cond);

  free((*pool));
  (*pool) = NULL;
}

void *thread_runner(void *arg)
{
  thread_pool_item_t *self = (thread_pool_item_t *) arg;

  pthread_mutex_lock(self->mutex);
  self->go = FALSE;
  pthread_cond_signal(self->cond);
  pthread_mutex_unlock(self->mutex);

  while (!self->quit) {

    /* Wait for some work */
    pthread_mutex_lock(self->mutex);
    while (!self->go) pthread_cond_wait(self->cond, self->mutex);

    /* Pre-flight check in case we were unlocked by deallocate_thread_pool() */
    if (self->quit) break;

    /* Doing our job */
    (*self->function)(self->data);

    self->usage++;
    self->go = FALSE;
    pthread_mutex_unlock(self->mutex);

    pthread_mutex_lock(self->owner->mutex);
    self->next = self->owner->free_list;
    self->owner->free_list = self;
    pthread_cond_signal(self->owner->cond);
    pthread_mutex_unlock(self->owner->mutex);
  }

  pthread_exit(NULL);
}

void send_to_pool(thread_pool_t *pool, void *function, void *data)
{
  thread_pool_item_t *worker;

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
  worker->go = TRUE;

  pthread_cond_signal(worker->cond);
  pthread_mutex_unlock(worker->mutex);
}

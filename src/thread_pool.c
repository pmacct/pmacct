/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2021 by Paolo Lucente
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

/* includes */
#include "pmacct.h"
#include "thread_pool.h"

thread_pool_t *allocate_thread_pool(int count)
{
  int i, rc;
  thread_pool_t *pool;
  thread_pool_item_t *worker;
  pthread_attr_t attr, *attr_ptr = NULL;
  size_t default_stack_size;

  if (count <= 0) {
    Log(LOG_WARNING, "WARN ( %s/%s ): allocate_thread_pool() requires count > 0\n", config.name, config.type);
    return NULL;
  }

  // Allocate pool
  pool = malloc(sizeof(thread_pool_t));
  assert(pool);
  memset(pool, 0, sizeof(thread_pool_t));

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
  pool->list = malloc(count * sizeof(struct thread_pool_item_t *));
  memset(pool->list, 0, count * sizeof(struct thread_pool_item_t *));
  pool->free_list = NULL;

  for (i = 0; i < pool->count; i++) {
    worker = malloc(sizeof(thread_pool_item_t));
    assert(worker);

    worker->id = (i + 1);
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

    rc = pthread_attr_init(&attr);
    if (rc) {
      Log(LOG_ERR, "ERROR ( %s/%s ): pthread_attr_init(): %s\n", config.name, config.type, strerror(rc));
      deallocate_thread_pool(&pool);
      return NULL;
    }

    if (config.thread_stack && config.thread_stack < MIN_TH_STACK_SIZE) {
      config.thread_stack = MIN_TH_STACK_SIZE;
      Log(LOG_INFO, "INFO ( %s/%s ): thread_stack re-defined to minimum: %u\n", config.name, config.type, MIN_TH_STACK_SIZE);
    }

    /*
       Thread stack handling:
       * if thread_stack is defined, apply it;
       * if thread_stack is found not good but system default is good (ie.
	 equal or greater than MIN_TH_STACK_SIZE), apply system default;
       * if system default is not good (ie. less than MIN_TH_STACK_SIZE),
	 apply MIN_TH_STACK_SIZE;
       * if nothing of the above works bail out.
    */
    pthread_attr_getstacksize(&attr, &default_stack_size); 
    if (config.thread_stack) {                        
      rc = pthread_attr_setstacksize(&attr, config.thread_stack);
      if (rc && default_stack_size >= MIN_TH_STACK_SIZE) rc = pthread_attr_setstacksize(&attr, default_stack_size);
    }

    if (rc || default_stack_size < MIN_TH_STACK_SIZE) rc = pthread_attr_setstacksize(&attr, MIN_TH_STACK_SIZE);

    if (!rc) {
      size_t confd_stack_size;

      attr_ptr = &attr;
      pthread_attr_getstacksize(&attr, &confd_stack_size);
      if (confd_stack_size != config.thread_stack && confd_stack_size != default_stack_size) 
        Log(LOG_INFO, "INFO ( %s/%s ): pthread_attr_setstacksize(): %lu\n", config.name, config.type, (unsigned long)confd_stack_size);
    }
    else {
      Log(LOG_ERR, "ERROR ( %s/%s ): pthread_attr_setstacksize(): %s\n", config.name, config.type, strerror(rc));
      deallocate_thread_pool(&pool);
      return NULL;
    }

    rc = pthread_create(worker->thread, attr_ptr, thread_runner, worker);

    if (rc) {
      Log(LOG_ERR, "ERROR ( %s/%s ): pthread_create(): %s\n", config.name, config.type, strerror(rc));
      deallocate_thread_pool(&pool);
      return NULL;
    }

    // Wait for thread init
    pthread_mutex_lock(worker->mutex);
    while (worker->go != 0) pthread_cond_wait(worker->cond, worker->mutex);
    pthread_mutex_unlock(worker->mutex);

    // Add to lists
    worker->next = pool->free_list;
    pool->free_list = worker;
    pool->list[i] = worker;
  }

  return pool;
}

void deallocate_thread_pool(thread_pool_t **pool)
{
  thread_pool_t *pool_ptr = NULL;
  thread_pool_item_t *worker = NULL;
  int i = 0;

  if (!pool || !(*pool)) return;

  pool_ptr = (*pool); 

  /* Let's give send_to_pool() some advantage in case it was just called */
  sleep(1);

  for (i = 0; i < pool_ptr->count; i++) {
    worker = pool_ptr->list[i];

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
  int ret = FALSE;

  pthread_mutex_lock(self->mutex);
  self->go = FALSE;
  pthread_cond_signal(self->cond);
  pthread_mutex_unlock(self->mutex);

  while (!self->quit) {
    /* Wait for some work */
    pthread_mutex_lock(self->mutex);

    while (!self->go) {
      pthread_cond_wait(self->cond, self->mutex);
    }

    /* Pre-flight check in case we were unlocked by deallocate_thread_pool() */
    if (self->quit) break;

    /* Doing our job */
    ret = (*self->function)(self->data);

    if (ret == ERR) self->quit = TRUE;

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

  while (pool->free_list == NULL) {
    pthread_cond_wait(pool->cond, pool->mutex);
  }

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

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

#ifndef _THREAD_POOL_H_
#define _THREAD_POOL_H_

#include <pthread.h>
#include <assert.h> /* for assert() */
#include <sys/errno.h> /* for EBUSY */

#define DEBUG        0
#define THREAD_DEBUG 0
#define DEFAULT_TH_NUM 10

typedef struct thread_pool_item {
  int			id;

  pthread_mutex_t   		*mutex;
  pthread_cond_t    		*cond;

  pthread_t         		*thread;

  void               		(*function)(struct packet_ptrs *data);
  struct packet_ptrs 		*data;

  int                		usage;
  int          			go;
  int          			quit;  

  struct thread_pool_item	*next;
  struct thread_pool		*owner;
} thread_pool_item_t;

typedef struct thread_pool {
  int			count;

  thread_pool_item_t	*free_list;

  pthread_cond_t	*cond;
  pthread_mutex_t	*mutex;
} thread_pool_t;

#if (!defined __THREAD_POOL_C)
#define EXT extern
#else
#define EXT
#endif
EXT thread_pool_t *allocate_thread_pool(int count);
EXT void desallocate_thread_pool(thread_pool_t *pool);
EXT void send_to_pool(thread_pool_t *pool, void *function, struct packet_ptrs *data);
EXT void *thread_runner(void *);
#undef EXT

#endif /* _THREAD_POOL_H_ */

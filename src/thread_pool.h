/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2020 by Paolo Lucente
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

#ifndef _THREAD_POOL_H_
#define _THREAD_POOL_H_

#include <pthread.h>
#include <assert.h> /* for assert() */
#include <sys/errno.h> /* for EBUSY */

#define DEFAULT_TH_NUM 10
#define MIN_TH_STACK_SIZE 8192000

typedef struct thread_pool_item {
  int			id;

  pthread_mutex_t   		*mutex;
  pthread_cond_t    		*cond;

  pthread_t         		*thread;

  int				(*function)(struct packet_ptrs *data);
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

extern thread_pool_t *allocate_thread_pool(int);
extern void deallocate_thread_pool(thread_pool_t **);
extern void send_to_pool(thread_pool_t *, void *, void *);
extern void *thread_runner(void *);

#endif /* _THREAD_POOL_H_ */

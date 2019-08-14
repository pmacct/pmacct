/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2019 by Paolo Lucente
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

/* includes */
#include "pmacct.h"
#include "imt_plugin.h"

/* rules:
   first pool descriptor id is 1 */

/* functions */
void init_memory_pool_table()
{
  if (config.num_memory_pools) {
    mpd = (unsigned char *) map_shared(0, (config.num_memory_pools+1)*sizeof(struct memory_pool_desc),
				   PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    memset(mpd, 0, (config.num_memory_pools+1)*sizeof(struct memory_pool_desc));
  }
  else {
    mpd = (unsigned char *) map_shared(0, (NUM_MEMORY_POOLS+1)*sizeof(struct memory_pool_desc),
				   PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    memset(mpd, 0, (NUM_MEMORY_POOLS+1)*sizeof(struct memory_pool_desc));
  }

  current_pool = (struct memory_pool_desc *) mpd;
}


void clear_memory_pool_table()
{
  struct memory_pool_desc *pool_ptr;

  pool_ptr = (struct memory_pool_desc *) mpd;
  while (pool_ptr->next) {
    memset(pool_ptr->base_ptr, 0, pool_ptr->len);
    pool_ptr->id = 0;
    pool_ptr = pool_ptr->next;
  }

  /* clearing last memory pool and rewinding stuff */ 
  memset(pool_ptr->base_ptr, 0, pool_ptr->len);
  current_pool = (struct memory_pool_desc *) mpd;
}

struct memory_pool_desc *request_memory_pool(int size)
{
  int new_id; 
  unsigned char *memptr;
  struct memory_pool_desc *new_pool;
  
  /* trying to find resource already allocated but
     currently unused */
  if (current_pool->next) {
    if (!current_pool->id) {
      new_pool = current_pool;
      new_pool->id = 1;
    }
    else {
      new_pool = current_pool->next;
      new_pool->id = current_pool->id+1;
    }
    if (size <= new_pool->len) {
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): using an already allocated memory segment.\n", config.name, config.type);
      memset(new_pool->base_ptr, 0, size);
      new_pool->ptr = new_pool->base_ptr;
      new_pool->space_left = size;
      return new_pool; 
    }
  }

  /* we didn't find allocated resources; requesting new
     news and registering them in memory pool descriptors
     table */
  new_id = current_pool->id+1;
  Log(LOG_DEBUG, "DEBUG ( %s/%s ): allocating a new memory segment.\n", config.name, config.type);

  if (config.num_memory_pools) {
    if (new_id > config.num_memory_pools) return NULL; 
    new_pool = (struct memory_pool_desc *) mpd+(new_id-1);
  }
  else {
    if (new_id > NUM_MEMORY_POOLS) {
      /* 
         XXX: this malloc() is a quick workaround because of some mallopt() SEGV when
         trying to allocate chuncks < 1024; i'm not figuring out where is the *real*
	 problem. First experienced with:
         
       	 		gcc version 3.3.3 (Debian 20040320) / glibc 2.3.2
      */
      // new_pool = (struct memory_pool_desc *) malloc(sizeof(struct memory_pool_desc));
      new_pool = (struct memory_pool_desc *) map_shared(0, 1024, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
      if (new_pool == MAP_FAILED) return NULL;
      memset(new_pool, 0, sizeof(struct memory_pool_desc));
    }
    else new_pool = (struct memory_pool_desc *) mpd+(new_id-1);
  }

  if (current_pool->id) current_pool->next = new_pool;

  /* We found a free room in mpd table; now we have
     allocate needed memory */
  memptr = (unsigned char *) map_shared(0, size, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
  if (memptr == MAP_FAILED) {
    Log(LOG_WARNING, "WARN ( %s/%s ): memory sold out ! Please, clear in-memory stats !\n", config.name, config.type);
    return NULL;
  }

  memset(memptr, 0, size);
  new_pool->id = new_id;
  new_pool->base_ptr = memptr;
  new_pool->ptr = memptr;
  new_pool->space_left = size;
  new_pool->len = size;
  return new_pool;
}

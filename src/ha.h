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

#ifndef HA_H
#define HA_H

/*Global variables*/
typedef void (*queue_thread_handler)();

// A linked list (LL) node to store a queue entry
typedef struct QNode
{
    void *key; //Data
    size_t key_len; //Data length
    long long timestamp;
}nodestruct;

/*Functions*/
extern void pm_ha_countdown_delete();
extern void pm_ha_queue_thread_wrapper();
extern int pm_ha_queue_produce_thread(void *);
extern void enQueue(cdada_queue_t*, void *, size_t);

#endif //HA_H

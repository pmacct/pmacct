/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2008 by Paolo Lucente
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
    along with this program; if no, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#if (!defined __NFV8_HANDLERS_C)
#define EXT extern
#else
#define EXT
#endif
EXT void load_nfv8_handlers();

EXT void v8_1_filter_handler(struct packet_ptrs *, void *);
EXT void v8_2_filter_handler(struct packet_ptrs *, void *);
EXT void v8_3_filter_handler(struct packet_ptrs *, void *);
EXT void v8_4_filter_handler(struct packet_ptrs *, void *);
EXT void v8_5_filter_handler(struct packet_ptrs *, void *);
EXT void v8_6_filter_handler(struct packet_ptrs *, void *);
EXT void v8_7_filter_handler(struct packet_ptrs *, void *);
EXT void v8_8_filter_handler(struct packet_ptrs *, void *);
EXT void v8_9_filter_handler(struct packet_ptrs *, void *);
EXT void v8_10_filter_handler(struct packet_ptrs *, void *);
EXT void v8_11_filter_handler(struct packet_ptrs *, void *);
EXT void v8_12_filter_handler(struct packet_ptrs *, void *);
EXT void v8_13_filter_handler(struct packet_ptrs *, void *);
EXT void v8_14_filter_handler(struct packet_ptrs *, void *);
#undef EXT

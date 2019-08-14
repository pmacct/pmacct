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

#ifndef PRINT_PLUGIN_H
#define PRINT_PLUGIN_H

/* includes */
#include <sys/poll.h>

/* prototypes */
extern void print_plugin(int, struct configuration *, void *);
extern void P_cache_purge(struct chained_cache *[], int, int);
extern void P_write_stats_header_formatted(FILE *, int);
extern void P_write_stats_header_csv(FILE *, int);
extern void P_fprintf_csv_string(FILE *, struct pkt_vlen_hdr_primitives *, pm_cfgreg_t, char *, char *);

/* global variables */
extern int print_output_stdout_header;

#endif //PRINT_PLUGIN_H

/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2018 by Paolo Lucente
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

/* defines */
struct rpki_data {
  int is_thread;
  char *log_str;
};

/* prototypes */
#if !defined(__RPKI_C)
#define EXT extern
#else
#define EXT
#endif
EXT void rpki_daemon_wrapper();
EXT void rpki_prepare_thread(struct rpki_data *);
EXT void rpki_daemon(struct rpki_data *);
EXT int rpki_roas_map_load(char *, struct rpki_data *);
#undef EXT

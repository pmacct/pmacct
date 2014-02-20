/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2014 by Paolo Lucente
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

#define IES_PER_SFV5_MODULES_DB_ENTRY	32
#define SFV5_MODULES_DB_ENTRIES		8

/* structures */
struct sfv5_modules_db_field {
  u_int32_t type;
  u_char *ptr;
  u_int32_t len;
};

struct sfv5_modules_db {
  struct sfv5_modules_db_field ie[IES_PER_SFV5_MODULES_DB_ENTRY];
};

struct sfv5_modules_desc {
  u_int32_t type; /* ie. flow, counter, etc. */
  struct sfv5_modules_db db[SFV5_MODULES_DB_ENTRIES];
};

/* functions */
#if (!defined __SFV5_MODULE_C)
#define EXT extern
#else
#define EXT
#endif
EXT void sfv5_modules_db_init();
EXT struct sfv5_modules_db_field *sfv5_modules_db_get_ie(u_int32_t);
EXT struct sfv5_modules_db_field *sfv5_modules_get_next_ie(u_int32_t);
EXT struct sfv5_modules_db_field *sfv5_modules_db_get_next_ie(u_int32_t);

EXT struct sfv5_modules_desc sfv5_modules;
#undef EXT

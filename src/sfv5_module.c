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
#include "sflow.h"
#include "bgp/bgp_packet.h"
#include "bgp/bgp.h"
#include "sfacctd.h"
#include "sfv5_module.h"
#include "pmacct-data.h"

/* Global variables */
struct sfv5_modules_desc sfv5_modules;

void sfv5_modules_db_init()
{
  memset(&sfv5_modules, 0, sizeof(sfv5_modules));
}

struct sfv5_modules_db_field *sfv5_modules_db_get_ie(u_int32_t type)
{
  u_int16_t idx, modulo = (type%SFV5_MODULES_DB_ENTRIES);
  struct sfv5_modules_db_field *db_ptr = NULL;

  for (idx = 0; idx < IES_PER_SFV5_MODULES_DB_ENTRY; idx++) {
    if (sfv5_modules.db[modulo].ie[idx].type == type) {
      db_ptr = &sfv5_modules.db[modulo].ie[idx];
      break;
    }
  }

  return db_ptr;
}

struct sfv5_modules_db_field *sfv5_modules_db_get_next_ie(u_int32_t type)
{
  u_int16_t idx, modulo = (type%SFV5_MODULES_DB_ENTRIES);
  struct sfv5_modules_db_field *db_ptr = NULL;

  for (idx = 0; idx < IES_PER_SFV5_MODULES_DB_ENTRY; idx++) {
    if (sfv5_modules.db[modulo].ie[idx].type == 0) {
      db_ptr = &sfv5_modules.db[modulo].ie[idx];
      break;
    }
  }

  return db_ptr;
}

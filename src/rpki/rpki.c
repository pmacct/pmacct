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
#define __RPKI_C

/* includes */
#include "pmacct.h"
#include "bgp/bgp.h"
#include "rpki.h"

void rpki_roas_map_load(char *file, int type)
{
  struct bgp_misc_structs *bms;

  bms = bgp_select_misc_db(type);
  if (!bms) return ERR;

#if defined WITH_JANSSON
  // XXX
#else
  Log(LOG_WARNING, "WARN ( %s/%s ): rpki_roas_map will not load (missing --enable-jansson).\n", config.name, bms->log_str);
#endif
}

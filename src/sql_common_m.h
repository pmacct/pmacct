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

#ifndef SQL_COMMON_M_H
#define SQL_COMMON_M_H

#include "pmacct.h"
#include "sql_common.h"

extern void AddToLRUTail(struct db_cache *Cursor);

extern void RetireElem(struct db_cache *Cursor);

extern void BuildChain(struct db_cache *Cursor, struct db_cache *newElem);

extern void ReBuildChain(struct db_cache *Cursor, struct db_cache *newElem);

extern void SwapChainedElems(struct db_cache *Cursor, struct db_cache *staleElem);

extern void SQL_SetENV();

extern void SQL_SetENV_child(const struct insert_data *idata);

#endif //SQL_COMMON_M_H

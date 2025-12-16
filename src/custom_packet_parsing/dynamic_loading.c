/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2023 by Paolo Lucente
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

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include "pmacct.h"
#include "dynamic_loading.h"

enum dynlib_result dynlib_load_and_resolve(const struct dynlib lib) {
  void* handle = dlopen(lib.path, RTLD_NOW);
  // load the dynamic library from name/path
  if (!handle) {
    Log(LOG_ERR, "ERROR ( %s ): [dynlib] Could not load provided library %s: %s\n", config.name, lib.path,
        dlerror());
    return DL_Error;
  }

  struct dynlib_fn* fn;
  for (int index = 0; !dynlib_fn_end(fn = &lib.table[index]); index++) {
    // just ignore symbols we do not have a target for
    if (!fn->store)
      continue;

    // load symbol by name
    void* sym = dlsym(handle, fn->name);
    if (!sym) {
      printf("ERROR ( %s ): [dynlib] expected symbol \"%s\" not found in dynamic library %s.\n", config.name, fn->name,
             lib.path);
      return DL_Error;
    }

    // store symbol found into target address
    *fn->store = sym;
  }

  return DL_Success;
}
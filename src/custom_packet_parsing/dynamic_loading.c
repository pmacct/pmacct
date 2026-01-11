/*
 * Copyright (c) 2025 Maxence Younsi <maxence.younsi@insa-lyon.fr> and Pierre Weisse <pierre.weisse@insa-lyon.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include "pmacct.h"
#include "dynamic_loading.h"

bool dynlib_fn_end(const struct dynlib_fn* fn) {
  return !fn->name;
}

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
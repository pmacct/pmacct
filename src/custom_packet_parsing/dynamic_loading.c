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

#ifndef _DYNAMIC_LOADING_H_
#define _DYNAMIC_LOADING_H_

/// A dynamic library function target
struct dynlib_fn {
  /// Name of the symbol to lookup in the dynamic library
  const char* name;
  /// Where to store the pointer retrieved by dlsym
  void** store;
};

typedef struct dynlib_fn dynlib_table[];

/// Description of a dynamic library
struct dynlib {
  /// Library path (see @dlopen)
  const char* path;
  /// Array of @dynlib_fn describing the symbols to load
  /// MUST be terminated by an element with name == NULL
  struct dynlib_fn* table;
};

static bool dynlib_fn_end(const struct dynlib_fn* fn) {
  return !fn->name;
}

enum dynlib_result {
  DL_Error,
  DL_Success,
};

/// Load a dynamic library, retrieve symbols and store them where @dynlib_fn#store points to
extern enum dynlib_result dynlib_load_and_resolve(const struct dynlib lib);

#endif
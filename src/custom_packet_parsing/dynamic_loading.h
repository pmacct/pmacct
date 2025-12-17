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
/// see @dynlib for more details on the definition of a library
extern enum dynlib_result dynlib_load_and_resolve(const struct dynlib lib);

#endif
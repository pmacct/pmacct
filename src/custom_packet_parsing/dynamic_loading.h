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
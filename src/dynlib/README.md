# Introduction

This is the documentation for dynamic library loading in pmacct.

## Dynamic library loading

the `dynlib` files offer a generic way of loading a `.so` file and extracting specifically named functions from it into a list of function pointers.

This is meant to be a simple building block for creating modular extensions to pmacct's featureset like the `packet_processor` files.

Example usage can be found in `packet_processor.c` file in the `packet_processor_dynload` function.

This dynamic library loading works using the `dlopen` and `dlsym` linux functions.
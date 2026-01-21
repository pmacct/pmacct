# Introduction

This is documentation for dynamic library loading in pmacct and custom packet parsing libraries specifically

## Dynamic library loading

the `dynamic_loading` files offer a generic way of loading a `.so` file and extracting specifically named functions from it into a list of function pointers.

This is meant to be a simple building block for creating modular extensions to pmacct's featureset like the `packet_processor` files.

Example usage can be found in `packet_processor.c` file in the `packet_processor_dynload` function.

This dynamic library loading works using the `dlopen` and `dlsym` linux functions.

## Custom packet parsing libraries

With a compatible library providing functions with the signatures described in `packet_processor.h`, you can change the behavior of pmacct by replacing the following functions :
- `bgp_parse_msg` found in `pmacct/src/bgp/bgp_msg.h`
- `bmp_process_packet` found in `pmacct/src/bmp/bmp_msg.h`
- `bmp_peer_init` found in `pmacct/src/bmp/bmp_msg.h`
- `bmp_peer_close` found in `pmacct/src/bmp/bmp_msg.h`

The dynamic library is loaded at run time and stops execution during initial configuration if its loading causes an error (incorrect path, missing symbols).

its configuration key is `custom_packet_parsing_lib:{path to the dynamic library}`

### Implementation

Your custom packet parsing library MUST satisfy the following 4 requirements :
- have all of the functions listed above exposed with the same names
- take the same inputs and return the same types as the existing functions for their replacements
- uphold any invariants that those functions require internally in their replacements
- respect the C ABI for the replacements to existing functions

To reduce the burden of reimplementing such high level functions from the ground up, you can rely on pmacct's existing featureset and functions and build your library with pmacct as a dependency.

### Building 

If your library depends on pmacct, it will most likely depend at some level of the call stack on some structures which change size depending on pmacct build options, the most common being the `configuration` struct in `pmacct/src/cfg.h`.

In order to avoid any issues with different definitions of the same struct between the library and pmacct itself, you must build any library depending on pmacct with the same build configuration.

The easiest way that pmacct supports is as follows :
- configure pmacct to build as you want it to
- `make install` pmacct, this will install a `pmacct.pc` file in your system's `pkg-config` files and create a `config.h` file in `pmacct/src` with all pmacct symbols set to what the configuration requires
- in your library's build system, import pmacct CFLAGS and LDFLAGS from the `pmacct.pc` pkg-config file and pass them to the compiler which will compile pmacct as a dependency, the `config.h` file is already included in pmacct to properly set internal symbols for external compilation.
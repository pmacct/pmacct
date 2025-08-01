# Building pmacct

## Basics

```
autogen.sh
./configure
make
make install
```

## `configure`: environment variables

A list of environment variables to pass to `configure`:

```
  CC				C compiler command
  CFLAGS			C compiler flags
  LDFLAGS     			linker flags, e.g. -L<lib dir> if you have libraries in a
              			nonstandard directory <lib dir>
  LIBS        			libraries to pass to the linker, e.g. -l<library>
  CPPFLAGS    			(Objective) C/C++ preprocessor flags, e.g. -I<include dir> if
              			you have headers in a nonstandard directory <include dir>
  CPP         			C preprocessor
  PKG_CONFIG  			path to pkg-config utility
  PKG_CONFIG_PATH		directories to add to pkg-config's search path
  PKG_CONFIG_LIBDIR		path overriding pkg-config's built-in search path
  PGSQL_CFLAGS			C compiler flags for PGSQL, overriding pkg-config
  PGSQL_LIBS			linker flags for PGSQL, overriding pkg-config
  MONGODB_CFLAGS		C compiler flags for MONGODB, overriding pkg-config
  MONGODB_LIBS			linker flags for MONGODB, overriding pkg-config
  SQLITE3_CFLAGS		C compiler flags for SQLITE3, overriding pkg-config
  SQLITE3_LIBS			linker flags for SQLITE3, overriding pkg-config
  RABBITMQ_CFLAGS		C compiler flags for RABBITMQ, overriding pkg-config
  RABBITMQ_LIBS			linker flags for RABBITMQ, overriding pkg-config
  ZMQ_CFLAGS			C compiler flags for ZMQ, overriding pkg-config
  ZMQ_LIBS			linker flags for ZMQ, overriding pkg-config
  KAFKA_CFLAGS			C compiler flags for KAFKA, overriding pkg-config
  KAFKA_LIBS			linker flags for KAFKA, overriding pkg-config
  REDIS_CFLAGS			C compiler flags for REDIS, overriding pkg-config
  REDIS_LIBS			linker flags for REDIS, overriding pkg-config
  GNUTLS_CFLAGS			C compiler flags for GNUTLS, overriding pkg-config
  GNUTLS_LIBS			linker flags for GNUTLS, overriding pkg-config
  GEOIPV2_CFLAGS		C compiler flags for GEOIPV2, overriding pkg-config
  GEOIPV2_LIBS			linker flags for GEOIPV2, overriding pkg-config
  JANSSON_CFLAGS		C compiler flags for JANSSON, overriding pkg-config
  JANSSON_LIBS			linker flags for JANSSON, overriding pkg-config
  AVRO_CFLAGS			C compiler flags for AVRO, overriding pkg-config
  AVRO_LIBS			linker flags for AVRO, overriding pkg-config
  SERDES_CFLAGS			C compiler flags for SERDES, overriding pkg-config
  SERDES_LIBS			linker flags for SEREDES, overriding pkg-config
  NFLOG_CFLAGS			C compiler flags for NFLOG, overriding pkg-config
  NFLOG_LIBS			linker flags for NFLOG, overriding pkg-config
  NDPI_CFLAGS			C compiler flags for dynamic nDPI, overriding pkg-config
  NDPI_LIBS			linker flags for dynamic nDPI, overriding pkg-config
  UNYTE_UDP_NOTIF_CFLAGS	C compiler flags for dynamic Unyte UDP Notif, overriding pkg-config
  UNYTE_UDP_NOTIF_LIBS		linker flags for dynamic Unyte UDP Notif, overriding pkg-config
  GRPC_COLLECTOR_CFLAGS		C compiler flags for dynamic GRPC Collector, overriding pkg-config
  GRPC_COLLECTOR_LIBS		linker flags for dynamic GRPC Collector, overriding pkg-config
  EBPF_CFLAGS			C compiler flags for dynamic libbpf, overriding pkg-config
  EBPF_LIBS			linker flags for dynamic libbpf, overriding pkg-config
```

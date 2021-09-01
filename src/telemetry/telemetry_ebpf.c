/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2021 by Paolo Lucente
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

/* includes */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <signal.h>
#include <syslog.h>

#include "addr.h"
#include "log.h"
#include "telemetry_ebpf.h"

#ifdef WITH_EBPF
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#endif

/* Functions */
#ifdef WITH_UNYTE_UDP_NOTIF
#ifdef WITH_EBPF
static int libbpf_print_fn_unyte_udp_notif(enum libbpf_print_level level, const char *format, va_list args) {
  return level <= LIBBPF_DEBUG ? vfprintf(stderr, format, args) : 0;
}

int attach_ebpf_unyte_udp_notif(int fd, char *filename, u_int32_t key)
{
  int umap_fd, size_map_fd, prog_fd, local_fd = fd;
  u_int32_t balancer_count = 0;
  long err = 0;

  assert(fd >= 0);

  // set log
  libbpf_set_print(libbpf_print_fn_unyte_udp_notif);

  struct bpf_object_open_opts opts = {.sz = sizeof(struct bpf_object_open_opts),
                                      .pin_root_path = "/sys/fs/bpf/reuseport"};
  struct bpf_object *obj = bpf_object__open_file(filename, &opts);

  err = libbpf_get_error(obj);
  if (err) {
    Log(LOG_ERR, "ERROR: Failed to open BPF elf file\n");
    return -1;
  }

  struct bpf_map *udpmap = bpf_object__find_map_by_name(obj, "udp_balancing_targets");
  assert(udpmap);

  // Load BPF program to the kernel
  if (bpf_object__load(obj) != 0) {
    Log(LOG_ERR, "ERROR: Failed loading BPF object into kernel\n");
    return -1;
  }

  struct bpf_program *prog = bpf_object__find_program_by_name(obj, "_selector");
  if (!prog) {
    Log(LOG_ERR, "ERROR: Could not find BPF program in BPF object\n");
    return -1;
  }

  prog_fd = bpf_program__fd(prog);
  assert(prog_fd);

  umap_fd = bpf_map__fd(udpmap);
  assert(umap_fd);

  if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &prog_fd, sizeof(prog_fd)) != 0) {
    Log(LOG_ERR, "ERROR: Could not attach BPF prog\n");
    return -1;
  }

  if (bpf_map_update_elem(umap_fd, &key, &local_fd, BPF_ANY) != 0) {
    Log(LOG_ERR, "ERROR: Could not update reuseport array\n");
    return -1;
  }

  /*
     Determine intended number of hash buckets
     Assumption: static during lifetime of this process
  */
  struct bpf_map *size_map = bpf_object__find_map_by_name(obj, "size");
  assert(size_map);
  size_map_fd = bpf_map__fd(size_map);
  assert(size_map_fd);

  bpf_map_lookup_elem(size_map_fd, &key, &balancer_count);
  if (balancer_count == 0) {
    /* BPF program hasn't run yet to initalize this: exit */
  }
  else {
    if (bpf_map_update_elem(size_map_fd, &index, &balancer_count, BPF_ANY) != 0) {
      Log(LOG_ERR, "ERROR: Could not update balancer count\n");
      return -1;
    }
  }

  return local_fd;
}
#endif
#endif

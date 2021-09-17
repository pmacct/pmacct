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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <signal.h>
#include <syslog.h>

#include "addr.h"
#include "log.h"
#include "ebpf_rp_balancer.h"

#ifdef WITH_EBPF
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#endif

/* Functions */
#ifdef WITH_EBPF
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
  return level <= LIBBPF_DEBUG ? vfprintf(stderr, format, args) : 0;
}

int attach_ebpf_reuseport_balancer(int fd, char *filename, char *cluster_name, u_int32_t key, int is_tcp)
{
  char default_cluster_name[] = "default", path[256];
  int map_fd, prog_fd, ret;
  int64_t local_fd = fd;
  long err = 0;
  struct bpf_map *map;

  assert(fd >= 0);

  // set log
  libbpf_set_print(libbpf_print_fn);

  if (cluster_name) {
    snprintf(path, sizeof(path), "/pmacct/%s", cluster_name);
  }
  else {
    snprintf(path, sizeof(path), "/pmacct/%s", default_cluster_name);
  }

  struct bpf_object_open_opts opts = {.sz = sizeof(struct bpf_object_open_opts), .pin_root_path = path};
  struct bpf_object *obj = bpf_object__open_file(filename, &opts);

  err = libbpf_get_error(obj);
  if (err) {
    Log(LOG_ERR, "ERROR ( %s ): Failed to open BPF elf file\n", filename);
    return -1;
  }

  if (!is_tcp) {
    map = bpf_object__find_map_by_name(obj, "udp_balancing_targets");
  }
  else {
    map = bpf_object__find_map_by_name(obj, "tcp_balancing_targets");
  }
  assert(map);

  // Load BPF program to the kernel
  if (bpf_object__load(obj) != 0) {
    Log(LOG_ERR, "ERROR ( %s ): Failed loading BPF object into kernel\n", filename);
    return -1;
  }

  struct bpf_program *prog = bpf_object__find_program_by_name(obj, "_selector");
  if (!prog) {
    Log(LOG_ERR, "ERROR ( %s ): Could not find BPF program in BPF object\n", filename);
    return -1;
  }

  prog_fd = bpf_program__fd(prog);
  assert(prog_fd);

  map_fd = bpf_map__fd(map);
  assert(map_fd);

  if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &prog_fd, sizeof(prog_fd)) != 0) {
    Log(LOG_ERR, "ERROR ( %s ): Could not attach BPF prog\n", filename);
    return -1;
  }

  ret = bpf_map_update_elem(map_fd, &key, &local_fd, BPF_ANY);
  if (ret) {
    Log(LOG_ERR, "ERROR ( %s ): Could not update reuseport array (map=%d key=%d fd=%ld errno=%d\n", filename, map_fd, key, local_fd, errno);
    return -1;
  }
  else {
    Log(LOG_DEBUG, "DEBUG ( %s ): Updated reuseport array (map=%d key=%d fd=%ld\n", filename, map_fd, key, local_fd);
  }

  return local_fd;
}
#endif

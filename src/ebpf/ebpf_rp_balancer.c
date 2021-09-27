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
extern int mkdir_multilevel(const char *, int, uid_t, gid_t);

#ifdef WITH_EBPF
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
  return level <= LIBBPF_DEBUG ? vfprintf(stderr, format, args) : 0;
}

int attach_ebpf_reuseport_balancer(int fd, char *filename, char *cluster_name, char *aux, u_int32_t key, int is_tcp)
{
  char default_cluster_name[] = "default", path[256];
  u_int32_t nonce_key = 0, nonce_value = 12345;
  int map_fd, prog_fd, nonce_fd, ret;
  int64_t local_fd = fd;
  long err = 0;
  struct bpf_map *map, *nonce_map;
  uid_t owner = -1;
  gid_t group = -1;

  if (!filename) {
    Log(LOG_ERR, "ERROR: attach_ebpf_reuseport_balancer(): Invalid 'filename' supplied.\n");
    return -1;
  }

  if (fd < 0) {
    Log(LOG_ERR, "ERROR ( %s ): attach_ebpf_reuseport_balancer(): Invalid 'fd' supplied.\n", filename);
    return -1;
  }

  if (!filename) {
    Log(LOG_ERR, "ERROR ( %s ): attach_ebpf_reuseport_balancer(): No 'aux' string supplied.\n", filename);
    return -1;
  }

  // set log
  libbpf_set_print(libbpf_print_fn);

  if (cluster_name) {
    snprintf(path, sizeof(path), "/sys/fs/bpf/pmacct/%s/%s", cluster_name, aux);
  }
  else {
    snprintf(path, sizeof(path), "/sys/fs/bpf/pmacct/%s/%s", default_cluster_name, aux);
  }

  ret = mkdir_multilevel(path, 0, owner, group);
  if (ret) {
    Log(LOG_ERR, "ERROR ( %s ): attach_ebpf_reuseport_balancer(): mkdir_multilevel() failed.\n", filename);
    return -1;
  }

  struct bpf_object_open_opts opts = {.sz = sizeof(struct bpf_object_open_opts), .pin_root_path = path};
  struct bpf_object *obj = bpf_object__open_file(filename, &opts);

  err = libbpf_get_error(obj);
  if (err) {
    Log(LOG_ERR, "ERROR ( %s ): Failed to open BPF elf file\n", filename);
    return -1;
  }

  // nonce map
  nonce_map = bpf_object__find_map_by_name(obj, "nonce");
  assert(nonce_map);

  // balancing targets map
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

  nonce_fd = bpf_map__fd(nonce_map);
  assert(nonce_fd);

  map_fd = bpf_map__fd(map);
  assert(map_fd);

  ret = bpf_map_update_elem(nonce_fd, &nonce_key, &nonce_value, BPF_ANY);
  if (ret) {
    Log(LOG_ERR, "ERROR ( %s ): Could not update nonce array (map=%d key=%d fd=%d errno=%d\n", filename, nonce_fd, nonce_key, nonce_value, errno);
    return -1;
  }

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

/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2018 by Paolo Lucente
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

#define __JSONUDP_PLUGIN_C

/* includes */
#include "pmacct.h"
#include "addr.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "plugin_common.h"
#include "plugin_cmn_json.h"
#include "plugin_cmn_avro.h"
#include "print_plugin.h"
#include "ip_flow.h"
#include "classifier.h"
#include "crc32.h"
#include "bgp/bgp.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#if defined (WITH_NDPI)
#include "ndpi/ndpi.h"
#endif

/* Functions */

/*
 * Shamelessly stolen from src/nfprobe_plugin/nfprobe_plugin.c
 * Copy/paste because it is static there. TODO: Consolidate
 * into src/util.c.
 */
static void
parse_hostport(const char *s, struct sockaddr *addr, socklen_t *len)
{
  char *orig, *host, *port;
  struct addrinfo hints, *res;
  int herr;

  if ((host = orig = strdup(s)) == NULL) {
    Log(LOG_ERR, "ERROR ( %s/%s ): parse_hostport(), strdup() out of memory\n", config.name, config.type);
    exit_gracefully(1);
  }

  trim_spaces(host);
  trim_spaces(orig);

  if ((port = strrchr(host, ':')) == NULL || *(++port) == '\0' || *host == '\0') {
    Log(LOG_ERR, "ERROR ( %s/%s ): parse_hostport(), invalid 'jsonudp_server' argument\n", config.name, config.type);
    exit_gracefully(1);
  }
  *(port - 1) = '\0';
	
  /* Accept [host]:port for numeric IPv6 addresses */
  if (*host == '[' && *(port - 2) == ']') {
    host++;
    *(port - 2) = '\0';
  }

  memset(&hints, '\0', sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM;

  if ((herr = getaddrinfo(host, port, &hints, &res)) == -1) {
    Log(LOG_ERR, "ERROR ( %s/%s ): parse_hostport(), address lookup failed\n", config.name, config.type);
    exit_gracefully(1);
  }

  if (res == NULL || res->ai_addr == NULL) {
    Log(LOG_ERR, "ERROR ( %s/%s ): parse_hostport(), no addresses found for [%s]:%s\n", config.name, config.type, host, port);
    exit_gracefully(1);
  }

  if (res->ai_addrlen > *len) {
    Log(LOG_ERR, "ERROR ( %s/%s ): parse_hostport(), address too long.\n", config.name, config.type);
    exit_gracefully(1);
  }

  memcpy(addr, res->ai_addr, res->ai_addrlen);
  free(orig);
  *len = res->ai_addrlen;
}

int jsonudp_plugin_create_client(const struct sockaddr *server) {
  int client;

  if ((client = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    return -1;
  }
}

int jsonudp_plugin_shutdown_client(int client) {
  shutdown(client, SHUT_RDWR);
  close(client);
}

void jsonudp_plugin(int pipe_fd, struct configuration *cfgptr, void *ptr)
{
  struct pkt_data *data;
  struct sockaddr udp_server_addr;
  socklen_t udp_server_addr_len = sizeof(struct sockaddr);
  int udp_server_socket = -1;
  struct ports_table pt;
  unsigned char *pipebuf;
  struct pollfd pfd;
  int refresh_timeout, ret, num, recv_budget, poll_bypass;
  struct ring *rg = &((struct channels_list_entry *)ptr)->rg;
  struct ch_status *status = ((struct channels_list_entry *)ptr)->status;
  int datasize = ((struct channels_list_entry *)ptr)->datasize;
  u_int32_t bufsz = ((struct channels_list_entry *)ptr)->bufsize;
  pid_t core_pid = ((struct channels_list_entry *)ptr)->core_pid;
  struct networks_file_data nfd;
#ifdef WITH_ZMQ
  struct p_zmq_host zmq_host = {0,};
#endif

  unsigned char *rgptr;
  int pollagain = TRUE;
  u_int32_t seq = 1, rg_err_count = 0;

  struct extra_primitives extras;
  struct primitives_ptrs prim_ptrs;
  char *dataptr;

  int jsonudp_type_default = JSONUDP_TYPE_UDP;
  char *jsonudp_server_default = "127.0.0.1:5001";
#ifdef WITH_ZMQ
  u_int8_t jsonudp_topic_default = 1;
#endif

  /*
   * General plugin setup (Taken from print_plugin).
   */
  memcpy(&config, cfgptr, sizeof(struct configuration));
  memcpy(&extras, &((struct channels_list_entry *)ptr)->extras, sizeof(struct extra_primitives));
  recollect_pipe_memory(ptr);
  pm_setproctitle("%s [%s]", "JSON UDP Plugin", config.name);
  P_set_signals();
  P_init_default_values();
  P_config_checks();
  pipebuf = (unsigned char *) pm_malloc(config.buffer_size);

  /*
   * Zero out locals.
   */
  memset(pipebuf, 0, config.buffer_size);
  memset(&udp_server_addr, 0, sizeof(struct sockaddr));

  /*
   * Build a sockaddr from the jsonudp_server parameter.
   * If the user did not specify one, we will use a default.
   */

  if (config.jsonudp_server == NULL) {
    Log(LOG_WARNING, "WARNING ( %s/%s ): Using default server (%s).\n",
                     config.name, config.type, jsonudp_server_default);
    config.jsonudp_server = jsonudp_server_default;
  }
  if (!config.jsonudp_type) {
    Log(LOG_WARNING, "WARNING ( %s/%s ): Using default type (%s).\n",
                     config.name, config.type, jsonudp_type_default);
    config.jsonudp_type = jsonudp_type_default;
  }
  if (!config.jsonudp_topic) {
    /*
     * Only warn about a default topic if they are going to use ZeroMQ.
     */
#ifdef WITH_ZMQ
    if (config.jsonudp_type == JSONUDP_TYPE_ZEROMQ) {
      Log(LOG_WARNING, "WARNING ( %s/%s ): Using default topic (%d).\n",
                       config.name, config.type, jsonudp_topic_default);
    }
    config.jsonudp_topic = jsonudp_topic_default;
#endif
  }


  if (config.jsonudp_type == JSONUDP_TYPE_UDP) {
    parse_hostport(config.jsonudp_server,
                   &udp_server_addr,
                   &udp_server_addr_len);
    if ((udp_server_socket=jsonudp_plugin_create_client(&udp_server_addr))<0) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Could not connect to the server (%s). "
                   "Exiting.\n", config.name,config.type,config.jsonudp_server);
      exit_plugin(1);
    }
  } else {
#ifndef WITH_ZMQ
    Log(LOG_ERR, "ERROR ( %s/%s ): Not compiled with ZeroMQ support. "
                 "Exiting.\n", config.name,config.type);
    exit_plugin(1);
#else
    /*
     * NB: the library that sets the hostname automatically adds tcp://
     * to the start of the host. This is really important to know!
     */
    p_zmq_init_pub(&zmq_host, config.jsonudp_server, config.jsonudp_topic);
    p_zmq_pub_setup(&zmq_host);
#endif
  }

  /*
   * Setup cjhandlers to print the netflow record appropriately.
   * This is a prerequisite for using the cjhandler[] global.
   */
  compose_json(config.what_to_count, config.what_to_count_2);

  /*
   * How long to block when poll() for records from the parent.
   */
  refresh_timeout = config.sql_refresh_time*1000;

  /*
   * More general configuration (again, taken from print_plugin).
   */
  load_networks(config.networks_file, &nt, &nc);
  set_net_funcs(&nt);

  if (config.ports_file) load_ports(config.ports_file, &pt);

  memset(&prim_ptrs, 0, sizeof(prim_ptrs));
  set_primptrs_funcs(&extras);
  setnonblocking(pipe_fd);

  /* setting number of entries in _protocols structure */
  while (_protocols[protocols_number].number != -1) protocols_number++;

  /* plugin main loop (again, copied from print_plugin).*/
  for(;;) {
    poll_again:
    status->wakeup = TRUE;
    poll_bypass = FALSE;
    pfd.fd = pipe_fd;
    pfd.events = POLLIN;

    ret = poll(&pfd, (pfd.fd == ERR ? 0 : 1), refresh_timeout);

    if (ret <= 0) {
      if (getppid() != core_pid) {
        Log(LOG_ERR, "ERROR ( %s/%s ): Core process *seems* gone. Exiting.\n", config.name, config.type);
        exit_plugin(1);
      }

      if (ret < 0) goto poll_again;
    }

    poll_ops:
    recv_budget = 0;
    if (poll_bypass) {
      poll_bypass = FALSE;
      goto read_data;
    }

    switch (ret) {
    case 0: /* timeout */
      break;
    default: /* we received data */
      read_data:
      if (recv_budget == DEFAULT_PLUGIN_COMMON_RECV_BUDGET) {
	poll_bypass = TRUE;
	goto poll_ops;
      }

      if (config.pipe_homegrown) {
        if (!pollagain) {
          seq++;
          seq %= MAX_SEQNUM;
          if (seq == 0) rg_err_count = FALSE;
        }
        else {
          if ((ret = read(pipe_fd, &rgptr, sizeof(rgptr))) == 0)
	    exit_plugin(1); /* we exit silently; something happened at the write end */
        }

        if ((rg->ptr + bufsz) > rg->end) rg->ptr = rg->base;

	if (((struct ch_buf_hdr *)rg->ptr)->seq != seq) {
	  if (!pollagain) {
	    pollagain = TRUE;
	    goto poll_again;
	  }
          else {
            rg_err_count++;
            if (config.debug || (rg_err_count > MAX_RG_COUNT_ERR)) {
              Log(LOG_WARNING, "WARN ( %s/%s ): Missing data detected (plugin_buffer_size=%llu plugin_pipe_size=%llu).\n",
                        config.name, config.type, config.buffer_size, config.pipe_size);
              Log(LOG_WARNING, "WARN ( %s/%s ): Increase values or look for plugin_buffer_size, plugin_pipe_size in CONFIG-KEYS document.\n\n",
                        config.name, config.type);
            }
	    rg->ptr = (rg->base + status->last_buf_off);
            seq = ((struct ch_buf_hdr *)rg->ptr)->seq;
          }
        }

        pollagain = FALSE;
        memcpy(pipebuf, rg->ptr, bufsz);
        rg->ptr += bufsz;
      }
      data = (struct pkt_data *) (pipebuf+sizeof(struct ch_buf_hdr));
      if (config.debug_internal_msg)
        Log(LOG_DEBUG, "DEBUG ( %s/%s ): buffer received len=%llu seq=%u num_entries=%u\n",
                config.name, config.type, ((struct ch_buf_hdr *)pipebuf)->len, seq,
                ((struct ch_buf_hdr *)pipebuf)->num);

      while (((struct ch_buf_hdr *)pipebuf)->num > 0) {
	for (num = 0; primptrs_funcs[num]; num++)
	  (*primptrs_funcs[num])((u_char *)data, &extras, &prim_ptrs);

	for (num = 0; net_funcs[num]; num++)
	  (*net_funcs[num])(&nt, &nc, &data->primitives, prim_ptrs.pbgp, &nfd);

	if (config.ports_file) {
          if (!pt.table[data->primitives.src_port]) data->primitives.src_port = 0;
          if (!pt.table[data->primitives.dst_port]) data->primitives.dst_port = 0;
        }

        /*
         * If there is support, we are going to convert the
         * data packet that we just received into a JSON-formatted
         * 'thing' and send it to the specified host on the specified
         * port.
         */
#ifdef WITH_JANSSON
        /*
         * We need a chained_cache entry to wrap the packet
         * so that we can use cjhandler functions.
         */
        struct chained_cache tmp_cc;
        memset(&tmp_cc, 0, sizeof(struct chained_cache));
        memcpy(&tmp_cc.primitives,
               &data->primitives,
               sizeof(struct pkt_primitives));
        tmp_cc.bytes_counter = data->pkt_len;
        tmp_cc.packet_counter = data->pkt_num;
        tmp_cc.flow_counter = data->flo_num;

        /*
         * Use cjhandlers to format the record in JSON
         */
        json_t *json_obj = json_object();
	for (int idx = 0; idx < N_PRIMITIVES && cjhandler[idx]; idx++) {
          cjhandler[idx](json_obj, &tmp_cc);
        }

        /*
         * Assuming nothing went wrong, transmit!
         */
        if (json_obj) {
          char *json_output = compose_json_str(json_obj);
          ssize_t json_output_len = strlen(json_output);
          if (json_output != NULL) {
            if (config.jsonudp_type == JSONUDP_TYPE_UDP) {
              /*
               * send via udp.
               */
              if (sendto(udp_server_socket,
                         json_output,
                         json_output_len, 0,
                         (struct sockaddr*)&udp_server_addr,
                         sizeof(struct sockaddr)) != json_output_len) {
                Log(LOG_ERR, "ERROR ( %s/%s ): Error forwarding record "
                             "via UDP.\n",
                              config.name,
                              config.type);
              }
            } else {
#ifdef WITH_ZMQ
              /*
               * send via zeromq.
               */
              if (!p_zmq_topic_send(&zmq_host, json_output, json_output_len)) {
                Log(LOG_ERR, "ERROR ( %s/%s ): Error forwarding record "
                             "via ZeroMQ.\n",
                              config.name,
                              config.type);
              }
#endif
            }
          }
          free(json_output);
        }
#endif

	((struct ch_buf_hdr *)pipebuf)->num--;
        if (((struct ch_buf_hdr *)pipebuf)->num) {
          dataptr = (unsigned char *) data;
          if (!prim_ptrs.vlen_next_off) dataptr += datasize;
	  else dataptr += prim_ptrs.vlen_next_off;
          data = (struct pkt_data *) dataptr;
	}
      }

      recv_budget++;
      goto read_data;
    }
  }
}

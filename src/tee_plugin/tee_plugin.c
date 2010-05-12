/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2010 by Paolo Lucente
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

#define __TEE_PLUGIN_C

#include "../pmacct.h"
#include "tee_plugin.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"

void tee_plugin(int pipe_fd, struct configuration *cfgptr, void *ptr)
{
  struct pkt_msg *msg;
  unsigned char *pipebuf;
  struct pollfd pfd;
  int timeout, err;
  int ret, num, fd;
  struct ring *rg = &((struct channels_list_entry *)ptr)->rg;
  struct ch_status *status = ((struct channels_list_entry *)ptr)->status;
  u_int32_t bufsz = ((struct channels_list_entry *)ptr)->bufsize;
  char *dataptr, dest_addr[256], dest_serv[256];

  struct sockaddr_storage dest;
  socklen_t dest_len;

  unsigned char *rgptr;
  int pollagain = TRUE;
  u_int32_t seq = 1, rg_err_count = 0;

  /* XXX: glue */
  memcpy(&config, cfgptr, sizeof(struct configuration));
  recollect_pipe_memory(ptr);
  pm_setproctitle("%s [%s]", "Tee Plugin", config.name);
  if (config.pidfile) write_pid_file_plugin(config.pidfile, config.type, config.name);

  /* signal handling */
  signal(SIGINT, Tee_exit_now);
  signal(SIGUSR1, SIG_IGN);
  signal(SIGUSR2, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);
#if !defined FBSD4
  signal(SIGCHLD, SIG_IGN);
#else
  signal(SIGCHLD, ignore_falling_child);
#endif

  if (config.tee_transparent && getuid() != 0) {
    Log(LOG_ERR, "ERROR ( %s/%s ): Transparent mode requires super-user permissions. Exiting ...\n", config.name, config.type);
    exit_plugin(1);
  }

  if (!config.nfprobe_receiver) {
    Log(LOG_ERR, "ERROR ( %s/%s ): tee_receiver is not specified. Exiting ...\n", config.name, config.type);
    exit_plugin(1);
  }

  memset(&dest, 0, sizeof(dest));
  dest_len = sizeof(dest);
  Tee_parse_hostport(config.nfprobe_receiver, (struct sockaddr *)&dest, &dest_len);

  config.print_refresh_time = DEFAULT_TEE_REFRESH_TIME;
  timeout = config.print_refresh_time*1000;

  pipebuf = (unsigned char *) Malloc(config.buffer_size);

  pfd.fd = pipe_fd;
  pfd.events = POLLIN;
  setnonblocking(pipe_fd);

  memset(pipebuf, 0, config.buffer_size);

  /* Arrange send socket */
  if (dest.ss_family != 0) {
    if ((err = getnameinfo((struct sockaddr *) &dest,
            dest_len, dest_addr, sizeof(dest_addr),
            dest_serv, sizeof(dest_serv), NI_NUMERICHOST)) == -1) {
      Log(LOG_ERR, "ERROR ( %s/%s ): getnameinfo: %d\n", config.name, config.type, err);
      exit_plugin(1);
    }
    fd = Tee_prepare_sock(&dest, dest_len);
  }

  /* plugin main loop */
  for (;;) {
    poll_again:
    status->wakeup = TRUE;
    ret = poll(&pfd, 1, timeout);
    if (ret < 0) goto poll_again;

    switch (ret) {
    case 0: /* timeout */
      /* reserved for future since we don't currently cache/batch/etc */
      break;
    default: /* we received data */
      read_data:
      if (!pollagain) {
        seq++;
        seq %= MAX_SEQNUM;
        if (seq == 0) rg_err_count = FALSE;
      }
      else {
        if ((ret = read(pipe_fd, &rgptr, sizeof(rgptr))) == 0)
          exit_plugin(1); /* we exit silently; something happened at the write end */
      }

      if (((struct ch_buf_hdr *)rg->ptr)->seq != seq) {
        if (!pollagain) {
          pollagain = TRUE;
          goto poll_again;
        }
        else {
          rg_err_count++;
          if (config.debug || (rg_err_count > MAX_RG_COUNT_ERR)) {
            Log(LOG_ERR, "ERROR ( %s/%s ): We are missing data.\n", config.name, config.type);
            Log(LOG_ERR, "If you see this message once in a while, discard it. Otherwise some solutions follow:\n");
            Log(LOG_ERR, "- increase shared memory size, 'plugin_pipe_size'; now: '%u'.\n", config.pipe_size);
            Log(LOG_ERR, "- increase buffer size, 'plugin_buffer_size'; now: '%u'.\n", config.buffer_size);
            Log(LOG_ERR, "- increase system maximum socket size.\n\n");
          }
          seq = ((struct ch_buf_hdr *)rg->ptr)->seq;
        }
      }

      pollagain = FALSE;
      memcpy(pipebuf, rg->ptr, bufsz);
      if ((rg->ptr+bufsz) >= rg->end) rg->ptr = rg->base;
      else rg->ptr += bufsz;

      msg = (struct pkt_msg *) (pipebuf+sizeof(struct ch_buf_hdr));

      while (((struct ch_buf_hdr *)pipebuf)->num) {
        Tee_send(msg, fd);

        ((struct ch_buf_hdr *)pipebuf)->num--;
        if (((struct ch_buf_hdr *)pipebuf)->num) {
	  dataptr = (unsigned char *) msg;
          dataptr += PmsgSz;
	  msg = (struct pkt_msg *) dataptr;
	}
      }
      goto read_data;
    }
  }  
}

void Tee_exit_now(int signum)
{
  wait(NULL);
  exit_plugin(0);
}

void Tee_send(struct pkt_msg *msg, int target)
{
  if (config.debug) {
    struct host_addr a;
    u_char agent_addr[50];
    u_int16_t agent_port;

    sa_to_addr((struct sockaddr *)msg, &a, &agent_port);
    addr_to_str(agent_addr, &a);
    Log(LOG_DEBUG, "DEBUG ( %s/%s ): Sending NetFlow packet from [%s:%u] seqno [%u] to [%s]\n",
			config.name, config.type, agent_addr, agent_port, msg->seqno, config.nfprobe_receiver);
  }

  if (!config.tee_transparent) {
    if (send(target, msg->payload, msg->len, 0) == -1)
      Log(LOG_ERR, "ERROR ( %s/%s ): send() to [%s] failed\n", config.name, config.type, config.nfprobe_receiver);
  }
  else {
  }
}

int Tee_prepare_sock(struct sockaddr_storage *addr, socklen_t len)
{
  int s, ret = 0;
  struct host_addr source_ip;
  struct sockaddr ssource_ip;

  if (config.nfprobe_source_ip) {
    ret = str_to_addr(config.nfprobe_source_ip, &source_ip);
    addr_to_sa(&ssource_ip, &source_ip, 0);
  }

  if ((s = socket(addr->ss_family, SOCK_DGRAM, 0)) == -1) {
    Log(LOG_ERR, "ERROR ( %s/%s ): socket() error: %s\n", config.name, config.type, strerror(errno));
    exit_plugin(1);
  }

  /* XXX: SNDBUF tuning? */

  if (ret && bind(s, (struct sockaddr *) &ssource_ip, sizeof(ssource_ip)) == -1)
    Log(LOG_ERR, "ERROR ( %s/%s ): bind() error: %s\n", config.name, config.type, strerror(errno));

  if (connect(s, (struct sockaddr*)addr, len) == -1) {
    Log(LOG_ERR, "ERROR ( %s/%s ): connect() error: %s\n", config.name, config.type, strerror(errno));
    exit_plugin(1);
  }

  return(s);
}

// XXX: duplicate function
void Tee_parse_hostport(const char *s, struct sockaddr *addr, socklen_t *len)
{
        char *orig, *host, *port;
        struct addrinfo hints, *res;
        int herr;

        if ((host = orig = strdup(s)) == NULL) {
                fprintf(stderr, "Out of memory\n");
                exit_plugin(1);
        }

        trim_spaces(host);
        trim_spaces(orig);

        if ((port = strrchr(host, ':')) == NULL ||
            *(++port) == '\0' || *host == '\0') {
                fprintf(stderr, "Invalid -n argument.\n");
                exit_plugin(1);
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
                fprintf(stderr, "Address lookup failed: %s\n",
                    gai_strerror(herr));
                exit_plugin(1);
        }
        if (res == NULL || res->ai_addr == NULL) {
                fprintf(stderr, "No addresses found for [%s]:%s\n", host, port);
                exit_plugin(1);
        }
        if (res->ai_addrlen > *len) {
                Log(LOG_ERR, "ERROR ( %s/%s ): Address too long.\n", config.name, config.type);
                exit_plugin(1);
        }
        memcpy(addr, res->ai_addr, res->ai_addrlen);
        free(orig);
        *len = res->ai_addrlen;
}

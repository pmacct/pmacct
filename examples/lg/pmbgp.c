/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2017 by Paolo Lucente
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

#define __PMBGP_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "addr.h"
#include "zmq_common.h"
#include "bgp/bgp.h"
#include "pmbgpd.h"
#include "pmbgp.h"

/* functions */
#ifdef WITH_ZMQ
void usage_pmbgp(char *prog)
{
  printf("%s %s (%s)\n", PMBGP_USAGE_HEADER, PMACCT_VERSION, PMACCT_BUILD);
  printf("Usage: %s [query]\n\n", prog);
  printf("Queries:\n");
  printf("  -p\tIP prefix to look up\n");
  printf("  -P\tBGP peer routing table to look up\n");
  printf("  -z\tpmbgpd Looking Glass IP address [default: 127.0.0.1]\n");
  printf("  -Z\tpmbgpd Looking Glass port [default: 17900]\n");
  printf("\n");
  printf("  -h\tShow this page\n");
  printf("  -V\tPrint version and exit\n");
  printf("\n");
  printf("For suggestions, critics, bugs, contact me: %s.\n", MANTAINER);
}

void version_pmbgp(char *prog)
{
  printf("%s %s (%s)\n", PMBGP_USAGE_HEADER, PMACCT_VERSION, PMACCT_BUILD);
  printf("\n");
  printf("For suggestions, critics, bugs, contact me: %s.\n", MANTAINER);
}

int main(int argc,char **argv)
{
  char prefix_str[SRVBUFLEN], peer_str[SRVBUFLEN];
  char *zmq_host_str_ptr, zmq_host_str[SRVBUFLEN], default_zmq_host_str[] = "127.0.0.1";
  int ret, zmq_port = 0, default_zmq_port = 17900;

  struct p_zmq_host zmq_host;
  struct pm_bgp_lg_req req;
  struct pm_bgp_lg_rep rep;
  struct host_addr prefix_ha;

  /* getopt() stuff */
  extern char *optarg;
  extern int optind, opterr, optopt;
  int errflag, cp;

  memset(prefix_str, 0, sizeof(prefix_str));
  memset(peer_str, 0, sizeof(peer_str));
  memset(zmq_host_str, 0, sizeof(zmq_host_str));
  memset(&zmq_host, 0, sizeof(zmq_host));
  memset(&req, 0, sizeof(req));
  memset(&rep, 0, sizeof(rep));

  while (!errflag && ((cp = getopt(argc, argv, ARGS_PMBGP)) != -1)) {
    switch (cp) {
    case 'h':
      usage_pmbgp(argv[0]);
      exit(0);
      break;
    case 'V':
      version_pmbgp(argv[0]);
      exit(0);
      break;
    case 'p':
      strlcpy(prefix_str, optarg, sizeof(prefix_str));
      break;
    case 'P':
      strlcpy(peer_str, optarg, sizeof(peer_str));
      break;
    case 'z':
      strlcpy(zmq_host_str, optarg, sizeof(zmq_host_str));
      break;
    case 'Z':
      zmq_port = atoi(optarg);
      break;
    default:
      printf("ERROR: parameter %c unknown! \n  Exiting...\n\n", cp);
      usage_pmbgp(argv[0]);
      exit(1);
      break;
    }
  }

  if (!strlen(prefix_str) || !strlen(peer_str)) {
    printf("ERROR: mandatory options, -p and/or -P, are not specified. Exiting ..\n");
    exit(1);
  }
  
  if (!strlen(zmq_host_str)) zmq_host_str_ptr = default_zmq_host_str; 
  else zmq_host_str_ptr = zmq_host_str; 

  if (!zmq_port) zmq_port = default_zmq_port;

  /* craft query */
  {
    struct host_addr peer_addr;

    str_to_addr(peer_str, &peer_addr);
    addr_to_sa(&req.peer, &peer_addr, FALSE /* XXX: support for BGP port to be added */);
  }

  str_to_addr(prefix_str, &prefix_ha);  
  req.pref.family = prefix_ha.family;
  if (prefix_ha.family == AF_INET) {
    memcpy(&req.pref.u.prefix4, &prefix_ha.address.ipv4, sizeof(struct in_addr));
    req.pref.prefixlen = 32; /* XXX: support for masks to be added */
  }
  else if (prefix_ha.family == AF_INET6) {
    memcpy(&req.pref.u.prefix6, &prefix_ha.address.ipv6, sizeof(struct in6_addr));
    req.pref.prefixlen = 128; /* XXX: support for masks to be added */
  }

  pmbgp_zmq_req_setup(&zmq_host, zmq_host_str_ptr, zmq_port);

  pmbgp_zmq_send_bin(&zmq_host.sock, &req, sizeof(req)); 
  pmbgp_zmq_recv_bin(&zmq_host.sock, &rep, sizeof(rep)); 

  // XXX
}

void pmbgp_zmq_req_setup(struct p_zmq_host *zmq_host, char *host, int port)
{
  int ret;

  if (!zmq_host->ctx) zmq_host->ctx = zmq_ctx_new();

  zmq_host->sock.obj = zmq_socket(zmq_host->ctx, ZMQ_REQ);
  if (!zmq_host->sock.obj) {
    printf("ERROR: zmq_socket() failed for ZMQ_REQ: %s. Exiting.\n", zmq_strerror(errno));
    exit(1);
  }

  snprintf(zmq_host->sock.str, sizeof(zmq_host->sock.str), "tcp://%s:%u", host, port);

  ret = zmq_connect(zmq_host->sock.obj, zmq_host->sock.str);
  if (ret == ERR) {
    printf("ERROR: zmq_connect() failed for ZMQ_REQ: %s. Exiting.\n", zmq_strerror(errno));
    exit(1);
  }
}

int pmbgp_zmq_recv_bin(struct p_zmq_sock *sock, void *buf, int len)
{
  int rcvlen;

  rcvlen = zmq_recv(sock->obj, buf, len, 0);
  if (rcvlen == ERR) {
    printf("ERROR: zmq_recv() failed for ZMQ_REQ: %s. Exiting.\n", zmq_strerror(errno));
    exit(1);
  }

  return rcvlen;
}

int pmbgp_zmq_send_bin(struct p_zmq_sock *sock, void *buf, int len)
{
  int sndlen;

  sndlen = zmq_send(sock->obj, buf, len, 0);
  if (sndlen == ERR) {
    printf("ERROR: zmq_send() failed for ZMQ_REQ: %s. Exiting.\n", zmq_strerror(errno));
    exit(1);
  }

  return sndlen;
}
#else
int main(int argc,char **argv)
{
  printf("WARN: pmbgp: tool depends on missing --enable-zmq. Exiting.\n");
}
#endif

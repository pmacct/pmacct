#include "pmacct.h"
#include "addr.h"
#include "network.h"

struct tunnel_handler tunnel_registry[TUNNEL_REGISTRY_STACKS][TUNNEL_REGISTRY_ENTRIES];

int parse_proxy_header(int fd, struct host_addr *addr, u_int16_t *port)
{
  const char v2sig[12] = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";
  char ip_address[INET6_ADDRSTRLEN];
  size_t size = 0;
  proxy_protocol_header hdr;

  addr_to_str(ip_address, addr);

  int ret = recv(fd, &hdr, sizeof(hdr), MSG_PEEK);

  /* 16 bytes can detect both V1 and V2 protocols */
  if (ret < 16) {
    return -1;
  }

  if (memcmp(hdr.v1.line, "PROXY", 5) == 0) {
    Log(LOG_DEBUG, "DEBUG Proxy Protocol V1\n");

    char *end = memchr(hdr.v1.line, '\r', ret - 1);
    if (!end || end[1] != '\n')  {
      return -1;
    }
    end = '\0';

    /* V1 Header contains string: PROXY TCP4 <src ip> <dst ip> <src port> <dst port>\r\n */
    Log(LOG_INFO, "INFO Replacing: %s:%u\n", ip_address, *port);

    /* Find the Source IP Address */
    char *s = &hdr.v1.line[11];
    char *e = strchr(s, ' ');
    snprintf(ip_address, (e - s + 1), "%s", s);

    /* Find the Source TCP Port */
    s = e + 1;
    e = strchr(s, ' ');
    s = e + 1;
    *port = strtoul(s, 0, 10);

    Log(LOG_INFO, "                with Proxy Protocol V1 containing: %s:%u\n", ip_address, *port);
    str_to_addr(ip_address, addr);

    /* Consume the proxy protocol header for real, skip header + CRLF */
    size = (end + 2 - hdr.v1.line);
  }
  else if (memcmp(&hdr.v2, v2sig, 12) == 0) {
    Log(LOG_DEBUG, "DEBUG Proxy Protocol V2\n");

    size = (16 + ntohs(hdr.v2.len));
    if (ret < size) {
      return -1;
    }

    if (((hdr.v2.ver_cmd & 0xF0) == 0x20) && ((hdr.v2.ver_cmd & 0x0F) == 0x01)) {
      Log(LOG_DEBUG, "DEBUG Proxy Protocol PROXY command\n");

      if (hdr.v2.fam == 0x11) {
        Log(LOG_DEBUG, "DEBUG Proxy Protocol TCP/IPv4\n");

        /* Replace IP address string originally obtained from socket */
        Log(LOG_INFO, "INFO Replacing: %s:%u\n", ip_address, *port);
        addr->family = AF_INET;
        memcpy(&addr->address.ipv4.s_addr, &hdr.v2.addr.ip4.src_addr, sizeof(hdr.v2.addr.ip4.src_addr));
        *port = ntohs(hdr.v2.addr.ip4.src_port);

        addr_to_str(ip_address, addr);
        Log(LOG_INFO, "                with Proxy Protocol V2 containing: %s:%u\n", ip_address, *port);
      }
      else {
        Log(LOG_DEBUG, "DEBUG Proxy Protocol (TODO) Unsupported family: %u\n", hdr.v2.fam);
      }
    }
    else if (((hdr.v2.ver_cmd & 0xF0) == 0x20) && ((hdr.v2.ver_cmd & 0x0F) == 0x00)) {
      /* LOCAL Command. Health Check. Use real conection endpoints. */
      Log(LOG_DEBUG, "DEBUG Proxy Protocol LOCAL command\n");
    }
  }
  else {
    Log(LOG_DEBUG, "DEBUG Not Proxy Protocol\n");
  }

  if (size > 0) {
    /* Consume the proxy protocol header for real */
    ret = recv(fd, &hdr, size, 0);
  }

  return 0;
}

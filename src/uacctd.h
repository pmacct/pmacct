#ifdef ENABLE_ULOG

/* Linux NetFilter ULOG stuff */
#include <asm/types.h>
#include <linux/socket.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4/ipt_ULOG.h>

#define ULOG_BUFLEN 10480 /*should be enough room up to 9K Ethernet jumbo frames */
#define DEFAULT_ULOG_GROUP 1

#ifndef SOL_NETLINK
#define SOL_NETLINK    270
#endif

#ifndef NETLINK_NO_ENOBUFS
#define NETLINK_NO_ENOBUFS 5
#endif

/* functions */
#if (!defined __UACCTD_C)
#define EXT extern
#else
#define EXT
EXT unsigned int get_ifindex(char *);
#endif
#undef EXT

#endif

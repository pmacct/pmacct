/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2015 by Paolo Lucente
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
#include <stdarg.h>
#include <sys/stat.h>

/* defines */
#define LOGSTRLEN LONGSRVBUFLEN 

struct _facility_map {
  char string[10];
  int num;
};

static const struct _facility_map facility_map[] = {
	{"auth", LOG_AUTH},
	{"mail", LOG_MAIL},
	{"daemon", LOG_DAEMON},
	{"kern", LOG_KERN},
	{"user", LOG_USER},
	{"local0", LOG_LOCAL0},
	{"local1", LOG_LOCAL1},
	{"local2", LOG_LOCAL2},
	{"local3", LOG_LOCAL3},
	{"local4", LOG_LOCAL4},
	{"local5", LOG_LOCAL5},
	{"local6", LOG_LOCAL6},
	{"local7", LOG_LOCAL7},
	{"-1", -1},
};

struct _log_notifications {
  u_int8_t max_classifiers;
  u_int8_t bgp_peers_throttling;
  u_int8_t bmp_peers_throttling;
  u_int8_t geoip_ipv4_file_null;
  u_int8_t geoip_ipv6_file_null;
};

/* prototypes */
#if (!defined __LOG_C)
#define EXT extern
#else
#define EXT
#endif
EXT void Log(short int, char *, ...);
EXT int parse_log_facility(const char *);
EXT void log_notifications_init(struct _log_notifications *);
EXT void log_notification_set(u_int8_t *);
EXT void log_notification_unset(u_int8_t *);
EXT int log_notification_isset(u_int8_t);

/* global vars */
EXT struct _log_notifications log_notifications;
#undef EXT

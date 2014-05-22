/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2014 by Paolo Lucente
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
    along with this program; if no, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#define __LOG_C

/* includes */
#include "pmacct.h"
#if defined WITH_RABBITMQ
#include "amqp_common.h"
#endif 

/* functions */
void Log(short int level, char *msg, ...)
{
  va_list ap;
  char syslog_string[LOGSTRLEN];
  
  if ((level == LOG_DEBUG) && (!config.debug && !debug)) return;

#if defined WITH_RABBITMQ
  if (!config.syslog && !config.logfile_fd && !log_amqp_host.routing_key) {
#else
  if (!config.syslog && !config.logfile_fd) {
#endif
    va_start(ap, msg);
    vprintf(msg, ap);
    va_end(ap);
    fflush(stdout);
  }
  else {
    va_start(ap, msg);
    vsnprintf(syslog_string, LOGSTRLEN, msg, ap);
    va_end(ap);

    if (config.syslog) syslog(level, syslog_string);

    if (config.logfile_fd) {
      char timebuf[SRVBUFLEN];
      struct tm *tmnow;
      time_t now;

      now = time(NULL);
      tmnow = localtime(&now);
      strftime(timebuf, SRVBUFLEN, "%b %d %H:%M:%S", tmnow);

      fprintf(config.logfile_fd, "%s %s", timebuf, syslog_string);
      fflush(config.logfile_fd);
    }

#if defined WITH_RABBITMQ
    if (log_amqp_host.routing_key) {
      char *json_str = NULL;
      int ret;

      json_str = compose_log_json(syslog_string);

      if (json_str) {
        ret = p_amqp_publish(&log_amqp_host, json_str, AMQP_PUBLISH_LOG);
        free(json_str);
      }
    }
#endif
  }
}

int parse_log_facility(const char *facility)
{
  int i;
  
  for (i = 0; facility_map[i].num != -1; i++) {
    if (!strcmp(facility, facility_map[i].string))
      return facility_map[i].num; 
  }

  return ERR;
}

void log_notifications_init(struct _log_notifications *ln)
{
  if (ln) {
    memset(ln, 0, sizeof(struct _log_notifications));
  }
}

void log_notification_set(u_int8_t *elem)
{
  *elem = TRUE;
}

void log_notification_unset(u_int8_t *elem)
{
  *elem = FALSE;
}

int log_notification_isset(u_int8_t elem)
{
  if (elem == TRUE) return TRUE;
  else return FALSE;
}

#if defined WITH_RABBITMQ
void log_init_amqp_host()
{
  p_amqp_init_host(&log_amqp_host);

  p_amqp_set_user(&log_amqp_host, config.log_amqp_user);
  p_amqp_set_passwd(&log_amqp_host, config.log_amqp_passwd);
  p_amqp_set_exchange(&log_amqp_host, config.log_amqp_exchange);
  p_amqp_set_routing_key(&log_amqp_host, config.log_amqp_routing_key);
  p_amqp_set_exchange_type(&log_amqp_host, config.log_amqp_exchange_type);
  p_amqp_set_host(&log_amqp_host, config.log_amqp_host);
  p_amqp_set_persistent_msg(&log_amqp_host, config.log_amqp_persistent_msg);
}
#else
void log_init_amqp_host()
{
}
#endif

/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2023 by Paolo Lucente
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

/* includes */
#include "pmacct.h"

/* Global variables */
struct _log_notifications log_notifications;


/* functions */
void Log(short int level, char *msg, ...)
{
  va_list ap;

  if ((level == LOG_DEBUG) && (!config.debug && !debug)) return;

  if (!config.syslog && !config.logfile_fd) {
    va_start(ap, msg);
    vfprintf(stderr, msg, ap);
    va_end(ap);
    fflush(stderr);
  }
  else {
    if (config.syslog) {
      va_start(ap, msg);
      vsyslog(level, msg, ap);
      va_end(ap);
    }

    if (config.logfile_fd) {
      char timebuf[SRVBUFLEN];
      struct tm result_tm, *tmnow;
      time_t now;

      now = time(NULL);
      if (!config.timestamps_utc) {
	tmnow = localtime_r(&now, &result_tm);
      }
      else {
	tmnow = gmtime_r(&now, &result_tm);
      }

      strftime(timebuf, SRVBUFLEN, "%Y-%m-%dT%H:%M:%S", tmnow);
      append_rfc3339_timezone(timebuf, SRVBUFLEN, tmnow);

      fprintf(config.logfile_fd, "%s ", timebuf);
      va_start(ap, msg);
      vfprintf(config.logfile_fd, msg, ap);
      va_end(ap);
      fflush(config.logfile_fd);
    }
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

void log_notification_init(struct log_notification *ln)
{
  if (ln) {
    memset(ln, 0, sizeof(struct log_notification));
  }
}

void log_notifications_init(struct _log_notifications *ln)
{
  if (ln) {
    memset(ln, 0, sizeof(struct _log_notifications));
  }
}

int log_notification_set(struct log_notification *ln, time_t now, int timeout)
{
  if (ln) {
    ln->knob = TRUE;
    if (now) ln->stamp = now;
    else ln->stamp = time(NULL);
    ln->timeout = timeout;

    return SUCCESS;
  }
  else return ERR;
}

int log_notification_unset(struct log_notification *ln)
{
  if (ln) {
    log_notification_init(ln);

    return SUCCESS;
  }
  else return ERR;
}

int log_notification_isset(struct log_notification *ln, time_t now)
{
  time_t now_local;

  if (ln) {
    if (ln->timeout) {
      if (!now) now_local = time(NULL);
      else now_local = now;

      if (now_local < (ln->stamp + ln->timeout)) {
        /* valid */
        if (ln->knob == TRUE) return TRUE;
        else return FALSE;
      }
      else {
        /* expired */
        log_notification_unset(ln);
        return FALSE;
      }
    }
    else {
      if (ln->knob == TRUE) return TRUE;
      else return FALSE;
    }
  }

  return ERR;
}

/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2013 by Paolo Lucente
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

#define __UTIL_C

/* includes */
#include "pmacct.h"

static const char pkt_len_distrib_unknown[] = "unknown";

/* functions */
void setnonblocking(int sock)
{
  int opts;

  opts = fcntl(sock,F_GETFL);
  opts = (opts | O_NONBLOCK);
  fcntl(sock,F_SETFL,opts);
}

void setblocking(int sock)
{
  int opts;

  opts = fcntl(sock, F_GETFL);
  opts & O_NONBLOCK ? opts ^= O_NONBLOCK : opts;
  fcntl(sock, F_SETFL, opts);
}

int daemonize()
{
  int fdd;
  pid_t pid;

  pid = fork();

  switch (pid) {
  case -1:
    return -1;
  case 0:
    break;
  default:
    exit(0);
  }

  if (setsid() == -1) return -1;

  fdd = open("/dev/null", O_RDWR, 0);
  if (fdd != -1) {
    dup2(fdd, 0);
    dup2(fdd, 1);
    dup2(fdd, 2); 
    if (fdd > 2) close(fdd);
  }

  return 0;
}

char *extract_token(char **string, int delim)
{
  char *token, *delim_ptr;

  if (!strlen(*string)) return NULL;

  start:
  if (delim_ptr = strchr(*string, delim)) {
    *delim_ptr = '\0';
    token = *string;
    *string = delim_ptr+1;
    if (!strlen(token)) goto start;
  }
  else {
    token = *string;
    *string += strlen(*string);
    if (!strlen(token)) return NULL;
  }

  return token;
}

char *extract_plugin_name(char **string)
{
  char *name, *delim_ptr;
  char name_start = '[';
  char name_end = ']';

  if ((delim_ptr = strchr(*string, name_start))) {
    *delim_ptr = '\0';
    name = delim_ptr+1; 
    if ((delim_ptr = strchr(name, name_end))) *delim_ptr = '\0';
    else {
      printf("ERROR: Not weighted parhentesis: '[%s'\n", name); 
      exit(1);
    }
  }
  else return NULL;

  return name;
}


/*
 * Copyright (c) 1990, 1991, 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

char *copy_argv(register char **argv)
{
  register char **p;
  register unsigned int len = 0;
  char *buf;
  char *src, *dst;

  p = argv;
  if (*p == 0)
    return NULL;

  while (*p)
    len += strlen(*p++) + 1;

   buf = (char *)malloc(len);
   if (buf == NULL) {
     Log(LOG_ERR, "ERROR: copy_argv: malloc()\n");
     return NULL;
   }

   p = argv;
   dst = buf;
   while ((src = *p++) != NULL) {
     while ((*dst++ = *src++) != '\0');
     dst[-1] = ' ';
   }

   dst[-1] = '\0';
   return buf;
}

void trim_spaces(char *buf)
{
  char *tmp_buf;
  int i, len;

  len = strlen(buf);

  tmp_buf = (char *)malloc(len + 1);
  if (tmp_buf == NULL) {
    Log(LOG_ERR, "ERROR: trim_spaces: malloc()\n");
    return;
  }
   
  /* trimming spaces at beginning of the string */
  for (i = 0; i <= len; i++) {
    if (!isspace(buf[i])) {
      if (i != 0) { 
        strlcpy(tmp_buf, &buf[i], len+1-i);
        strlcpy(buf, tmp_buf, len+1-i);
      }
      break;
    } 
  }

  /* trimming spaces at the end of the string */
  for (i = strlen(buf)-1; i >= 0; i--) { 
    if (isspace(buf[i]))
      buf[i] = '\0';
    else break;
  }

  free(tmp_buf);
}

void trim_all_spaces(char *buf)
{
  char *tmp_buf;
  int i = 0, len, quotes = FALSE;

  len = strlen(buf);

  tmp_buf = (char *)malloc(len + 1);
  if (tmp_buf == NULL) {
    Log(LOG_ERR, "ERROR: trim_all_spaces: malloc()\n");
    return;
  }

  /* trimming all spaces */
  while (i <= len) {
    if (buf[i] == '\'') {
      if (!quotes) quotes = TRUE;
      else if (quotes) quotes = FALSE;
    }
    if (isspace(buf[i]) && !quotes) {
      strlcpy(tmp_buf, &buf[i+1], len);
      strlcpy(&buf[i], tmp_buf, len);
      len--;
    }
    else i++;
  }

  free(tmp_buf);
}

void strip_quotes(char *buf)
{
  char *ptr, *tmp_buf;
  int i = 0, len;

  len = strlen(buf);

  tmp_buf = (char *)malloc(len + 1);
  if (tmp_buf == NULL) {
    Log(LOG_ERR, "ERROR: strip_quotes: malloc()\n");
    return;
  }
  ptr = buf;

  /* stripping all quote marks using a temporary buffer to avoid string corruption by strcpy() */
  while (i <= len) {
    if (ptr[i] == '\'') {
      strcpy(tmp_buf, &ptr[i+1]);
      strcpy(&buf[i], tmp_buf);
      len--;
    }
    else i++;
  }

  free(tmp_buf);
}

int isblankline(char *line)
{
  int len, j, n_spaces = 0;
 
  if (!line) return FALSE;

  len = strlen(line); 
  for (j = 0; j < len; j++) 
    if (isspace(line[j])) n_spaces++;

  if (n_spaces == len) return TRUE;
  else return FALSE;
}

int iscomment(char *line)
{
  int len, j, first_char = TRUE;

  if (!line) return FALSE;

  len = strlen(line);
  for (j = 0; j <= len; j++) {
    if (!isspace(line[j])) first_char--;
    if (!first_char) {
      if (line[j] == '!') return TRUE; 
      else return FALSE;
    }
  }

  return FALSE;
}

time_t roundoff_time(time_t t, char *value)
{
  // char *value = config.sql_history_roundoff;
  struct tm *rounded;
  int len, j;

  rounded = localtime(&t);
  rounded->tm_sec = 0; /* default round off */

  if (value) {
    len = strlen(value);
    for (j = 0; j < len; j++) {
      if (value[j] == 'm') rounded->tm_min = 0;
      else if (value[j] == 'h') {
	rounded->tm_min = 0;
	rounded->tm_hour = 0;
      }
      else if (value[j] == 'd') {
        rounded->tm_min = 0;
        rounded->tm_hour = 0;
	rounded->tm_mday = 1;
      }
      else if (value[j] == 'w') {
        rounded->tm_min = 0;
        rounded->tm_hour = 0;
	while (rounded->tm_wday > 1) {
	  rounded->tm_mday--;
	  rounded->tm_wday--;
	}
      }
      else if (value[j] == 'M') {
        rounded->tm_min = 0;
        rounded->tm_hour = 0;
	rounded->tm_mday = 1;
	rounded->tm_mon = 0;
      }
      else Log(LOG_WARNING, "WARN: ignoring unknown round off value: %c\n", value[j]); 
    }
  }

  t = mktime(rounded);
  return t;
}

/* op = 0 (add); op = 1 (sub) */
time_t calc_monthly_timeslot(time_t t, int howmany, int op)
{
  time_t base = t, final;
  struct tm *tmt;

  tmt = localtime(&t);

  while (howmany) {
    tmt->tm_mday = 1;
    if (op == ADD) tmt->tm_mon++;
    else if (op == SUB) tmt->tm_mon--;
    howmany--;
  }

  final = mktime(tmt);
  
  return (final-base);
}	

FILE *open_logfile(char *filename)
{
  char timebuf[SRVBUFLEN];
  FILE *file = NULL;
  struct tm *tmnow;
  time_t now;
  uid_t owner = -1;
  gid_t group = -1;

  if (config.files_uid) owner = config.files_uid;
  if (config.files_gid) group = config.files_gid;

  file = fopen(filename, "a"); 
  if (file) {
    if (chown(filename, owner, group) == -1)
      printf("WARN: Unable to chown() logfile '%s': %s\n", filename, strerror(errno));
  }
  else {
    printf("WARN: Unable to fopen() logfile '%s': %s\n", filename, strerror(errno));
    file = NULL;
  }

  return file;
}

void close_print_output_file(FILE *f, char *filename, time_t now)
{
  char buf[LARGEBUFLEN], buf2[LARGEBUFLEN], *fname_ptr, *fname_ptr_tmp;
  char latest_fname[LARGEBUFLEN], latest_pname[LARGEBUFLEN];
  struct tm *tmnow;
  u_int16_t offset;

  fclose(f);

  handle_dynname_internal_strings(buf, LARGEBUFLEN-10, filename);
  tmnow = localtime(&now);
  strftime(buf2, LARGEBUFLEN-10, buf, tmnow);

  /* Check: filename is not making use of the reserved word 'latest' */
  for (fname_ptr_tmp = buf2, fname_ptr = NULL; fname_ptr_tmp; fname_ptr_tmp = strchr(fname_ptr_tmp, '/')) {
    if (*fname_ptr_tmp == '/') fname_ptr_tmp++;
    fname_ptr = fname_ptr_tmp;
  }

  strcpy(latest_fname, config.name);
  strcat(latest_fname, "-latest");
  if (!strcmp(fname_ptr, latest_fname)) {
    Log(LOG_WARNING, "WARN: Invalid print_ouput_file '%s': reserved word\n", buf2);
    return;
  }

  /* Let's point 'latest' to the newly opened file */
  if (f) {
    memcpy(latest_pname, buf2, LARGEBUFLEN);
    offset = strlen(buf2)-strlen(fname_ptr);
    if (strlen(latest_fname) < LARGEBUFLEN-offset) {
      strcpy(latest_pname+offset, latest_fname);
      unlink(latest_pname);
      symlink(fname_ptr, latest_pname);
    }
    else Log(LOG_WARNING, "WARN: Unable to link latest file for print_ouput_file '%s'\n", buf2);
  }
}

FILE *open_print_output_file(char *filename, time_t now)
{
  char buf[LARGEBUFLEN], buf2[LARGEBUFLEN];
  FILE *file = NULL;
  struct tm *tmnow;
  uid_t owner = -1;
  gid_t group = -1;

  if (config.files_uid) owner = config.files_uid;
  if (config.files_gid) group = config.files_gid;

  handle_dynname_internal_strings(buf, LARGEBUFLEN-10, filename);
  tmnow = localtime(&now);
  strftime(buf2, LARGEBUFLEN-10, buf, tmnow);

  file = fopen(buf2, "w");
  if (file) {
    if (chown(buf2, owner, group) == -1)
      Log(LOG_WARNING, "WARN: Unable to chown() print_ouput_file '%s': %s\n", buf2, strerror(errno));

    if (file_lock(fileno(file))) {
      Log(LOG_ALERT, "ALERT: Unable to obtain lock for print_ouput_file '%s'.\n", buf2);
      file = NULL;
    }
  }
  else {
    Log(LOG_ERR, "ERROR: Unable to open print_ouput_file '%s'\n", buf2);
    file = NULL;
  }

  return file;
}

/*
   Notes:
   - we check for sufficient space: we do not (de)allocate anything
   - as long as we have only a couple possible replacements, we test them all
*/
void handle_dynname_internal_strings(char *new, int newlen, char *old)
{
  int oldlen;
  char ref_string[] = "$ref", hst_string[] = "$hst";
  char *ptr_start, *ptr_end;

  oldlen = strlen(old);
  if (oldlen <= newlen) strcpy(new, old);

  ptr_start = strstr(new, ref_string);
  if (ptr_start) {
    char buf[newlen];
    int len;

    len = strlen(ptr_start);
    ptr_end = ptr_start;
    ptr_end += 4;
    len -= 4;

    snprintf(buf, newlen, "%u", config.sql_refresh_time);
    strncat(buf, ptr_end, len);

    len = strlen(buf);
    *ptr_start = '\0';
    strncat(new, buf, len); 
  }

  ptr_start = strstr(new, hst_string);
  if (ptr_start) {
    char buf[newlen];
    int len, howmany;

    len = strlen(ptr_start);
    ptr_end = ptr_start;
    ptr_end += 4;
    len -= 4;

    howmany = sql_history_to_secs(config.sql_history, config.sql_history_howmany);
    snprintf(buf, newlen, "%u", howmany);
    strncat(buf, ptr_end, len);

    len = strlen(buf);
    *ptr_start = '\0';
    strncat(new, buf, len);
  }
}

void handle_dynname_internal_strings_same(char *new, int newlen, char *old)
{
  handle_dynname_internal_strings(new, newlen, old);
  strlcpy(old, new, newlen);
}

int sql_history_to_secs(int mu, int howmany)
{
  int ret = 0;

  if (mu == COUNT_MINUTELY) ret = howmany*60;
  else if (mu == COUNT_HOURLY) ret = howmany*3600;
  else if (mu == COUNT_DAILY) ret = howmany*86400;
  else if (mu == COUNT_WEEKLY) ret = howmany*86400*7;
  else if (mu == COUNT_MONTHLY) ret = howmany*86400*30; /* XXX: this is an approx! */

  return ret;
}

void write_pid_file(char *filename)
{
  FILE *file;
  char pid[10];
  uid_t owner = -1;
  gid_t group = -1;

  unlink(filename); 

  if (config.files_uid) owner = config.files_uid;
  if (config.files_gid) group = config.files_gid;
    
  file = fopen(filename,"w");
  if (file) {
    if (chown(filename, owner, group) == -1)
      Log(LOG_WARNING, "WARN: Unable to chown() pidfile '%s': %s\n", filename, strerror(errno));

    if (file_lock(fileno(file))) {
      Log(LOG_ALERT, "ALERT: Unable to obtain lock for pidfile '%s'.\n", filename);
      return;
    }
    sprintf(pid, "%d\n", getpid());
    fwrite(pid, strlen(pid), 1, file);

    file_unlock(fileno(file));
    fclose(file);
  }
  else {
    Log(LOG_ERR, "ERROR: Unable to open pidfile '%s'\n", filename);
    return;
  }
}

void write_pid_file_plugin(char *filename, char *type, char *name)
{
  int len = strlen(filename) + strlen(type) + strlen(name) + 3;
  FILE *file;
  char *fname, pid[10], minus[] = "-";
  uid_t owner = -1;
  gid_t group = -1;

  fname = malloc(len);
  memset(fname, 0, sizeof(fname));
  strcpy(fname, filename);
  strcat(fname, minus);
  strcat(fname, type);
  strcat(fname, minus);
  strcat(fname, name);

  config.pidfile = fname;
  unlink(fname);

  if (config.files_uid) owner = config.files_uid;
  if (config.files_gid) group = config.files_gid;

  file = fopen(fname,"w");
  if (file) {
    if (chown(fname, owner, group) == -1)
      Log(LOG_WARNING, "WARN: Unable to chown() '%s': %s\n", fname, strerror(errno));

    if (file_lock(fileno(file))) {
      Log(LOG_ALERT, "ALERT: Unable to obtain lock of '%s'.\n", fname);
      return;
    }
    sprintf(pid, "%d\n", getpid());
    fwrite(pid, strlen(pid), 1, file);

    file_unlock(fileno(file));
    fclose(file);
  }
  else {
    Log(LOG_ERR, "ERROR: Unable to open file '%s'\n", fname);
    return;
  }
}

void remove_pid_file(char *filename)
{
  unlink(filename);
}

int file_lock(int fd)
{
  int ret;
#if defined SOLARIS
  flock_t lock;

  lock.l_type = F_WRLCK;
  lock.l_whence = 0;
  lock.l_start = 0;
  lock.l_len = 0;

  ret = fcntl(fd, F_SETLK, &lock);
  return((ret == -1) ? -1 : 0);
#else
  ret = flock(fd, LOCK_EX);
  return ret;
#endif
}

int file_unlock(int fd)
{
  int ret;
#if defined SOLARIS
  flock_t lock;

  lock.l_type = F_UNLCK;
  lock.l_whence = 0;
  lock.l_start = 0;
  lock.l_len = 0;

  ret = fcntl(fd, F_SETLK, &lock);
  return((ret == -1) ? -1 : 0);
#else
  ret = flock(fd, LOCK_UN);
  return ret;
#endif
}

int sanitize_buf_net(char *filename, char *buf, int rows)
{
  if (!sanitize_buf(buf)) {
    if (!strchr(buf, '/')) {
      Log(LOG_ERR, "ERROR ( %s ): Missing '/' separator at line %d. Ignoring.\n", filename, rows);
      return TRUE;
    }
  }
  else return TRUE;

  return FALSE;
}

int sanitize_buf(char *buf)
{
  int x = 0, valid_char = 0;

  trim_all_spaces(buf);
  while (x < strlen(buf)) {
    if (!isspace(buf[x])) valid_char++;
    x++;
  }
  if (!valid_char) return TRUE;
  if (buf[0] == '!') return TRUE;

  return FALSE;
}

int check_not_valid_char(char *filename, char *buf, int c)
{
  if (!buf) return FALSE;
  
  if (strchr(buf, c)) {
    Log(LOG_ERR, "ERROR ( %s ): Invalid symbol '%c' detected. ", filename, c);
    return TRUE; 
  }
  else return FALSE;
}

void mark_columns(char *buf)
{
  int len, x, word = FALSE, quotes = FALSE;

  if (!buf) return;

  len = strlen(buf);
  for (x = 0; x < len; x++) {
    if (buf[x] == '\'') {
      if (!quotes) quotes = TRUE;
      else if (quotes) quotes = FALSE;
    }
    if ((isalpha(buf[x])||isdigit(buf[x])||ispunct(buf[x])) && !word) word = TRUE;
    if (isspace(buf[x]) && word && !quotes) {
      buf[x] = '|';
      word = FALSE;
    }
  }

  /* removing trailing '|' if any */
  x = strlen(buf);
  word = FALSE;

  while (x > 0) {
    if (buf[x] == '|' && !word) buf[x] = '\0';
    if ((isalpha(buf[x])||isdigit(buf[x])||ispunct(buf[x])) && !word) word = TRUE;
    x--;
  }
}

int Setsocksize(int s, int level, int optname, void *optval, int optlen)
{
  int ret, len = sizeof(int), saved, value;

  memcpy(&value, optval, sizeof(int));
  
  getsockopt(s, level, optname, &saved, &len);
  if (value > saved) {
    for (; value; value >>= 1) {
      ret = setsockopt(s, level, optname, &value, optlen); 
      if (ret >= 0) break;
    }
    if (!value) setsockopt(s, level, optname, &saved, len); 
  }

  return ret;
}

void *map_shared(void *addr, size_t len, int prot, int flags, int fd, off_t off)
{
#if defined USE_DEVZERO
  void *mem;
  int devzero;

  devzero = open ("/dev/zero", O_RDWR);
  if (devzero < 0) return MAP_FAILED;
  mem = mmap(addr, len, prot, flags, devzero, off);
  close(devzero);

  return mem;
#else /* MAP_ANON or MAP_ANONYMOUS */
  return (void *)mmap(addr, len, prot, flags, fd, off);
#endif
}

void lower_string(char *string)
{
  int i = 0;

  while (string[i] != '\0') {
    string[i] = tolower(string[i]);
    i++;
  }
}

void evaluate_sums(u_int64_t *wtc, char *name, char *type)
{
  int tag = FALSE;
  int tag2 = FALSE;
  int class = FALSE;
  int flows = FALSE;

  if (*wtc & COUNT_ID) {
    *wtc ^= COUNT_ID;
    tag = TRUE;
  }

  if (*wtc & COUNT_ID2) {
    *wtc ^= COUNT_ID2;
    tag2 = TRUE;
  }

  if (*wtc & COUNT_CLASS) {
    *wtc ^= COUNT_CLASS;
    class = TRUE;
  }

  if (*wtc & COUNT_FLOWS) {
    *wtc ^= COUNT_FLOWS;
    flows = TRUE;
  }

  if (*wtc & COUNT_SUM_MAC) {
    if (*wtc != COUNT_SUM_MAC) {
      *wtc = COUNT_SUM_MAC;
      Log(LOG_WARNING, "WARN ( %s/%s ): SUM aggregation is to be used alone. Resetting other aggregation methods.\n", name, type);
    }
  }

  if (*wtc & COUNT_SUM_HOST) {
    if (*wtc != COUNT_SUM_HOST) {
      *wtc = COUNT_SUM_HOST;
      Log(LOG_WARNING, "WARN ( %s/%s ): SUM aggregation is to be used alone. Resetting other aggregation methods.\n", name, type);
    }
  }
  else if (*wtc & COUNT_SUM_NET) {
    if (*wtc != COUNT_SUM_NET) {
      *wtc = COUNT_SUM_NET;
      Log(LOG_WARNING, "WARN ( %s/%s ): SUM aggregation is to be used alone. Resetting other aggregation methods.\n", name, type);
    }
  }
  else if (*wtc & COUNT_SUM_AS) {
    if (*wtc != COUNT_SUM_AS) {
      *wtc = COUNT_SUM_AS;
      Log(LOG_WARNING, "WARN ( %s/%s ): SUM aggregation is to be used alone. Resetting other aggregation methods.\n", name, type);
    }
  }
  else if (*wtc & COUNT_SUM_PORT) {
    if (*wtc != COUNT_SUM_PORT) {
      *wtc = COUNT_SUM_PORT;
      Log(LOG_WARNING, "WARN ( %s/%s ): SUM aggregation is to be used alone. Resetting other aggregation methods.\n", name, type);
    }
  }

  if (tag) *wtc |= COUNT_ID;
  if (tag2) *wtc |= COUNT_ID2;
  if (class) *wtc |= COUNT_CLASS;
  if (flows) *wtc |= COUNT_FLOWS;
}

int file_archive(const char *path, int rotations)
{
  struct stat st;
  char *new_path;
  int j, ret, len = strlen(path)+11;
  
  new_path = malloc(len);
  memset(new_path, 0, len);
  for (j = 1; j < rotations; j++) {
    snprintf(new_path, len, "%s.%d", path, j); 
    ret = stat(new_path, &st);
    if (ret < 0) {
      rename(path, new_path);
      return 0;
    }
  }

  /* we should never reach this point */
  Log(LOG_ALERT, "ALERT: No more recovery logfile ( %s ) rotations allowed. Data is getting lost.\n", path);  
  return -1;
}

void stop_all_childs()
{
  my_sigint_handler(0); /* it does same thing */
}

void strftime_same(char *s, int max, char *tmp, const time_t *now)
{
  struct tm *nowtm;

  nowtm = localtime(now);
  strftime(tmp, max, s, nowtm);
  strlcpy(s, tmp, max);
}

int read_SQLquery_from_file(char *path, char *buf, int size)
{
  FILE *f;
  char *ptr;
  int ret;

  memset(buf, 0, size);
  f = fopen(path, "r");
  if (!f) {
    Log(LOG_ERR, "ERROR: %s does not exist.\n", path);
    return(0);
  }
  
  ret = fread(buf, size, 1, f);

  if (ret != 1 && !feof(f)) {
    Log(LOG_ERR, "ERROR: Unable to read from SQL schema '%s': %s\n", path, strerror(errno));
    return(0);
  }

  fclose(f);
  
  ptr = strrchr(buf, ';');
  if (!ptr) {
    Log(LOG_ERR, "ERROR: missing trailing ';' in SQL query read from %s.\n", path);
    return(0); 
  } 
  else *ptr = '\0';
  
  return (int)*ptr-(int)*buf;
} 

void stick_bosbit(u_char *label)
{
  u_char *ptr;

  ptr = label+2;
  *ptr |= 0x1;
}

/*
 * timeval_cmp(): returns > 0 if a > b; < 0 if a < b; 0 if a == b.
 */
int timeval_cmp(struct timeval *a, struct timeval *b)
{
  if (a->tv_sec > b->tv_sec) return 1;
  if (a->tv_sec < b->tv_sec) return -1;
  if (a->tv_sec == b->tv_sec) {
    if (a->tv_usec > b->tv_usec) return 1;
    if (a->tv_usec < b->tv_usec) return -1;
    if (a->tv_usec == b->tv_usec) return 0;
  }
}

/*
 * exit_all(): Core Process exit lane. Not meant to be a nice shutdown method: it is
 * an exit() replacement that sends kill signals to the plugins.
 */
void exit_all(int status)
{
  struct plugins_list_entry *list = plugins_list;

#if defined (IRIX) || (SOLARIS)
  signal(SIGCHLD, SIG_IGN);
#else
  signal(SIGCHLD, ignore_falling_child);
#endif

  while (list) {
    if (memcmp(list->type.string, "core", sizeof("core"))) kill(list->pid, SIGKILL);
    list = list->next;
  }

  wait(NULL);
  if (config.pidfile) remove_pid_file(config.pidfile);

  exit(status);
}

/* exit_plugin(): meant to be called on exit by plugins; it is a simple wrapper to
   enforce some final operations before shutting down */
void exit_plugin(int status)
{
  if (config.pidfile) remove_pid_file(config.pidfile);

  exit(status);
}

void reset_tag_status(struct packet_ptrs_vector *pptrsv)
{
  pptrsv->v4.tag = FALSE;
  pptrsv->vlan4.tag = FALSE;
  pptrsv->mpls4.tag = FALSE;
  pptrsv->vlanmpls4.tag = FALSE;
  pptrsv->v4.tag2 = FALSE;
  pptrsv->vlan4.tag2 = FALSE;
  pptrsv->mpls4.tag2 = FALSE;
  pptrsv->vlanmpls4.tag2 = FALSE;

#if defined ENABLE_IPV6
  pptrsv->v6.tag = FALSE;
  pptrsv->vlan6.tag = FALSE;
  pptrsv->mpls6.tag = FALSE;
  pptrsv->vlanmpls6.tag = FALSE;
  pptrsv->v6.tag2 = FALSE;
  pptrsv->vlan6.tag2 = FALSE;
  pptrsv->mpls6.tag2 = FALSE;
  pptrsv->vlanmpls6.tag2 = FALSE;
#endif
}

void reset_net_status(struct packet_ptrs *pptrs)
{
  pptrs->lm_mask_src = FALSE;
  pptrs->lm_mask_dst = FALSE;
  pptrs->lm_method_src = FALSE;
  pptrs->lm_method_dst = FALSE;
}

void reset_net_status_v(struct packet_ptrs_vector *pptrsv)
{
  pptrsv->v4.lm_mask_src = FALSE;
  pptrsv->vlan4.lm_mask_src = FALSE;
  pptrsv->mpls4.lm_mask_src = FALSE;
  pptrsv->vlanmpls4.lm_mask_src = FALSE;
  pptrsv->v4.lm_mask_dst = FALSE;
  pptrsv->vlan4.lm_mask_dst = FALSE;
  pptrsv->mpls4.lm_mask_dst = FALSE;
  pptrsv->vlanmpls4.lm_mask_dst = FALSE;
  pptrsv->v4.lm_method_src = FALSE;
  pptrsv->vlan4.lm_method_src = FALSE;
  pptrsv->mpls4.lm_method_src = FALSE;
  pptrsv->vlanmpls4.lm_method_src = FALSE;
  pptrsv->v4.lm_method_dst = FALSE;
  pptrsv->vlan4.lm_method_dst = FALSE;
  pptrsv->mpls4.lm_method_dst = FALSE;
  pptrsv->vlanmpls4.lm_method_dst = FALSE;

#if defined ENABLE_IPV6
  pptrsv->v6.lm_mask_src = FALSE;
  pptrsv->vlan6.lm_mask_src = FALSE;
  pptrsv->mpls6.lm_mask_src = FALSE;
  pptrsv->vlanmpls6.lm_mask_src = FALSE;
  pptrsv->v6.lm_mask_dst = FALSE;
  pptrsv->vlan6.lm_mask_dst = FALSE;
  pptrsv->mpls6.lm_mask_dst = FALSE;
  pptrsv->vlanmpls6.lm_mask_dst = FALSE;
  pptrsv->v6.lm_method_src = FALSE;
  pptrsv->vlan6.lm_method_src = FALSE;
  pptrsv->mpls6.lm_method_src = FALSE;
  pptrsv->vlanmpls6.lm_method_src = FALSE;
  pptrsv->v6.lm_method_dst = FALSE;
  pptrsv->vlan6.lm_method_dst = FALSE;
  pptrsv->mpls6.lm_method_dst = FALSE;
  pptrsv->vlanmpls6.lm_method_dst = FALSE;
#endif
}

void reset_shadow_status(struct packet_ptrs_vector *pptrsv)
{
  pptrsv->v4.shadow = FALSE;
  pptrsv->vlan4.shadow = FALSE;
  pptrsv->mpls4.shadow = FALSE;
  pptrsv->vlanmpls4.shadow = FALSE;

#if defined ENABLE_IPV6
  pptrsv->v6.shadow = FALSE;
  pptrsv->vlan6.shadow = FALSE;
  pptrsv->mpls6.shadow = FALSE;
  pptrsv->vlanmpls6.shadow = FALSE;
#endif
}

void reset_fallback_status(struct packet_ptrs *pptrs)
{
  pptrs->renormalized = FALSE;
}

void set_default_preferences(struct configuration *cfg)
{
  if (!cfg->nfacctd_as) cfg->nfacctd_as = NF_AS_KEEP;
  if (!cfg->nfacctd_bgp_peer_as_src_type) cfg->nfacctd_bgp_peer_as_src_type = BGP_SRC_PRIMITIVES_KEEP;
  if (!cfg->nfacctd_bgp_src_std_comm_type) cfg->nfacctd_bgp_src_std_comm_type = BGP_SRC_PRIMITIVES_KEEP;
  if (!cfg->nfacctd_bgp_src_ext_comm_type) cfg->nfacctd_bgp_src_ext_comm_type = BGP_SRC_PRIMITIVES_KEEP;
  if (!cfg->nfacctd_bgp_src_as_path_type) cfg->nfacctd_bgp_src_as_path_type = BGP_SRC_PRIMITIVES_KEEP;
  if (!cfg->nfacctd_bgp_src_local_pref_type) cfg->nfacctd_bgp_src_local_pref_type = BGP_SRC_PRIMITIVES_KEEP;
  if (!cfg->nfacctd_bgp_src_med_type) cfg->nfacctd_bgp_src_med_type = BGP_SRC_PRIMITIVES_KEEP;
}

void set_shadow_status(struct packet_ptrs *pptrs)
{
  pptrs->shadow = TRUE;
}

void set_sampling_table(struct packet_ptrs_vector *pptrsv, u_char *t)
{
  pptrsv->v4.sampling_table = t;
  pptrsv->vlan4.sampling_table = t;
  pptrsv->mpls4.sampling_table = t;
  pptrsv->vlanmpls4.sampling_table = t;

#if defined ENABLE_IPV6
  pptrsv->v6.sampling_table = t;
  pptrsv->vlan6.sampling_table = t;
  pptrsv->mpls6.sampling_table = t;
  pptrsv->vlanmpls6.sampling_table = t;
#endif
}

struct packet_ptrs *copy_packet_ptrs(struct packet_ptrs *pptrs)
{
  struct packet_ptrs *new_pptrs;
  int offset;
  u_char dummy_tlhdr[16];

  /* Copy the whole structure first */
  if ((new_pptrs = malloc(sizeof(struct packet_ptrs))) == NULL) {
    return NULL;
  }
  memcpy(new_pptrs, pptrs, sizeof(struct packet_ptrs));

  /* Copy the packet buffer */
  if ((new_pptrs->packet_ptr = malloc(pptrs->pkthdr->caplen)) == NULL) {
    free(new_pptrs);
    return NULL;
  }
  memcpy(new_pptrs->packet_ptr, pptrs->packet_ptr, pptrs->pkthdr->caplen);

  /* Copy the pcap packet header */
  if ((new_pptrs->pkthdr = malloc(sizeof(struct pcap_pkthdr))) == NULL) {
    free(new_pptrs->packet_ptr);
    free(new_pptrs);
    return NULL;
  }
  memcpy(new_pptrs->pkthdr, pptrs->pkthdr, sizeof(struct pcap_pkthdr));

  /* Fix the pointers */
  offset = (int) new_pptrs->packet_ptr - (int) pptrs->packet_ptr;

  /* Pointers can be NULL */
  if (pptrs->iph_ptr)
    new_pptrs->iph_ptr += offset;
  if (pptrs->tlh_ptr)
    if(pptrs->tlh_ptr > pptrs->packet_ptr && pptrs->tlh_ptr < pptrs->packet_ptr+offset) // If it is not a dummy tlh_ptr
      new_pptrs->tlh_ptr += offset;
    else {
      memset(dummy_tlhdr, 0, sizeof(dummy_tlhdr));
      new_pptrs->tlh_ptr = dummy_tlhdr;
    }
  if (pptrs->payload_ptr)
    new_pptrs->payload_ptr += offset;

  return new_pptrs;
}

void free_packet_ptrs(struct packet_ptrs *pptrs)
{
  free(pptrs->pkthdr);
  free(pptrs->packet_ptr);
  free(pptrs);
}

#if DEBUG_TIMING
void start_timer(struct mytimer *t)
{
  gettimeofday(&t->t0, NULL);
}

void stop_timer(struct mytimer *t, const char *format, ...)
{
  char msg[1024];
  va_list ap;

  gettimeofday(&t->t1, NULL);
  va_start(ap, format);
  vsnprintf(msg, 1024, format, ap);
  va_end(ap);

  fprintf(stderr, "TIMER:%s:%d\n", msg, (t->t1.tv_sec - t->t0.tv_sec) * 1000000 + (t->t1.tv_usec - t->t0.tv_usec));
}
#endif

void evaluate_bgp_aspath_radius(char *path, int len, int radius)
{
  int count, idx;

  for (idx = 0, count = 0; idx < len; idx++) {
    if (path[idx] == ' ') count++;
    if (count == radius) {
      path[idx] = '\0';
      memset(&path[idx+1], 0, len-strlen(path)); 
      break;
    }
  }
}

void copy_stdcomm_to_asn(char *stdcomm, as_t *asn, int is_origin)
{
  char *delim, *delim2;
  char *p1, *p2;

  if (!stdcomm || !strlen(stdcomm) || (delim = strchr(stdcomm, ':')) == NULL) return; 

  delim2 = strchr(stdcomm, ',');
  *delim = '\0';
  if (delim2) *delim2 = '\0';
  p1 = stdcomm;
  p2 = delim+1;

  if (is_origin) *asn = atoi(p2); 
  else *asn = atoi(p1);
}

void *Malloc(unsigned int size)
{
  unsigned char *obj;

  obj = (unsigned char *) malloc(size);
  if (!obj) {
    sbrk(size);
    obj = (unsigned char *) malloc(size);
    if (!obj) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Unable to grab enough memory (requested: %u bytes). Exiting ...\n",
      config.name, config.type, size);
      exit_plugin(1);
    }
  }

  return obj;
}

void load_allow_file(char *filename, struct hosts_table *t)
{
  FILE *file;
  char buf[SRVBUFLEN];
  int index = 0;

  if (filename) {
    if ((file = fopen(filename, "r")) == NULL) {
      Log(LOG_ERR, "ERROR ( default/core ): allow file '%s' not found\n", filename);
      exit(1);
    }

    memset(t->table, 0, sizeof(t->table));
    while (!feof(file)) {
      if (index >= MAX_MAP_ENTRIES) break; /* XXX: we shouldn't exit silently */
      memset(buf, 0, SRVBUFLEN);
      if (fgets(buf, SRVBUFLEN, file)) {
        if (!sanitize_buf(buf)) {
          if (str_to_addr(buf, &t->table[index])) index++;
          else Log(LOG_WARNING, "WARN ( default/core ): 'nfacctd_allow_file': Bad IP address '%s'. Ignored.\n", buf);
        }
      }
    }
    t->num = index;

    /* Set to -1 to distinguish between no map and empty map conditions */ 
    if (!t->num) t->num = -1;

    fclose(file);
  }
}

void load_bgp_md5_file(char *filename, struct bgp_md5_table *t)
{
  FILE *file;
  char buf[SRVBUFLEN], *ptr;
  int index = 0;

  if (filename) {
    if ((file = fopen(filename, "r")) == NULL) {
      Log(LOG_ERR, "ERROR ( default/core/BGP ): BGP MD5 file '%s' not found\n", filename);
      exit(1);
    }

    memset(t->table, 0, sizeof(t->table));
    while (!feof(file)) {
      if (index >= BGP_MD5_MAP_ENTRIES) break; /* XXX: we shouldn't exit silently */
      memset(buf, 0, SRVBUFLEN);
      if (fgets(buf, SRVBUFLEN, file)) {
        if (!sanitize_buf(buf)) {
	  char *endptr, *token;
	  int tk_idx = 0, ret = 0, len = 0;

	  ptr = buf;
	  memset(&t->table[index], 0, sizeof(t->table[index]));
	  while ( (token = extract_token(&ptr, ',')) && tk_idx < 2 ) {
	    if (tk_idx == 0) ret = str_to_addr(token, &t->table[index].addr);
	    else if (tk_idx == 1) {
	      strlcpy(t->table[index].key, token, TCP_MD5SIG_MAXKEYLEN); 
	      len = strlen(t->table[index].key); 
	    } 
	    tk_idx++;
	  }

          if (ret > 0 && len > 0) index++;
          else Log(LOG_WARNING, "WARN ( default/core/BGP ): 'bgp_daemon_md5_file': line '%s' ignored.\n", buf);
        }
      }
    }
    t->num = index;

    /* Set to -1 to distinguish between no map and empty map conditions */
    if (!t->num) t->num = -1;

    fclose(file);
  }
}

void unload_bgp_md5_file(struct bgp_md5_table *t)
{
  int index = 0;

  while (index < t->num) {
    memset(t->table[index].key, 0, TCP_MD5SIG_MAXKEYLEN);
    index++;
  }
}

int check_allow(struct hosts_table *allow, struct sockaddr *sa)
{
  int index;

  for (index = 0; index < allow->num; index++) {
    if (((struct sockaddr *)sa)->sa_family == allow->table[index].family) {
      if (allow->table[index].family == AF_INET) {
        if (((struct sockaddr_in *)sa)->sin_addr.s_addr == allow->table[index].address.ipv4.s_addr)
          return TRUE;
      }
#if defined ENABLE_IPV6
      else if (allow->table[index].family == AF_INET6) {
        if (!ip6_addr_cmp(&(((struct sockaddr_in6 *)sa)->sin6_addr), &allow->table[index].address.ipv6))
          return TRUE;
      }
#endif
    }
  }

  return FALSE;
}

int BTA_find_id(struct id_table *t, struct packet_ptrs *pptrs, pm_id_t *tag, pm_id_t *tag2)
{
  struct xflow_status_entry *xsentry = (struct xflow_status_entry *) pptrs->f_status;
  struct xflow_status_map_cache *xsmc = NULL;
  int ret = 0;

  pptrs->bta_af = 0;

  if (bta_map_caching && xsentry) {
    if (pptrs->l3_proto == ETHERTYPE_IP) xsmc = &xsentry->bta_v4; 
#if defined ENABLE_IPV6
    else if (pptrs->l3_proto == ETHERTYPE_IPV6) xsmc = &xsentry->bta_v6;
#endif
  }

  if (bta_map_caching && xsmc && timeval_cmp(&xsmc->stamp, &reload_map_tstamp) > 0) {
    *tag = xsmc->id;
    *tag2 = xsmc->id2;
    ret = xsmc->ret;
  }
  else {
    if (find_id_func) {
      ret = find_id_func(t, pptrs, tag, tag2);
      if (xsmc) {
	xsmc->id = *tag;
	xsmc->id2 = *tag2;
	xsmc->ret = ret;
	gettimeofday(&xsmc->stamp, NULL);
      }
    }
  }

  if (ret == PRETAG_MAP_RCODE_ID) pptrs->bta_af = ETHERTYPE_IP;
#if defined ENABLE_IPV6
  else if (ret == BTA_MAP_RCODE_ID_ID2) pptrs->bta_af = ETHERTYPE_IPV6;
#endif

  return ret;
}

void calc_refresh_timeout(time_t deadline, time_t now, int *timeout)
{
  *timeout = ((deadline-now)+1)*1000;
}

int load_tags(char *filename, struct pretag_filter *filter, char *value_ptr)
{
  char *count_token, *range_ptr;
  pm_id_t value = 0, range = 0;
  int changes = 0;
  char *endptr_v, *endptr_r;
  u_int8_t neg;

  if (!filter || !value_ptr) return changes;

  trim_all_spaces(value_ptr);
  filter->num = 0;

  while ((count_token = extract_token(&value_ptr, ',')) && changes < MAX_PRETAG_MAP_ENTRIES/4) {
    neg = pt_check_neg(&count_token);
    range_ptr = pt_check_range(count_token);
    value = strtoull(count_token, &endptr_v, 10);
    if (range_ptr) range = strtoull(range_ptr, &endptr_r, 10);
    else range = value;

    if (range_ptr && range <= value) {
      Log(LOG_ERR, "WARN ( %s/%s ): Range value is expected in format low-high. '%llu-%llu' not loaded in file '%s'.\n",
			config.name, config.type, value, range, filename);
      changes++;
      break;
    }

    filter->table[filter->num].neg = neg;
    filter->table[filter->num].n = value;
    filter->table[filter->num].r = range;
    filter->num++;
    changes++;
  }

  return changes;
}

/* return value:
   TRUE: We want it!
   FALSE: Discard it!
*/

int evaluate_tags(struct pretag_filter *filter, pm_id_t tag)
{
  int index;

  if (filter->num == 0) return FALSE; /* no entries in the filter array: tag filtering disabled */

  for (index = 0; index < filter->num; index++) {
    if (filter->table[index].n <= tag && filter->table[index].r >= tag) return (FALSE | filter->table[index].neg);
    else if (filter->table[index].neg) return FALSE;
  }

  return TRUE;
}

void load_pkt_len_distrib_bins()
{
  char *ptr, *endptr_v, *endptr_r, *token, *range_ptr;
  u_int16_t value = 0, range = 0;
  int idx, aux_idx;

  ptr = config.pkt_len_distrib_bins_str;

  /* We leave config.pkt_len_distrib_bins[0] to NULL to catch unknowns */
  config.pkt_len_distrib_bins[0] = pkt_len_distrib_unknown;
  idx = 1;

  while ((token = extract_token(&ptr, ',')) && idx < MAX_PKT_LEN_DISTRIB_BINS) {
    range_ptr = pt_check_range(token);
    value = strtoull(token, &endptr_v, 10);
    if (range_ptr) {
      range = strtoull(range_ptr, &endptr_r, 10);
      range_ptr--; *range_ptr = '-';
    }
    else range = value;

    if (value > ETHER_JUMBO_MTU || range > ETHER_JUMBO_MTU) {
      Log(LOG_WARNING, "WARN ( %s/%s ): pkt_len_distrib_bins: value must be in the range 0-9000. '%llu-%llu' not loaded.\n",
                        config.name, config.type, value, range);
      continue;
    }

    if (range_ptr && range <= value) {
      Log(LOG_WARNING, "WARN ( %s/%s ): pkt_len_distrib_bins: range value is expected in format low-high. '%llu-%llu' not loaded.\n",
                        config.name, config.type, value, range);
      continue;
    }

    config.pkt_len_distrib_bins[idx] = token;
    for (aux_idx = value; aux_idx <= range; aux_idx++)
      config.pkt_len_distrib_bins_lookup[aux_idx] = idx;

    idx++;
  }

  if (config.debug) {
    for (idx = 0; idx < MAX_PKT_LEN_DISTRIB_BINS; idx++) {
      if (config.pkt_len_distrib_bins[idx])
        Log(LOG_DEBUG, "DEBUG ( %s/%s ): pkt_len_distrib_bins[%u]: %s\n", config.name, config.type, idx, config.pkt_len_distrib_bins[idx]);
    }
  }
}

void evaluate_pkt_len_distrib(struct pkt_data *data)
{
  pm_counter_t avg_len = data->pkt_num ? data->pkt_len / data->pkt_num : 0;

  if (avg_len > 0 && avg_len < ETHER_JUMBO_MTU) data->primitives.pkt_len_distrib = config.pkt_len_distrib_bins_lookup[avg_len];
  else data->primitives.pkt_len_distrib = 0;
}

char *write_sep(char *sep, int *count)
{
  static char empty_sep[] = "";

  if (*count) return sep;
  else {
    (*count)++;
    return empty_sep;
  }
}

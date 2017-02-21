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

#define __UTIL_C

/* includes */
#include "pmacct.h"
#include "addr.h"
#include "pmacct-data.h"
#include "ip_flow.h"
#include "classifier.h"
#include "plugin_hooks.h"
#include <search.h>
#include <sys/file.h>

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
     Log(LOG_ERR, "ERROR ( %s/%s ): copy_argv: malloc()\n", config.name, config.type);
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
    Log(LOG_ERR, "ERROR: trim_spaces: malloc() failed.\n");
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
    Log(LOG_ERR, "ERROR: trim_all_spaces: malloc() failed.\n");
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

  tmp_buf = (char *) malloc(len + 1);
  if (tmp_buf == NULL) {
    Log(LOG_ERR, "ERROR ( %s/%s ): strip_quotes: malloc() failed.\n", config.name, config.type);
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
      if (line[j] == '!' || line[j] == '#') return TRUE; 
      else return FALSE;
    }
  }

  return FALSE;
}

void string_add_newline(char *buf)
{
  int len = strlen(buf);

  buf[len] = '\n';
  len++;
  buf[len] = '\0';
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
      else Log(LOG_WARNING, "WARN ( %s/%s ): ignoring unknown round off value: %c\n", config.name, config.type, value[j]); 
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

FILE *open_output_file(char *filename, char *mode, int lock)
{
  FILE *file = NULL;
  uid_t owner = -1;
  gid_t group = -1;
  int ret;

  if (!filename || !mode) return file;

  if (config.files_uid) owner = config.files_uid;
  if (config.files_gid) group = config.files_gid;

  ret = mkdir_multilevel(filename, TRUE, owner, group);
  if (ret) {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] open_output_file(): mkdir_multilevel() failed.\n", config.name, config.type, filename);
    return file;
  }

  ret = access(filename, F_OK);

  file = fopen(filename, mode); 

  if (file) {
    if (chown(filename, owner, group) == -1)
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] open_output_file(): chown() failed (%s).\n", config.name, config.type, filename, strerror(errno));

    if (lock) {
      if (file_lock(fileno(file))) {
        Log(LOG_ERR, "ERROR ( %s/%s ): [%s] open_output_file(): file_lock() failed.\n", config.name, config.type, filename);
        file = NULL;
      }
    }
  }
  else {
    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] open_output_file(): fopen() failed (%s).\n", config.name, config.type, filename, strerror(errno));
    file = NULL;
  }

  return file;
}

void link_latest_output_file(char *link_filename, char *filename_to_link)
{
  int ret, rewrite_latest = FALSE;
  char buf[SRVBUFLEN];
  uid_t owner = -1;
  gid_t group = -1;

  if (!link_filename || !filename_to_link) return;

  if (config.files_uid) owner = config.files_uid;
  if (config.files_gid) group = config.files_gid;

  /* create dir structure to get to file, if needed */
  ret = mkdir_multilevel(link_filename, TRUE, owner, group);
  if (ret) {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] link_latest_output_file(): mkdir_multilevel() failed.\n", config.name, config.type, buf);
    return;
  }

  /* if a file with same name exists let's investigate if filename_to_link is newer */
  ret = access(link_filename, F_OK);

  if (!ret) {
    struct stat s1, s2;

    memset(&s1, 0, sizeof(struct stat));
    memset(&s2, 0, sizeof(struct stat));
    readlink(link_filename, buf, SRVBUFLEN);

    /* filename_to_link is newer than buf or buf is un-existing */
    stat(buf, &s1);
    stat(filename_to_link, &s2);
    if (s2.st_mtime >= s1.st_mtime) rewrite_latest = TRUE;
  }
  else rewrite_latest = TRUE;

  if (rewrite_latest) {
    unlink(link_filename);
    symlink(filename_to_link, link_filename);

    if (lchown(link_filename, owner, group) == -1)
      Log(LOG_WARNING, "WARN ( %s/%s ): link_latest_output_file(): unable to chown() '%s'.\n", config.name, config.type, link_filename);
  }
}

void close_output_file(FILE *f)
{
  if (f) fclose(f);
}

/*
   Notes:
   - we check for sufficient space: we do not (de)allocate anything
   - as long as we have only a couple possible replacements, we test them all
*/
void handle_dynname_internal_strings(char *new, int newlen, char *old, struct primitives_ptrs *prim_ptrs)
{
  int oldlen;
  char ref_string[] = "$ref", hst_string[] = "$hst", psi_string[] = "$peer_src_ip";
  char tag_string[] = "$tag", tag2_string[] = "$tag2";
  char *ptr_start, *ptr_end;

  if (!new || !old || !prim_ptrs) return;

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

  ptr_start = strstr(new, psi_string);
  if (ptr_start) {
    char empty_peer_src_ip[] = "null";
    char peer_src_ip[SRVBUFLEN];
    char buf[newlen];
    int len, howmany;

    len = strlen(ptr_start);
    ptr_end = ptr_start;
    ptr_end += strlen(psi_string);
    len -= strlen(psi_string);

    if (prim_ptrs && prim_ptrs->pbgp) addr_to_str(peer_src_ip, &prim_ptrs->pbgp->peer_src_ip);
    else strlcpy(peer_src_ip, empty_peer_src_ip, strlen(peer_src_ip));

    escape_ip_uscores(peer_src_ip);
    snprintf(buf, newlen, "%s", peer_src_ip);
    strncat(buf, ptr_end, len);

    len = strlen(buf);
    *ptr_start = '\0';
    strncat(new, buf, len);
  }

  ptr_start = strstr(new, tag_string);
  if (ptr_start) {
    pm_id_t zero_tag = 0;
    char buf[newlen];
    int len, howmany;

    len = strlen(ptr_start);
    ptr_end = ptr_start;
    ptr_end += strlen(tag_string);
    len -= strlen(tag_string);

    if (prim_ptrs && prim_ptrs->data) snprintf(buf, newlen, "%llu", prim_ptrs->data->primitives.tag); 
    else snprintf(buf, newlen, "%llu", zero_tag);

    strncat(buf, ptr_end, len);

    len = strlen(buf);
    *ptr_start = '\0';
    strncat(new, buf, len);
  }

  ptr_start = strstr(new, tag2_string);
  if (ptr_start) {
    pm_id_t zero_tag = 0;
    char buf[newlen];
    int len, howmany;

    len = strlen(ptr_start);
    ptr_end = ptr_start;
    ptr_end += strlen(tag2_string);
    len -= strlen(tag2_string);

    if (prim_ptrs && prim_ptrs->data) snprintf(buf, newlen, "%llu", prim_ptrs->data->primitives.tag2);
    else snprintf(buf, newlen, "%llu", zero_tag);

    strncat(buf, ptr_end, len);

    len = strlen(buf);
    *ptr_start = '\0';
    strncat(new, buf, len);
  }
}

void escape_ip_uscores(char *str)
{
  int idx, len = 0;

  if (str) len = strlen(str);
  for (idx = 0; idx < len; idx++) {
    if (str[idx] == '.' || str[idx] == ':') str[idx] = '_';
  }
}

void handle_dynname_internal_strings_same(char *new, int newlen, char *old, struct primitives_ptrs *prim_ptrs)
{
  handle_dynname_internal_strings(new, newlen, old, prim_ptrs);
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
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Unable to chown(): %s\n", config.name, config.type, filename, strerror(errno));

    if (file_lock(fileno(file))) {
      Log(LOG_ERR, "ERROR ( %s/%s ): [%s] Unable to obtain lock.\n", config.name, config.type, filename);
      return;
    }
    sprintf(pid, "%d\n", getpid());
    fwrite(pid, strlen(pid), 1, file);

    file_unlock(fileno(file));
    fclose(file);
  }
  else {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] fopen() failed.\n", config.name, config.type, filename);
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
  if (!fname) {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] malloc() failed.\n", config.name, config.type, filename);
    return;
  }
  memset(fname, 0, len);
  strcpy(fname, filename);
  strcat(fname, minus);
  strcat(fname, type);
  strcat(fname, minus);
  strcat(fname, name);

  config.pidfile = fname;
  unlink(fname);

  if (config.files_uid) owner = config.files_uid;
  if (config.files_gid) group = config.files_gid;

  file = fopen(fname, "w");
  if (file) {
    if (chown(fname, owner, group) == -1)
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Unable to chown(): %s\n", config.name, config.type, fname, strerror(errno));

    if (file_lock(fileno(file))) {
      Log(LOG_ERR, "ERROR ( %s/%s ): [%s] Unable to obtain lock.\n", config.name, config.type, fname);
      goto exit_lane;
    }
    sprintf(pid, "%d\n", getpid());
    fwrite(pid, strlen(pid), 1, file);

    file_unlock(fileno(file));
    fclose(file);
  }
  else {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] fopen() failed.\n", config.name, config.type, fname);
    goto exit_lane;
  }

  exit_lane:
  config.pidfile = NULL;
  free(fname);
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
      Log(LOG_ERR, "ERROR ( %s/%s ): [%s:%u] Missing '/' separator. Ignoring.\n", config.name, config.type, filename, rows);
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
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] Invalid symbol '%c' detected.\n", config.name, config.type, filename, c);
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

  if (!string) return;

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

  if (*wtc & COUNT_TAG) {
    *wtc ^= COUNT_TAG;
    tag = TRUE;
  }

  if (*wtc & COUNT_TAG2) {
    *wtc ^= COUNT_TAG2;
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

  if (tag) *wtc |= COUNT_TAG;
  if (tag2) *wtc |= COUNT_TAG2;
  if (class) *wtc |= COUNT_CLASS;
  if (flows) *wtc |= COUNT_FLOWS;
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
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] file does not exist.\n", config.name, config.type, path);
    return(0);
  }
  
  ret = fread(buf, size, 1, f);

  if (ret != 1 && !feof(f)) {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] Unable to read from SQL schema: %s\n", config.name, config.type, path, strerror(errno));
    return(0);
  }

  fclose(f);
  
  ptr = strrchr(buf, ';');
  if (!ptr) {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] missing trailing ';' in SQL query.\n", config.name, config.type, path);
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

int check_bosbit(u_char *label)
{
  u_char *ptr;

  ptr = label+2;

  if (*ptr & 0x1) return TRUE;
  else return FALSE;
}

u_int32_t decode_mpls_label(char *label)
{
  u_int32_t ret = 0;
  u_char label_ttl[4];

  memset(label_ttl, 0, 4);
  memcpy(label_ttl, label, 3);
  ret = ntohl(*(uint32_t *)(label_ttl));
  ret = ((ret & 0xfffff000 /* label mask */) >> 12 /* label shift */);

  return ret;
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

void reset_tag_label_status(struct packet_ptrs_vector *pptrsv)
{
  pptrsv->v4.tag = FALSE;
  pptrsv->vlan4.tag = FALSE;
  pptrsv->mpls4.tag = FALSE;
  pptrsv->vlanmpls4.tag = FALSE;
  pptrsv->v4.tag2 = FALSE;
  pptrsv->vlan4.tag2 = FALSE;
  pptrsv->mpls4.tag2 = FALSE;
  pptrsv->vlanmpls4.tag2 = FALSE;
  pretag_free_label(&pptrsv->v4.label);
  pretag_free_label(&pptrsv->vlan4.label);
  pretag_free_label(&pptrsv->mpls4.label);
  pretag_free_label(&pptrsv->vlanmpls4.label);

#if defined ENABLE_IPV6
  pptrsv->v6.tag = FALSE;
  pptrsv->vlan6.tag = FALSE;
  pptrsv->mpls6.tag = FALSE;
  pptrsv->vlanmpls6.tag = FALSE;
  pptrsv->v6.tag2 = FALSE;
  pptrsv->vlan6.tag2 = FALSE;
  pptrsv->mpls6.tag2 = FALSE;
  pptrsv->vlanmpls6.tag2 = FALSE;
  pretag_free_label(&pptrsv->v6.label);
  pretag_free_label(&pptrsv->vlan6.label);
  pretag_free_label(&pptrsv->mpls6.label);
  pretag_free_label(&pptrsv->vlanmpls6.label);
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
  if (!cfg->proc_name) cfg->proc_name = default_proc_name;
  if (config.acct_type == ACCT_NF || config.acct_type == ACCT_SF) {
    if (!cfg->nfacctd_net) cfg->nfacctd_net = NF_NET_KEEP;
    if (!cfg->nfacctd_as) cfg->nfacctd_as = NF_AS_KEEP;
    set_truefalse_nonzero(&cfg->nfacctd_disable_checks);
  }
  set_truefalse_nonzero(&cfg->pipe_check_core_pid);
  set_truefalse_nonzero(&cfg->tmp_net_own_field);
  if (!cfg->nfacctd_bgp_peer_as_src_type) cfg->nfacctd_bgp_peer_as_src_type = BGP_SRC_PRIMITIVES_KEEP;
  if (!cfg->nfacctd_bgp_src_std_comm_type) cfg->nfacctd_bgp_src_std_comm_type = BGP_SRC_PRIMITIVES_KEEP;
  if (!cfg->nfacctd_bgp_src_ext_comm_type) cfg->nfacctd_bgp_src_ext_comm_type = BGP_SRC_PRIMITIVES_KEEP;
  if (!cfg->nfacctd_bgp_src_lrg_comm_type) cfg->nfacctd_bgp_src_lrg_comm_type = BGP_SRC_PRIMITIVES_KEEP;
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

void *pm_malloc(size_t size)
{
  unsigned char *obj;

  obj = (unsigned char *) malloc(size);
  if (!obj) {
    sbrk(size);
    obj = (unsigned char *) malloc(size);
    if (!obj) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Unable to grab enough memory (requested: %llu bytes). Exiting ...\n",
      config.name, config.type, size);
      exit_plugin(1);
    }
  }

  return obj;
}

void *pm_tsearch(const void *key, void **rootp, int (*compar)(const void *key1, const void *key2), size_t alloc_size)
{
  void *alloc_key, *ret_key;

  if (alloc_size) {
    alloc_key = malloc(alloc_size);
    memcpy(alloc_key, key, alloc_size);
    ret_key = tsearch(alloc_key, rootp, compar);

    if ((*(void **) ret_key) != alloc_key) free(alloc_key);

    return ret_key;
  }
  else return tsearch(key, rootp, compar); 
}

void *pm_tfind(const void *key, void *const *rootp, int (*compar) (const void *key1, const void *key2))
{
  return tfind(key, rootp, compar);
}

void *pm_tdelete(const void *key, void **rootp, int (*compar)(const void *key1, const void *key2))
{
  return tdelete(key, rootp, compar);
}

void pm_twalk(const void *root, void (*action)(const void *nodep, const VISIT which, const int depth))
{
  twalk(root, action);
}

void pm_tdestroy(void **root, void (*free_node)(void *nodep))
{
  /* in implementations where tdestroy() is not defined, tdelete() against
     the root node of the three destroys also the last few remaining bits */
#if (defined HAVE_TDESTROY)
  tdestroy((*root), free_node);
#endif
  (*root) = NULL;
}

void load_allow_file(char *filename, struct hosts_table *t)
{
  FILE *file;
  char buf[SRVBUFLEN];
  int index = 0;

  if (filename) {
    if ((file = fopen(filename, "r")) == NULL) {
      Log(LOG_ERR, "ERROR ( %s/%s ): [%s] file not found.\n", config.name, config.type, filename);
      exit(1);
    }

    memset(t->table, 0, sizeof(t->table));
    while (!feof(file)) {
      if (index >= MAX_MAP_ENTRIES) break; /* XXX: we shouldn't exit silently */
      memset(buf, 0, SRVBUFLEN);
      if (fgets(buf, SRVBUFLEN, file)) {
        if (!sanitize_buf(buf)) {
          if (str_to_addr(buf, &t->table[index])) index++;
          else Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Bad IP address '%s'. Ignored.\n", config.name, config.type, filename, buf);
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
      Log(LOG_ERR, "ERROR ( %s/core/BGP ): [%s] file not found.\n", config.name, filename);
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
          else Log(LOG_WARNING, "WARN ( %s/core/BGP ): [%s] line '%s' ignored.\n", config.name, filename, buf);
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
    *tag = xsmc->tag;
    *tag2 = xsmc->tag2;
    ret = xsmc->ret;
    memcpy(&pptrs->lookup_bgp_port, &xsmc->port, sizeof(s_uint16_t));
  }
  else {
    if (find_id_func) {
      ret = find_id_func(t, pptrs, tag, tag2);
      if (xsmc) {
	xsmc->tag = *tag;
	xsmc->tag2 = *tag2;
	xsmc->ret = ret;
	memcpy(&xsmc->port, &pptrs->lookup_bgp_port, sizeof(s_uint16_t));
	gettimeofday(&xsmc->stamp, NULL);
      }
    }
  }

  if (ret & PRETAG_MAP_RCODE_ID) pptrs->bta_af = ETHERTYPE_IP;
#if defined ENABLE_IPV6
  else if (ret & BTA_MAP_RCODE_ID_ID2) pptrs->bta_af = ETHERTYPE_IPV6;
#endif

  return ret;
}

void calc_refresh_timeout(time_t deadline, time_t now, int *timeout)
{
  if (deadline >= now) *timeout = ((deadline-now)+1)*1000;
  else *timeout = 0;
}

/* secs version of calc_refresh_timeout() */
void calc_refresh_timeout_sec(time_t deadline, time_t now, int *timeout)
{
  if (deadline >= now) *timeout = ((deadline-now)+1);
  else *timeout = 0;
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
    neg = pt_check_neg(&count_token, NULL);
    range_ptr = pt_check_range(count_token);
    value = strtoull(count_token, &endptr_v, 10);
    if (range_ptr) range = strtoull(range_ptr, &endptr_r, 10);
    else range = value;

    if (range_ptr && range <= value) {
      Log(LOG_ERR, "WARN ( %s/%s ): [%s] Range value is expected in format low-high. '%llu-%llu'.\n",
			config.name, config.type, filename, value, range);
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

int load_labels(char *filename, struct pretag_label_filter *filter, char *value_ptr)
{
  char *count_token, *value;
  int changes = 0;
  u_int8_t neg = 0;

  if (!filter || !value_ptr) return changes;

  filter->num = 0;

  while ((count_token = extract_token(&value_ptr, ',')) && changes < MAX_PRETAG_MAP_ENTRIES/4) {
    neg = pt_check_neg(&count_token, NULL);
    value = count_token;

    filter->table[filter->num].neg = neg;
    filter->table[filter->num].v = value;
    filter->table[filter->num].len = strlen(value);
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

int evaluate_labels(struct pretag_label_filter *filter, pt_label_t *label)
{
  char null_label[] = "null";
  int index;

  if (filter->num == 0) return FALSE; /* no entries in the filter array: tag filtering disabled */
  if (!label->val) label->val = null_label; 

  for (index = 0; index < filter->num; index++) {
    if (!memcmp(filter->table[index].v, label->val, filter->table[index].len)) return (FALSE | filter->table[index].neg);
    else {
      if (filter->table[index].neg) return FALSE;
    }
  }

  return TRUE;
}

void load_pkt_len_distrib_bins()
{
  char *ptr, *endptr_v, *endptr_r, *token, *range_ptr, *pkt_len_distrib_unknown;
  u_int16_t value = 0, range = 0;
  int idx, aux_idx;

  ptr = config.pkt_len_distrib_bins_str;

  pkt_len_distrib_unknown = malloc(strlen("unknown") + 1);
  strcpy(pkt_len_distrib_unknown, "unknown");

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

void version_daemon(char *header)
{
  printf("%s (%s)\n", header, PMACCT_BUILD);
  printf("%s\n\n", PMACCT_COMPILE_ARGS);
  printf("For suggestions, critics, bugs, contact me: %s.\n", MANTAINER);
} 

#ifdef WITH_JANSSON 
char *compose_json_str(void *obj)
{
  char *tmpbuf = NULL;
  json_t *json_obj = (json_t *) obj;

  tmpbuf = json_dumps(obj, JSON_PRESERVE_ORDER);
  json_decref(obj);

  return tmpbuf;
}

void write_and_free_json(FILE *f, void *obj)
{
  char *tmpbuf = NULL;
  json_t *json_obj = (json_t *) obj;

  if (!f) return;

  /* Waiting for jansson issue #256 on GitHub to be solved,
     ie. introduction of trailing newline chars, in order to
     switch to json_dumpf() */
  tmpbuf = json_dumps(json_obj, JSON_PRESERVE_ORDER);
  json_decref(json_obj);

  if (tmpbuf) {
    fprintf(f, "%s\n", tmpbuf);
    free(tmpbuf);
  }
}

#ifdef WITH_RABBITMQ
int write_and_free_json_amqp(void *amqp_log, void *obj)
{
  char *orig_amqp_routing_key = NULL, dyn_amqp_routing_key[SRVBUFLEN];
  struct p_amqp_host *alog = (struct p_amqp_host *) amqp_log;
  int ret = ERR;

  char *tmpbuf = NULL;
  json_t *json_obj = (json_t *) obj;

  tmpbuf = json_dumps(json_obj, JSON_PRESERVE_ORDER);
  json_decref(json_obj);

  if (tmpbuf) {
    if (alog->rk_rr.max) {
      orig_amqp_routing_key = p_amqp_get_routing_key(alog);
      P_handle_table_dyn_rr(dyn_amqp_routing_key, SRVBUFLEN, orig_amqp_routing_key, &alog->rk_rr);
      p_amqp_set_routing_key(alog, dyn_amqp_routing_key);
    }

    ret = p_amqp_publish_string(alog, tmpbuf);
    free(tmpbuf);

    if (alog->rk_rr.max) p_amqp_set_routing_key(alog, orig_amqp_routing_key);
  }

  return ret;
}
#endif

#ifdef WITH_KAFKA
int write_and_free_json_kafka(void *kafka_log, void *obj)
{
  char *orig_kafka_topic = NULL, dyn_kafka_topic[SRVBUFLEN];
  struct p_kafka_host *alog = (struct p_kafka_host *) kafka_log;
  int ret = ERR;

  char *tmpbuf = NULL;
  json_t *json_obj = (json_t *) obj;

  tmpbuf = json_dumps(json_obj, JSON_PRESERVE_ORDER);
  json_decref(json_obj);

  if (tmpbuf) {
    if (alog->topic_rr.max) {
      orig_kafka_topic = p_kafka_get_topic(alog);
      P_handle_table_dyn_rr(dyn_kafka_topic, SRVBUFLEN, orig_kafka_topic, &alog->topic_rr);
      p_kafka_set_topic(alog, dyn_kafka_topic);
    }

    ret = p_kafka_produce_data(alog, tmpbuf, strlen(tmpbuf));
    free(tmpbuf);

    if (alog->topic_rr.max) p_kafka_set_topic(alog, orig_kafka_topic);
  }

  return ret;
}
#endif

void add_writer_name_and_pid_json(void *obj, char *name, pid_t writer_pid)
{
  char wid[SHORTSHORTBUFLEN]; 
  json_t *json_obj = (json_t *) obj;

  snprintf(wid, SHORTSHORTBUFLEN, "%s/%u", name, writer_pid);
  json_object_set_new_nocheck(json_obj, "writer_id", json_string(wid));
}
#else
char *compose_json_str(void *obj)
{
  if (config.debug) Log(LOG_DEBUG, "DEBUG ( %s/%s ): compose_json_str(): JSON object not created due to missing --enable-jansson\n", config.name, config.type);

  return NULL;
}

void write_and_free_json(FILE *f, void *obj)
{
  if (config.debug) Log(LOG_DEBUG, "DEBUG ( %s/%s ): write_and_free_json(): JSON object not created due to missing --enable-jansson\n", config.name, config.type);
}

int write_and_free_json_amqp(void *amqp_log, void *obj)
{
  if (config.debug) Log(LOG_DEBUG, "DEBUG ( %s/%s ): write_and_free_json_amqp(): JSON object not created due to missing --enable-jansson\n", config.name, config.type);

  return 0;
}

int write_and_free_json_kafka(void *kafka_log, void *obj)
{
  if (config.debug) Log(LOG_DEBUG, "DEBUG ( %s/%s ): write_and_free_json_kafka(): JSON object not created due to missing --enable-jansson\n", config.name, config.type);

  return 0;
}

void add_writer_name_and_pid_json(void *obj, char *name, pid_t writer_pid)
{
  if (config.debug) Log(LOG_DEBUG, "DEBUG ( %s/%s ): add_writer_name_and_pid_json(): JSON object not created due to missing --enable-jansson\n", config.name, config.type);
}
#endif

#ifdef WITH_AVRO
void write_avro_schema_to_file(char *filename, avro_schema_t schema)
{
  FILE *avro_fp = open_output_file(filename, "w", TRUE);
  avro_writer_t avro_schema_writer = avro_writer_file(avro_fp);

  if (avro_schema_to_json(schema, avro_schema_writer)) {
    Log(LOG_ERR, "ERROR ( %s/%s ): AVRO: unable to dump schema: %s\n", config.name, config.type, avro_strerror());
    exit(1);
  }

  close_output_file(avro_fp);
}

char *compose_avro_purge_schema(avro_schema_t avro_schema, char *writer_name)
{
  avro_writer_t avro_writer;
  char *avro_buf = NULL, *json_str = NULL;

  if (!config.avro_buffer_size) config.avro_buffer_size = LARGEBUFLEN;

  avro_buf = malloc(config.avro_buffer_size);

  if (!avro_buf) {
    Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (avro_buf). Exiting ..\n", config.name, config.type);
    exit_plugin(1);
  }
  else memset(avro_buf, 0, config.avro_buffer_size);

  avro_writer = avro_writer_memory(avro_buf, config.avro_buffer_size);

  if (avro_schema_to_json(avro_schema, avro_writer)) {
    Log(LOG_ERR, "ERROR ( %s/%s ): AVRO: unable to dump schema: %s\n", config.name, config.type, avro_strerror());
    exit_plugin(1);
  }

  if (avro_writer_tell(avro_writer)) {
    char event_type[] = "purge_schema", wid[SHORTSHORTBUFLEN];
    json_t *obj = json_object();

    json_object_set_new_nocheck(obj, "event_type", json_string(event_type));

    snprintf(wid, SHORTSHORTBUFLEN, "%s/%u", writer_name, 0);
    json_object_set_new_nocheck(obj, "writer_id", json_string(wid));

    json_object_set_new_nocheck(obj, "schema", json_string(avro_buf));

    avro_writer_free(avro_writer);
    free(avro_buf);

    json_str = compose_json_str(obj);
  }

  return json_str;
}
#endif

void compose_timestamp(char *buf, int buflen, struct timeval *tv, int usec, int since_epoch)
{
  char tmpbuf[SRVBUFLEN];
  time_t time1;
  struct tm *time2;

  if (config.timestamps_since_epoch) {
    if (usec) snprintf(buf, buflen, "%u.%u", tv->tv_sec, tv->tv_usec);
    else snprintf(buf, buflen, "%u", tv->tv_sec);
  }
  else {
    time1 = tv->tv_sec;
    time2 = localtime(&time1);
    strftime(tmpbuf, SRVBUFLEN, "%Y-%m-%d %H:%M:%S", time2);

    if (usec) snprintf(buf, buflen, "%s.%u", tmpbuf, tv->tv_usec);
    else snprintf(buf, buflen, "%s", tmpbuf);
  }
}

void print_primitives(int acct_type, char *header)
{
  int idx;

  printf("%s (%s)\n", header, PMACCT_BUILD);

  for (idx = 0; strcmp(_primitives_matrix[idx].name, ""); idx++) {
    if ((acct_type == ACCT_NF && _primitives_matrix[idx].nfacctd) ||
	(acct_type == ACCT_SF && _primitives_matrix[idx].sfacctd) ||
	(acct_type == ACCT_PM && _primitives_matrix[idx].pmacctd)) {
      if (strcmp(_primitives_matrix[idx].desc, "")) /* entry */
        printf("%-32s : %-64s\n", _primitives_matrix[idx].name, _primitives_matrix[idx].desc);
      else /* title */
        printf("\n%s\n", _primitives_matrix[idx].name);
    }
  }
}

void set_primptrs_funcs(struct extra_primitives *extras)
{
  int idx = 0;

  memset(primptrs_funcs, 0, sizeof(primptrs_funcs));

  if (extras->off_pkt_bgp_primitives) {
    primptrs_funcs[idx] = primptrs_set_bgp;
    idx++;
  }

  if (extras->off_pkt_lbgp_primitives) {
    primptrs_funcs[idx] = primptrs_set_lbgp;
    idx++;
  }

  if (extras->off_pkt_nat_primitives) { 
    primptrs_funcs[idx] = primptrs_set_nat;
    idx++;
  }

  if (extras->off_pkt_mpls_primitives) { 
    primptrs_funcs[idx] = primptrs_set_mpls;
    idx++;
  }

  if (extras->off_custom_primitives) {
    primptrs_funcs[idx] = primptrs_set_custom;
    idx++;
  }

  if (extras->off_pkt_extras) {
    primptrs_funcs[idx] = primptrs_set_extras;
    idx++;
  }

  if (extras->off_pkt_vlen_hdr_primitives) {
    primptrs_funcs[idx] = primptrs_set_vlen_hdr;
    idx++;
  }
}

void primptrs_set_bgp(u_char *base, struct extra_primitives *extras, struct primitives_ptrs *prim_ptrs)
{
  prim_ptrs->pbgp = (struct pkt_bgp_primitives *) (base + extras->off_pkt_bgp_primitives);
  prim_ptrs->vlen_next_off = 0;
}

void primptrs_set_lbgp(u_char *base, struct extra_primitives *extras, struct primitives_ptrs *prim_ptrs)
{
  prim_ptrs->plbgp = (struct pkt_legacy_bgp_primitives *) (base + extras->off_pkt_lbgp_primitives);
  prim_ptrs->vlen_next_off = 0;
}

void primptrs_set_nat(u_char *base, struct extra_primitives *extras, struct primitives_ptrs *prim_ptrs)
{
  prim_ptrs->pnat = (struct pkt_nat_primitives *) (base + extras->off_pkt_nat_primitives);
  prim_ptrs->vlen_next_off = 0;
}

void primptrs_set_mpls(u_char *base, struct extra_primitives *extras, struct primitives_ptrs *prim_ptrs)
{
  prim_ptrs->pmpls = (struct pkt_mpls_primitives *) (base + extras->off_pkt_mpls_primitives);
  prim_ptrs->vlen_next_off = 0;
}

void primptrs_set_custom(u_char *base, struct extra_primitives *extras, struct primitives_ptrs *prim_ptrs)
{
  prim_ptrs->pcust = (char *) (base + extras->off_custom_primitives);
  prim_ptrs->vlen_next_off = 0;
}

void primptrs_set_extras(u_char *base, struct extra_primitives *extras, struct primitives_ptrs *prim_ptrs)
{
  prim_ptrs->pextras = (struct pkt_extras *) (base + extras->off_pkt_extras);
  prim_ptrs->vlen_next_off = 0;
}

void primptrs_set_vlen_hdr(u_char *base, struct extra_primitives *extras, struct primitives_ptrs *prim_ptrs)
{
  prim_ptrs->pvlen = (struct pkt_vlen_hdr_primitives *) (base + extras->off_pkt_vlen_hdr_primitives);
  prim_ptrs->vlen_next_off = extras->off_pkt_vlen_hdr_primitives + PvhdrSz + prim_ptrs->pvlen->tot_len;
}

int custom_primitives_vlen(struct custom_primitives_ptrs *cpptrs)
{
  int cpptrs_idx, vlen_prims = 0;
  struct custom_primitive_entry *cpe;

  for (cpptrs_idx = 0; cpptrs->primitive[cpptrs_idx].name && cpptrs_idx < cpptrs->num; cpptrs_idx++) {
    cpe = cpptrs->primitive[cpptrs_idx].ptr;
    if (cpe->len == PM_VARIABLE_LENGTH) vlen_prims++;
  }

  return vlen_prims;
}

void custom_primitives_reconcile(struct custom_primitives_ptrs *cpptrs, struct custom_primitives *registry)
{
  int cpptrs_idx, registry_idx;
  int pad = 0;

  /* first pass: linking */
  for (cpptrs_idx = 0; cpptrs->primitive[cpptrs_idx].name && cpptrs_idx < cpptrs->num; cpptrs_idx++) {
    for (registry_idx = 0; registry->primitive[registry_idx].len && registry_idx < registry->num; registry_idx++) {
      if (!strcmp(cpptrs->primitive[cpptrs_idx].name, registry->primitive[registry_idx].name)) {
        if (registry->primitive[registry_idx].len == PM_VARIABLE_LENGTH) {
	  cpptrs->primitive[cpptrs_idx].ptr = &registry->primitive[registry_idx];
	  cpptrs->primitive[cpptrs_idx].off = PM_VARIABLE_LENGTH;
	}
	else if (cpptrs->len + registry->primitive[registry_idx].len < UINT16_MAX) {
	  cpptrs->primitive[cpptrs_idx].ptr = &registry->primitive[registry_idx];
	  cpptrs->primitive[cpptrs_idx].off = cpptrs->len;
	  cpptrs->len += registry->primitive[registry_idx].alloc_len;
	}
	else {
	  Log(LOG_WARNING, "WARN ( %s/%s ): Max allocatable space for custom primitives finished (%s).\n",
		config.name, config.type, cpptrs->primitive[cpptrs_idx].name);
	  cpptrs->primitive[cpptrs_idx].ptr = NULL;
	}

	break;
      }
    }
  } 
  
  /* second pass: verification and finish-off */
  for (cpptrs_idx = 0; cpptrs->primitive[cpptrs_idx].name && cpptrs_idx < cpptrs->num; cpptrs_idx++) {
    if (!cpptrs->primitive[cpptrs_idx].ptr) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Unknown primitive '%s'\n", config.name, config.type, cpptrs->primitive[cpptrs_idx].name);
      exit(1);
    }
    else {
      struct custom_primitive_entry *cpe = cpptrs->primitive[cpptrs_idx].ptr;

      if (cpptrs->primitive[cpptrs_idx].off != PM_VARIABLE_LENGTH) { 
        Log(LOG_DEBUG, "DEBUG ( %s/%s ): Custom primitive '%s': type=%llx off=%u len=%u\n", config.name, config.type,
	  cpptrs->primitive[cpptrs_idx].name, cpe->type, cpptrs->primitive[cpptrs_idx].off, cpe->len);
      }
      else {
        Log(LOG_DEBUG, "DEBUG ( %s/%s ): Custom primitive '%s': type=%llx len=vlen\n", config.name, config.type,
	  cpptrs->primitive[cpptrs_idx].name, cpe->type);
      } 
    }
  }

  if (cpptrs->len) pad = 8 - (cpptrs->len % 8);
  cpptrs->len += pad; /* padding to a safe 64-bit boundary */
}

void custom_primitive_header_print(char *out, int outlen, struct custom_primitive_ptrs *cp_entry, int formatted)
{
  char format[SRVBUFLEN];

  if (out && cp_entry) {
    memset(out, 0, outlen);

    if (cp_entry->ptr->semantics == CUSTOM_PRIMITIVE_TYPE_UINT ||
        cp_entry->ptr->semantics == CUSTOM_PRIMITIVE_TYPE_HEX) {
      if (formatted) {
	snprintf(format, SRVBUFLEN, "%%-%u", cps_flen[cp_entry->ptr->len] > strlen(cp_entry->ptr->name) ? cps_flen[cp_entry->ptr->len] : strlen(cp_entry->ptr->name));
	strncat(format, "s", SRVBUFLEN);
      }
      else snprintf(format, SRVBUFLEN, "%s", "%s");
    }
    else if (cp_entry->ptr->semantics == CUSTOM_PRIMITIVE_TYPE_STRING ||
	     cp_entry->ptr->semantics == CUSTOM_PRIMITIVE_TYPE_RAW) {
      if (formatted) {
	snprintf(format, SRVBUFLEN, "%%-%u", cp_entry->ptr->len > strlen(cp_entry->ptr->name) ? cp_entry->ptr->len : strlen(cp_entry->ptr->name));
	strncat(format, "s", SRVBUFLEN);
      }
      else snprintf(format, SRVBUFLEN, "%s", "%s");
    }
    else if (cp_entry->ptr->semantics == CUSTOM_PRIMITIVE_TYPE_IP) {
      int len = 0;

      len = INET_ADDRSTRLEN;
#if defined ENABLE_IPV6
      len = INET6_ADDRSTRLEN;
#endif
      	
      if (formatted) {
        snprintf(format, SRVBUFLEN, "%%-%u", len > strlen(cp_entry->ptr->name) ? len : strlen(cp_entry->ptr->name));
        strncat(format, "s", SRVBUFLEN);
      }
      else snprintf(format, SRVBUFLEN, "%s", "%s");
    }
    else if (cp_entry->ptr->semantics == CUSTOM_PRIMITIVE_TYPE_MAC) {
      int len = ETHER_ADDRSTRLEN;

      if (formatted) {
        snprintf(format, SRVBUFLEN, "%%-%u", len > strlen(cp_entry->ptr->name) ? len : strlen(cp_entry->ptr->name));
        strncat(format, "s", SRVBUFLEN);
      }
      else snprintf(format, SRVBUFLEN, "%s", "%s");
    }

    snprintf(out, outlen, format, cp_entry->ptr->name);
  }
}

void custom_primitive_value_print(char *out, int outlen, char *in, struct custom_primitive_ptrs *cp_entry, int formatted)
{
  char format[SRVBUFLEN];

  if (in && out && cp_entry) {
    memset(out, 0, outlen); 

    if (cp_entry->ptr->semantics == CUSTOM_PRIMITIVE_TYPE_UINT ||
	cp_entry->ptr->semantics == CUSTOM_PRIMITIVE_TYPE_HEX) {
      if (formatted)
        snprintf(format, SRVBUFLEN, "%%-%u%s", cps_flen[cp_entry->ptr->len] > strlen(cp_entry->ptr->name) ? cps_flen[cp_entry->ptr->len] : strlen(cp_entry->ptr->name), 
			cps_type[cp_entry->ptr->semantics]); 
      else
        snprintf(format, SRVBUFLEN, "%%%s", cps_type[cp_entry->ptr->semantics]); 

      if (cp_entry->ptr->len == 1) {
        u_int8_t t8;

        memcpy(&t8, (in+cp_entry->off), 1);
	snprintf(out, outlen, format, t8);
      }
      else if (cp_entry->ptr->len == 2) {
        u_int16_t t16, st16;

        memcpy(&t16, (in+cp_entry->off), 2);
	st16 = ntohs(t16);
	snprintf(out, outlen, format, st16);
      }
      else if (cp_entry->ptr->len == 4) {
        u_int32_t t32, st32;

        memcpy(&t32, (in+cp_entry->off), 4);
        st32 = ntohl(t32);
	snprintf(out, outlen, format, st32);
      }
      else if (cp_entry->ptr->len == 8) {
        u_int64_t t64, st64;

        memcpy(&t64, (in+cp_entry->off), 8);
        st64 = pm_ntohll(t64);
	snprintf(out, outlen, format, st64);
      }
    }
    else if (cp_entry->ptr->semantics == CUSTOM_PRIMITIVE_TYPE_STRING ||
	     cp_entry->ptr->semantics == CUSTOM_PRIMITIVE_TYPE_RAW) {
      if (formatted)
	snprintf(format, SRVBUFLEN, "%%-%u%s", cp_entry->ptr->len > strlen(cp_entry->ptr->name) ? cp_entry->ptr->len : strlen(cp_entry->ptr->name),
			cps_type[cp_entry->ptr->semantics]); 
      else
	snprintf(format, SRVBUFLEN, "%%%s", cps_type[cp_entry->ptr->semantics]); 

      snprintf(out, outlen, format, (in+cp_entry->off));
    }
    else if (cp_entry->ptr->semantics == CUSTOM_PRIMITIVE_TYPE_IP) {
      struct host_addr ip_addr;
      char ip_str[INET6_ADDRSTRLEN];
      int len = 0;

      memset(&ip_addr, 0, sizeof(ip_addr));
      memset(ip_str, 0, sizeof(ip_str));

      len = INET_ADDRSTRLEN;
#if defined ENABLE_IPV6
      len = INET6_ADDRSTRLEN;
#endif

      if (cp_entry->ptr->len == 4) { 
	ip_addr.family = AF_INET;
	memcpy(&ip_addr.address.ipv4, in+cp_entry->off, 4); 
      }
#if defined ENABLE_IPV6
      else if (cp_entry->ptr->len == 16) {
	ip_addr.family = AF_INET6;
	memcpy(&ip_addr.address.ipv6, in+cp_entry->off, 16); 
      }
#endif

      addr_to_str(ip_str, &ip_addr);
      if (formatted)
        snprintf(format, SRVBUFLEN, "%%-%u%s", len > strlen(cp_entry->ptr->name) ? len : strlen(cp_entry->ptr->name),
                        cps_type[cp_entry->ptr->semantics]);
      else
        snprintf(format, SRVBUFLEN, "%%%s", cps_type[cp_entry->ptr->semantics]);

      snprintf(out, outlen, format, ip_str);
    }
    else if (cp_entry->ptr->semantics == CUSTOM_PRIMITIVE_TYPE_MAC) {
      char eth_str[ETHER_ADDRSTRLEN];
      int len = ETHER_ADDRSTRLEN;

      memset(eth_str, 0, sizeof(eth_str));
      etheraddr_string(in+cp_entry->off, eth_str);

      if (formatted)
        snprintf(format, SRVBUFLEN, "%%-%u%s", len > strlen(cp_entry->ptr->name) ? len : strlen(cp_entry->ptr->name),
                        cps_type[cp_entry->ptr->semantics]);
      else
        snprintf(format, SRVBUFLEN, "%%%s", cps_type[cp_entry->ptr->semantics]);

      snprintf(out, outlen, format, eth_str);
    }
  }
}

int mkdir_multilevel(const char *path, int trailing_filename, uid_t owner, gid_t group)
{
  char opath[SRVBUFLEN];
  char *p;
  int ret = 0, len = 0;

  strlcpy(opath, path, sizeof(opath));

  for (p = opath; *p; p++, len++) {
    if (*p == '/') {
      *p = '\0';
      if (len && access(opath, F_OK)) {
        ret = mkdir(opath, (S_IRWXU|S_IRWXG|S_IRWXO));
        if (ret) return ret;
        if (chown(opath, owner, group) == -1) return ret;
      }
      *p = '/';
    }
  }

  /* do a last mkdir in case the path was not terminated
     by a traiing '/' and we do not expect the last part
     to be a filename, ie. trailing_filename set to 0 */
  if (!trailing_filename && access(opath, F_OK)) {
    ret = mkdir(opath, (S_IRWXU|S_IRWXG|S_IRWXO));
    if (ret) return ret;
  }

  return ret;
}

char bin_to_hex(int nib) { return (nib < 10) ? ('0' + nib) : ('A' - 10 + nib); }

int print_hex(const u_char *a, u_char *buf, int len)
{
  int b = 0, i = 0;

  for (; i < len; i++) {
    u_char byte;

    // if (a[i] == '\0') break;

    byte = a[i];
    buf[b++] = bin_to_hex(byte >> 4);
    buf[b++] = bin_to_hex(byte & 0x0f);

    // separate the bytes with a dash
    if (i < (len - 1)) buf[b++] = '-';
  }

  if (buf[b-1] == '-') {
    buf[b-1] = '\0';
    return b;
  }
  else {
    buf[b] = '\0';
    return (b+1);
  }
}

unsigned char *vlen_prims_copy(struct pkt_vlen_hdr_primitives *src)
{
  unsigned char *dst = NULL;
  int len = 0;

  if (!src) return NULL;

  len = PvhdrSz + src->tot_len;
  dst = malloc(len);
  
  if (dst) {
    vlen_prims_init((struct pkt_vlen_hdr_primitives *) dst, src->tot_len);
    memcpy(dst, src, len);
  }

  return dst;
}

void vlen_prims_init(struct pkt_vlen_hdr_primitives *hdr, int add_len)
{
  if (!hdr) return;

  memset(hdr, 0, PvhdrSz + add_len);
}

void vlen_prims_free(struct pkt_vlen_hdr_primitives *hdr)
{
  if (!hdr) return;

  free(hdr);
}

int vlen_prims_cmp(struct pkt_vlen_hdr_primitives *src, struct pkt_vlen_hdr_primitives *dst)
{
  if (!src || !dst) return ERR;

  if (src->tot_len != dst->tot_len) return (src->tot_len - dst->tot_len);

  return memcmp(src, dst, (src->tot_len + PvhdrSz));
}

void vlen_prims_get(struct pkt_vlen_hdr_primitives *hdr, pm_cfgreg_t wtc, char **res)
{
  pm_label_t *label_ptr;
  char *ptr = (char *) hdr;
  int x, rlen;

  if (res) *res = NULL;

  if (!hdr || !wtc || !res) return;

  ptr += PvhdrSz; 
  label_ptr = (pm_label_t *) ptr; 

  for (x = 0, rlen = 0; x < hdr->num && rlen < hdr->tot_len; x++) {
    if (label_ptr->type == wtc) {
      if (label_ptr->len) {
        ptr += PmLabelTSz;
        *res = ptr;
      }

      return; 
    }
    else {
      ptr += (PmLabelTSz + label_ptr->len);
      rlen += (PmLabelTSz + label_ptr->len);
      label_ptr = (pm_label_t *) ptr;
    }
  }  
}

void vlen_prims_debug(struct pkt_vlen_hdr_primitives *hdr)
{
  pm_label_t *label_ptr;
  char *ptr = (char *) hdr;
  int x = 0;

  Log(LOG_DEBUG, "DEBUG ( %s/%s ): vlen_prims_debug(): VLEN ARRAY: num: %u tot_len: %u\n",
	config.name, config.type, hdr->num, hdr->tot_len);
  ptr += PvhdrSz;

  for (x = 0; x < hdr->num; x++) {
    label_ptr = (pm_label_t *) ptr;
    ptr += PmLabelTSz;

    Log(LOG_DEBUG, "DEBUG ( %s/%s ): vlen_prims_debug(): LABEL #%u: type: %llx len: %u val: %s\n",
	config.name, config.type, x, label_ptr->type, label_ptr->len, ptr);
  }
}

void vlen_prims_insert(struct pkt_vlen_hdr_primitives *hdr, pm_cfgreg_t wtc, int len, char *val, int copy_type /*, optional realloc */)
{
  pm_label_t *label_ptr;
  char *ptr = (char *) hdr;

  ptr += (PvhdrSz + hdr->tot_len); 
  label_ptr = (pm_label_t *) ptr;
  label_ptr->type = wtc;
  label_ptr->len = len;

  ptr += PmLabelTSz;

  if (len) {
    if (PM_MSG_BIN_COPY) memcpy(ptr, val, len);
    else if (PM_MSG_STR_COPY) strncpy(ptr, val, len);
  }

  hdr->num++;
  hdr->tot_len += (PmLabelTSz + len);
}

int vlen_prims_delete(struct pkt_vlen_hdr_primitives *hdr, pm_cfgreg_t wtc /*, optional realloc */)
{
  pm_label_t *label_ptr;
  char *ptr = (char *) hdr;
  int x = 0, ret = 0, jump = 0, off = 0;

  ptr += PvhdrSz;
  off += PvhdrSz;

  for (x = 0; x < hdr->num; x++) {
    label_ptr = (pm_label_t *) ptr;

    if (label_ptr->type == wtc) {
      char *new_ptr = ptr;

      jump = label_ptr->len;
      new_ptr += (PmLabelTSz + jump);
      off += (PmLabelTSz + jump);
      memset(ptr, 0, PmLabelTSz + jump);

      if (x + 1 < hdr->num) memcpy(ptr, new_ptr, hdr->tot_len - off); 

      hdr->num--;
      hdr->tot_len -= (PmLabelTSz + jump);
      /* XXX: optional realloc() */

      ret = (PmLabelTSz + jump);
      break;
    }
    else {
      ptr += (PmLabelTSz + label_ptr->len);
      off += (PmLabelTSz + label_ptr->len);
    }
  }

  return ret;
}

void replace_string(char *str, int string_len, char *var, char *value)
{
  char *ptr_start, *ptr_end;
  char buf[string_len];
  int ptr_len, len;

  if (!str || !var || !value) return;

  if (!strchr(str, '$')) return;

  if (string_len < ((strlen(str) + strlen(value)) - strlen(var))) return;

  ptr_start = strstr(str, var);
  if (ptr_start) {
    len = strlen(ptr_start);
    ptr_end = ptr_start;
    ptr_len = strlen(var);
    ptr_end += ptr_len;
    len -= ptr_len;

    snprintf(buf, string_len, "%s", value);
    strncat(buf, ptr_end, len);

    len = strlen(buf);
    *ptr_start = '\0';
    strncat(str, buf, len);
  }
}

void set_truefalse_nonzero(int *value)
{
  if (!value) return;

  if (!(*value)) (*value) = TRUE;
  else if ((*value) == FALSE_NONZERO) (*value) = FALSE;
}

void hash_init_key(pm_hash_key_t *key)
{
  if (!key) return;

  memset(key->val, 0, key->len); 
}

int hash_alloc_key(pm_hash_key_t *key, u_int16_t key_len)
{
  if (!key || !key_len) return ERR;

  if (!key->val) {
    key->val = malloc(key_len);
    if (key->val) {
      key->len = key_len;
      hash_init_key(key);
    }
    else return ERR;
  }
  else {
    key->val = realloc(key->val, key_len);
    if (key->val) key->len = key_len;
    else return ERR; 
  }

  return SUCCESS;
}

int hash_dup_key(pm_hash_key_t *dst, pm_hash_key_t *src)
{
  if (!src || !dst) return ERR;

  if (hash_alloc_key(dst, src->len) == ERR) return ERR;

  memcpy(dst->val, src->val, src->len);

  return SUCCESS;
}

void hash_destroy_key(pm_hash_key_t *key)
{
  if (!key) return;

  free(key->val);
  memset(key, 0, sizeof(pm_hash_key_t));
}

int hash_init_serial(pm_hash_serial_t *serial, u_int16_t key_len)
{
  int ret;

  if (!serial || !key_len) return ERR;

  memset(serial, 0, sizeof(pm_hash_serial_t));
  return hash_alloc_key(&serial->key, key_len);
}

void hash_destroy_serial(pm_hash_serial_t *serial)
{
  if (!serial) return;

  hash_destroy_key(&serial->key);
  memset(serial, 0, sizeof(pm_hash_serial_t));
}

void hash_serial_set_off(pm_hash_serial_t *serial, u_int16_t off)
{
  if (!serial) return;

  serial->off = off;
}

u_int16_t hash_serial_get_off(pm_hash_serial_t *serial)
{
  if (!serial) return ERR;

  return serial->off;
}

pm_hash_key_t *hash_serial_get_key(pm_hash_serial_t *serial)
{
  if (!serial) return NULL;

  return &serial->key;
}

u_int16_t hash_key_get_len(pm_hash_key_t *key)
{
  if (!key) return ERR;

  return key->len;
}

char *hash_key_get_val(pm_hash_key_t *key)
{
  if (!key) return NULL;

  return key->val;
}

void hash_serial_append(pm_hash_serial_t *serial, char *val, u_int16_t len, int realloc)
{
  u_int16_t key_len, key_off, rem_len;
  int ret;

  if (!serial || !val || !len) return;

  key_len = hash_key_get_len(&serial->key);
  key_off = hash_serial_get_off(serial);
  rem_len = (key_len - key_off);
 
  if (len > rem_len) {
    if (!realloc) return;
    else {
      ret = hash_alloc_key(&serial->key, (hash_key_get_len(&serial->key) + (len - rem_len)));      
      if (ret == ERR) return;
    }
  }

  memcpy((hash_key_get_val(&serial->key) + key_off), val, len); 
  hash_serial_set_off(serial, (key_off + len));
}

int hash_key_cmp(pm_hash_key_t *a, pm_hash_key_t *b)
{
  if (a->len != b->len) return (a->len - b->len);

  return memcmp(a->val, b->val, b->len);
}

void dump_writers_init()
{
  dump_writers.active = 0;
  dump_writers.max = config.dump_max_writers;
  if (dump_writers.list) memset(dump_writers.list, 0, (dump_writers.max * sizeof(pid_t)));
  dump_writers.flags = FALSE;
}

void dump_writers_count()
{
  u_int16_t idx, count;

  for (idx = 0, count = 0; idx < dump_writers.max; idx++) {
    if (dump_writers.list[idx]) {
      if (kill(dump_writers.list[idx], 0) != -1) count++;
      else dump_writers.list[idx] = 0;
    }
  }

  dump_writers.active = count;
  if (dump_writers.active == dump_writers.max) dump_writers.flags = CHLD_ALERT;
  else dump_writers.flags = FALSE;
}

u_int32_t dump_writers_get_flags()
{
  return dump_writers.flags;
}

u_int16_t dump_writers_get_active()
{
  return dump_writers.active;
}

u_int16_t dump_writers_get_max()
{
  return dump_writers.max;
}

int dump_writers_add(pid_t pid)
{
  u_int16_t idx;
  int ret = FALSE;

  if (dump_writers.flags != CHLD_ALERT) {
    for (idx = 0; idx < dump_writers.max; idx++) {
      if (!dump_writers.list[idx]) {
	dump_writers.list[idx] = pid; 
	break;
      }
    }

    ret = TRUE;
  }

  return ret;
}

int pm_scandir(const char *dir, struct dirent ***namelist,
            int (*select)(const struct dirent *),
            int (*compar)(const void *, const void *))
{
  DIR *d;
  struct dirent *entry;
  size_t entry_sz;
  int idx = 0;

  *namelist = NULL;

  if ((d = opendir(dir)) == NULL) return ERR;

  while ((entry = readdir(d))) {
    if (!select || (select && (*select)(entry))) {
      *namelist = (struct dirent **) realloc((void *)(*namelist), (size_t)((idx + 1) * sizeof(struct dirent *)));

      if (*namelist == NULL) {
         closedir(d);
         return ERR;
      }

      entry_sz = sizeof(struct dirent) - sizeof(entry->d_name) + strlen(entry->d_name) + 1;
      (*namelist)[idx] = (struct dirent *) malloc(entry_sz);

      if ((*namelist)[idx] == NULL) {
        closedir(d);
        return ERR;
      }

      memcpy((*namelist)[idx], entry, entry_sz);
      idx++;
    }
  }

  if (closedir(d)) return ERR;
  if (idx && (compar != NULL))
    qsort((void *)(*namelist), (size_t) idx, sizeof(struct dirent *), compar);

  return idx;
}

void pm_scandir_free(struct dirent ***namelist, int num)
{
  int idx;

  if (*namelist) {
    for (idx = 0; idx < num; idx++) free((*namelist)[idx]);

    free((*namelist));
    *namelist = NULL;
  }
}

int pm_alphasort(const void *a, const void *b)
{
  const struct dirent *dira = a;
  const struct dirent *dirb = b;

  return(strcmp(dira->d_name, dirb->d_name));
}

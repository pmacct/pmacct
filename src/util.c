/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2009 by Paolo Lucente
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
  int i, len;

  len = strlen(buf);
   
  /* trimming spaces at beginning of the string */
  for (i = 0; i <= len; i++) {
    if (!isspace(buf[i])) {
      if (i != 0)
        strlcpy(buf, &buf[i], len+1-i);
      break;
    } 
  }

  /* trimming spaces at the end of the string */
  for (i = strlen(buf)-1; i >= 0; i--) { 
    if (isspace(buf[i]))
      buf[i] = '\0';
    else break;
  }
}

void trim_all_spaces(char *buf)
{
  int i = 0, len, quotes = FALSE;

  len = strlen(buf);

  /* trimming all spaces */
  while (i <= len) {
    if (buf[i] == '\'') {
      if (!quotes) quotes = TRUE;
      else if (quotes) quotes = FALSE;
    }
    if (isspace(buf[i]) && !quotes) {
      strlcpy(&buf[i], &buf[i+1], len);
      len--;
    }
    else i++;
  }
}

void strip_quotes(char *buf)
{
  char *ptr;
  int i = 0, len;

  ptr = buf;
  len = strlen(buf);

  /* stripping all quote marks */
  while (i <= len) {
    if (ptr[i] == '\'') {
      strcpy(&buf[i], &ptr[i+1]);
      len--;
    }
    else i++;
  }
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


  file = fopen(filename, "a"); 
  if (file) {
    if (file_lock(fileno(file))) {
      Log(LOG_ALERT, "ALERT: Unable to obtain lock for logfile '%s'.\n", filename);
      file = NULL;
    }
  }
  else {
    Log(LOG_ERR, "ERROR: Unable to open logfile '%s'\n", filename);
    file = NULL;
  }

  if (file) {
    now = time(NULL);
    tmnow = localtime(&now);
    strftime(timebuf, SRVBUFLEN, "%Y-%m-%d %H:%M:%S" , tmnow);
    fprintf(file, "\n\n=== Start logging: %s ===\n\n", timebuf); 
    fflush(file);
  }

  return file;
}

void write_pid_file(char *filename)
{
  FILE *file;
  char pid[10];

  unlink(filename); 
    
  file = fopen(filename,"w");
  if (file) {
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

  fname = malloc(len);
  memset(fname, 0, sizeof(fname));
  strcpy(fname, filename);
  strcat(fname, minus);
  strcat(fname, type);
  strcat(fname, minus);
  strcat(fname, name);

  config.pidfile = fname;
  unlink(fname);

  file = fopen(fname,"w");
  if (file) {
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
  int ret, len, saved, value;

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
  int class = FALSE;
  int flows = FALSE;

  if (*wtc & COUNT_ID) {
    *wtc ^= COUNT_ID;
    tag = TRUE;
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

  memset(buf, 0, size);
  f = fopen(path, "r");
  if (!f) {
    Log(LOG_ERR, "ERROR: %s does not exist.\n", path);
    return(0);
  }
  
  fread(buf, size, 1, f);
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

#if defined ENABLE_IPV6
  pptrsv->v6.tag = FALSE;
  pptrsv->vlan6.tag = FALSE;
  pptrsv->mpls6.tag = FALSE;
  pptrsv->vlanmpls6.tag = FALSE;
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

void reset_tagdist_status(struct packet_ptrs_vector *pptrsv)
{
  pptrsv->v4.tag_dist = TRUE;
  pptrsv->vlan4.tag_dist = TRUE;
  pptrsv->mpls4.tag_dist = TRUE;
  pptrsv->vlanmpls4.tag_dist = TRUE;

#if defined ENABLE_IPV6
  pptrsv->v6.tag_dist = TRUE;
  pptrsv->vlan6.tag_dist = TRUE;
  pptrsv->mpls6.tag_dist = TRUE;
  pptrsv->vlanmpls6.tag_dist = TRUE;
#endif
}

void set_shadow_status(struct packet_ptrs *pptrs)
{
  pptrs->shadow = TRUE;
}

#if 0

Fields denoted by X will have their content modified

From network.h

  struct packet_ptrs {
D   struct pcap_pkthdr *pkthdr; /* ptr to header structure passed by libpcap */
    u_char *f_agent; /* ptr to flow export agent */
    u_char *f_header; /* ptr to NetFlow packet header */
    u_char *f_data; /* ptr to NetFlow data */
    u_char *f_tpl; /* ptr to NetFlow V9 template */
    u_char *f_status; /* ptr to status table entry */
    u_char *idtable; /* ptr to pretag table map */
D   u_char *packet_ptr; /* ptr to the whole packet */
    u_char *mac_ptr; /* ptr to mac addresses */
    u_int16_t l3_proto; /* layer-3 protocol: IPv4, IPv6 */
    int (*l3_handler)(register struct packet_ptrs *); /* layer-3 protocol handler */
    u_int16_t l4_proto; /* layer-4 protocol */
    u_int16_t tag; /* pre tag id */
    u_int16_t pf; /* pending fragments or packets */
    u_int8_t new_flow; /* pmacctd flows: part of a new flow ? */
    u_int8_t tcp_flags; /* pmacctd flows: TCP packet flags; URG, PUSH filtered out */
    u_char *vlan_ptr; /* ptr to vlan id */
    u_char *mpls_ptr; /* ptr to base MPLS label */
X   u_char *iph_ptr; /* ptr to ip header */
X   u_char *tlh_ptr; /* ptr to transport level protocol header */
X   u_char *payload_ptr; /* classifiers: ptr to packet payload */
    pm_class_t class; /* classifiers: class id */
    struct class_st cst; /* classifiers: class status */
    u_int8_t shadow; /* 0=the packet is being distributed for the 1st time
            1=the packet is being distributed for the 2nd+ time */
    u_int8_t tag_dist; /* tagged packet: 0=do not distribute the packet; 1=distribute it */
  };
#endif

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

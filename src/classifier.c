/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2019 by Paolo Lucente
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

#include "pmacct.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "ip_flow.h"
#include "classifier.h"
#include "jhash.h"
#if defined HAVE_DLOPEN
#include <dlfcn.h>
#endif

/* Global variables */
struct pkt_classifier *class;
u_int32_t class_trivial_hash_rnd = 140281;

void init_classifiers(char *path)
{
  char fname[2*MAX_FN_LEN+2]; //Allow space for %s/%s
  struct dirent **namelist;
  struct stat st;
  struct pkt_classifier css;
  int entries = 0, n = 0, x = 0, ret;
  int max = pmct_get_num_entries(); 

  if (!config.classifier_tentatives) config.classifier_tentatives = DEFAULT_TENTATIVES;

  class = map_shared(0, sizeof(struct pkt_classifier)*max, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
  memset(class, 0, sizeof(struct pkt_classifier)*max);

  /* valid case for nfacctd; NULL path checks are performed
     in daemons requiring it - ie. pmacctd, uacctd, etc. */
  if (!path) return;

  entries = pm_scandir(path, &namelist, 0, pm_alphasort);
  if (entries > 0) {
    while (n < entries) {
      memset(&css, 0, sizeof(struct pkt_classifier));
      snprintf(fname, sizeof(fname), "%s/%s", path, namelist[n]->d_name);
      ret = stat(fname, &st);

      if (ret < 0) Log(LOG_ERR, "ERROR: Unable to stat(): '%s'. Skipped.\n", fname);
      else {
	if (S_ISREG(st.st_mode) && (dot_pat(fname) || dot_so(fname))) {
	  if (x > max) {
	    Log(LOG_DEBUG, "DEBUG: No more room for classifiers.\n");
	    break;
	  }
	  Log(LOG_DEBUG, "DEBUG: reading %s classifier.\n", fname);

	  if (dot_pat(fname)) ret = parse_pattern_file(fname, &css);
          else if (dot_so(fname)) ret = parse_shared_object(fname, &css);
          if (ret) {
            css.id = x+1; /* id are >= 1 */
	    pmct_register(&css);
            x++;
          }
	  else memset(&css, 0, sizeof(struct pkt_classifier));
	}
      }
      free(namelist[n]);
      n++;
    }
    free(namelist);
    Log(LOG_DEBUG, "DEBUG: %d classifiers successfully loaded.\n", x);
  }
  else {
    Log(LOG_ERR, "ERROR: Unable to open: '%s'\n", path);
    exit_gracefully(1); 
  }
}

pm_class_t SF_evaluate_classifiers(char *string)
{
  int j = 0, max = pmct_get_num_entries();

  while (class[j].id && j < max) {
    if ( !strcmp(class[j].protocol, string) ) return class[j].id;
    j++;
  }

  return 0;
}

void evaluate_classifiers(struct packet_ptrs *pptrs, struct ip_flow_common *fp, unsigned int idx)
{
  struct pkt_classifier_data data;
  int plen = (config.snaplen ? config.snaplen : DEFAULT_SNAPLEN);
  unsigned int reverse = idx ? 0 : 1;
  char payload[plen+1];
  int j = 0, ret, cidx;
  int max = pmct_get_num_entries();
  void *cc_node = NULL, *cc_rev_node = NULL, *context = NULL;

  prepare_classifier_data(&data, fp, idx, pptrs);
  if (pptrs->new_flow) {
    init_class_accumulators(pptrs, fp, idx);
    search_conntrack(fp, pptrs, idx); 
  }

  /* Short circuit: a) if we have a class; b) if we have no more
     tentatives to classify the packet. Otherwise continue */
  if (fp->class[idx] || !fp->cst[idx].tentatives) {
    pptrs->class = fp->class[idx];
    handle_class_accumulators(pptrs, fp, idx);

    /* do we have an helper ? If yes, let's run it ! */
    if (fp->conntrack_helper) fp->conntrack_helper(fp->last[idx].tv_sec, pptrs);

    return;
  }

  /* We will pre-process the payload section of the snapshot */
  if (pptrs->payload_ptr) {
    int caplen = ((struct pcap_pkthdr *)pptrs->pkthdr)->caplen - (pptrs->payload_ptr - pptrs->packet_ptr), x = 0, y = 0;
 
    while (x < caplen && y < plen) {
      if (pptrs->payload_ptr[x] != '\0') {
        if (isascii(pptrs->payload_ptr[x])) payload[y] = tolower(pptrs->payload_ptr[x]);
	else payload[y] = pptrs->payload_ptr[x];
	y++;
      }
      x++;
    }
    payload[y] = '\0';

    while (class[j].id && j < max) {
      if (class[j].pattern) ret = pm_regexec(class[j].pattern, payload);
      else if (*class[j].func) {
	cc_node = search_context_chain(fp, idx, class[j].protocol);
	cc_rev_node = search_context_chain(fp, reverse, class[j].protocol);
	context = cc_node;
	ret = (*class[j].func)(&data, caplen, &context, &cc_rev_node, &class[j].extra);
	if (context && !cc_node) insert_context_chain(fp, idx, class[j].protocol, context);
      }

      if (ret) {
        if (ret > 1 && ret < max && class[ret-1].id) cidx = ret-1;
	else cidx = j;

        fp->class[0] = class[cidx].id;
        fp->class[1] = class[cidx].id;
        pptrs->class = class[cidx].id;
	handle_class_accumulators(pptrs, fp, idx);
	if (class[cidx].ct_helper) {
	  fp->conntrack_helper = class[cidx].ct_helper;
	  fp->conntrack_helper(fp->last[idx].tv_sec, pptrs); 
	}
	else fp->conntrack_helper = NULL;
        return;
      }
      j++;
    }
  }

  fp->class[idx] = FALSE;
  pptrs->class = FALSE;
  handle_class_accumulators(pptrs, fp, idx);
}

void init_class_accumulators(struct packet_ptrs *pptrs, struct ip_flow_common *fp, unsigned int idx)
{
  unsigned int reverse = idx ? 0 : 1;
  struct timeval now;

  memset(&pptrs->cst, 0, CSSz);
  memset(&fp->cst[idx], 0, CSSz);
  clear_context_chain(fp, idx);

  fp->cst[idx].tentatives = config.classifier_tentatives;
  fp->class[idx] = FALSE;

  memcpy(&fp->cst[idx].stamp, &fp->last[idx], sizeof(struct timeval));
  /* If the reciprocal of this flow a) is not expired and b) has a class
     then let's inherit it */
  now.tv_sec = fp->last[idx].tv_sec;
  now.tv_usec = 0;
  if (!is_expired_uni(&now, fp, reverse))
    fp->class[idx] = fp->class[reverse];
  else 
    fp->conntrack_helper = NULL; 
}

void handle_class_accumulators(struct packet_ptrs *pptrs, struct ip_flow_common *fp, unsigned int idx)
{
  struct pm_iphdr *iphp = (struct pm_iphdr *)pptrs->iph_ptr; 
  struct ip6_hdr *ip6hp = (struct ip6_hdr *)pptrs->iph_ptr; 

  /* The flow doesn't have a class yet */
  if (!fp->class[idx]) { 
    /* We have more chances to classify the flow */ 
    if (fp->cst[idx].tentatives) {
      memset(&pptrs->cst, 0, CSSz);
      pptrs->cst.tentatives = fp->cst[idx].tentatives; // XXX
      if (pptrs->l3_proto == ETHERTYPE_IP)
	fp->cst[idx].ba += ntohs(iphp->ip_len); 
      else if (pptrs->l3_proto == ETHERTYPE_IPV6)
	fp->cst[idx].ba += (IP6HdrSz+ntohs(ip6hp->ip6_plen));
      if (pptrs->frag_sum_bytes) {
	fp->cst[idx].ba += pptrs->frag_sum_bytes;
	pptrs->frag_sum_bytes = 0;
      }

      if (pptrs->new_flow) fp->cst[idx].fa++;

      if (pptrs->frag_sum_pkts) {
	fp->cst[idx].pa += pptrs->frag_sum_pkts;
	pptrs->frag_sum_pkts = 0;
      }
      fp->cst[idx].pa++;
      if (pptrs->payload_ptr) fp->cst[idx].tentatives--;
    }
    /* We finished tentatives, flow class is unknown */ 
    else {
      memset(&pptrs->cst, 0, CSSz);
      memset(&fp->cst[idx], 0, CSSz);
      clear_context_chain(fp, idx);
    }
  }
  else {
    memcpy(&pptrs->cst, &fp->cst[idx], CSSz);
    memset(&fp->cst[idx], 0, CSSz);
    clear_context_chain(fp, idx);
  } 
}

/* dot_pat(): checks that the supplied fname ends with the '.pat' suffix */
int dot_pat(char *fname)
{
  int len = strlen(fname);

  if (fname[len-4] == '.' && fname[len-3] == 'p' &&
      fname[len-2] == 'a' && fname[len-1] == 't') return 1; 

  return 0;
}

/* dot_so(): checks that the supplied fname ends with the '.so' suffix */
int dot_so(char *fname)
{
  int len = strlen(fname);

  if (fname[len-3] == '.' && fname[len-2] == 's' &&
      fname[len-1] == 'o') return 1;

  return 0;
}

/* l7code */
static int hex2dec(char c)
{
  switch (c) {
  case '0':
  case '1':
  case '2':
  case '3':
  case '4':
  case '5':
  case '6':
  case '7':
  case '8':
  case '9':
    return c - '0';
  case 'a':
  case 'b':
  case 'c':
  case 'd':
  case 'e':
  case 'f':
    return c - 'a' + 10;
  case 'A':
  case 'B':
  case 'C':
  case 'D':
  case 'E':
  case 'F':
    return c - 'A' + 10;
  default:
    Log(LOG_ERR, "hex2dec(): bad value!\n");
    return 0;
  }
}

/* l7code: takes a string with \xHH escapes and returns one with the
   characters they stand for */
static char * pre_process(char * s)
{
  char *result = malloc(strlen(s) + 1);
  int sindex = 0, rindex = 0;

  while( sindex < strlen(s) ) {
    if( sindex + 3 < strlen(s) &&
        s[sindex] == '\\' && s[sindex+1] == 'x' &&
        isxdigit(s[sindex + 2]) && isxdigit(s[sindex + 3]) ) {
      /* carefully remember to call tolower here... */
      result[rindex] = tolower( hex2dec(s[sindex + 2])*16 + hex2dec(s[sindex + 3] ) );
      sindex += 3; /* 4 total */
    }
    else result[rindex] = tolower(s[sindex]);

    sindex++;
    rindex++;
  }
  result[rindex] = '\0';

  return result;
}

/* l7code */
int parse_pattern_file(char *fname, struct pkt_classifier *css)
{
  FILE *f;
  char line[MAX_PATTERN_LEN];
  int linelen = 0;

  enum { protocol, pattern, done } datatype = protocol;

  f = fopen(fname, "r");

  if (!f) return 0;

  while ( fgets(line, MAX_PATTERN_LEN, f) ) {
    linelen = strlen(line);
    if(linelen < 2 || line[0] == '#') continue;

    /* strip the pesky newline... */
    if (line[linelen - 1] == '\n') line[linelen - 1] = '\0';

    if (datatype == protocol) {
      if (linelen >= MAX_PROTOCOL_LEN) {
        Log(LOG_ERR, "ERROR: Protocol name in %s too long. A maximum of %d chars is allowed.\n", fname, MAX_PROTOCOL_LEN);
	return 0;
      }

      strncpy(css->protocol, line, MAX_PROTOCOL_LEN);
      datatype = pattern;
    }
    else if (datatype == pattern) {
      if (linelen >= MAX_PATTERN_LEN) {
        Log(LOG_ERR, "ERROR: Pattern in %s too long. A maximum of %d chars is allowed.\n", fname, MAX_PATTERN_LEN);
	return 0;
      }
      css->pattern = pm_regcomp(pre_process(line), &linelen);
      if (!css->pattern) {
	Log(LOG_ERR, "ERROR: Failed compiling regular expression for protocol '%s'\n", css->protocol);
	return 0;
      } 

      datatype = done;
      break;
    }
    else {
      Log(LOG_ERR, "ERROR: parse_pattern_file(): internal error\n");
      return 0;
    }
  }

  if (datatype != done) {
    Log(LOG_ERR, "ERROR: Failed to get all needed data from %s\n", fname);
    return 0;
  }

  fclose(f);

  link_conntrack_helper(css);

  css->func = NULL;
  return 1;
}

int parse_shared_object(char *fname, struct pkt_classifier *css)
{
#if defined HAVE_DLOPEN
  int ret, (*init)(void **) = NULL;
  char *proto, *err, *type;
  void *handler;

  dlerror();
  handler = dlopen(fname, RTLD_NOW);
  if (!handler) {
    Log(LOG_ERR, "ERROR: Failed loading classifier from %s (%s)\n", fname, dlerror()); 
    return 0; 
  }

  type = dlsym(handler, "type");
  if (!type || strncmp(type, "classifier", 10)) {
    dlclose(handler);
    return 0;
  }

  proto = dlsym(handler, "protocol");
  if (!proto) {
    Log(LOG_ERR, "ERROR: Unable to find protocol descriptor in %s\n", fname); 
    dlclose(handler);
    return 0;
  }

  if (strlen(proto) >= MAX_PROTOCOL_LEN) {
    Log(LOG_ERR, "ERROR: Protocol name in %s too long. A maximum of %d chars is allowed.\n", fname, MAX_PROTOCOL_LEN);
    dlclose(handler);
    return 0;
  }

  strncpy(css->protocol, proto, MAX_PROTOCOL_LEN);

  *(void **) (&init) = dlsym(handler, "init");
  if (*init) {
    ret = (*init)(&css->extra);
    if (!ret) {
      Log(LOG_ERR, "ERROR: Failed initialization of classifier from %s\n", fname);
      dlclose(handler);
      return 0;
    }
  }

  dlerror();
  *(void **) (&css->func) = dlsym(handler, "classifier");
  if ((err = dlerror())) {
    Log(LOG_ERR, "ERROR: Unable to load classifier routine from %s (%s)\n", fname, err);
    dlclose(handler);
    return 0;
  }

  link_conntrack_helper(css);
  css->pattern = NULL;
  return 1;
#else
  return 0;
#endif
}

void link_conntrack_helper(struct pkt_classifier *css)
{
  int index = 0;

  while (strcmp(conntrack_helper_list[index].protocol, "")) {
    if (!strcmp(css->protocol, conntrack_helper_list[index].protocol)) {
      css->ct_helper = conntrack_helper_list[index].ct_helper;
      break;
    }

    index++;
  }
}

void *search_context_chain(struct ip_flow_common *fp, unsigned int idx, char *proto)
{
  struct context_chain *chain = fp->cc[idx]; 

  if (!chain) return NULL;

  while (chain->protocol) {
    if (!strncmp(chain->protocol, proto, MAX_PROTOCOL_LEN)) return chain->data; 
    else {
      if (chain->next) chain = chain->next;
      else return NULL;
    }
  }

  return NULL;
}

void insert_context_chain(struct ip_flow_common *fp, unsigned int idx, char *proto, void *context)
{
  struct context_chain *chain = fp->cc[idx];

  while (chain) {
    if (chain->next) chain = chain->next;
    else break;
  }

  if (!fp->cc[idx]) {
    fp->cc[idx] = malloc(sizeof(struct context_chain));
    if (!fp->cc[idx]) return;
    chain = fp->cc[idx];
  }
  else {
    chain->next = malloc(sizeof(struct context_chain));
    if (!chain->next) return;
    chain = chain->next;
  }

  chain->protocol = proto;
  chain->data = context;
  chain->next = NULL; 
}

void clear_context_chain(struct ip_flow_common *fp, unsigned int idx)
{
  struct context_chain *chain = fp->cc[idx], *aux;

  while (chain) {
    if (chain->next) {
      aux = chain;
      chain = chain->next;
      free(aux->data);
      free(aux);
    }
    else {
      free(chain->data);
      free(chain);
      break;
    }
  }

  fp->cc[idx] = NULL;
}

void prepare_classifier_data(struct pkt_classifier_data *data,
				struct ip_flow_common *fp,
				unsigned int idx,
				struct packet_ptrs *pptrs)
{
  data->stamp.tv_sec = fp->cst[idx].stamp.tv_sec;
  data->stamp.tv_usec = fp->cst[idx].stamp.tv_usec;
  data->packet_ptr = pptrs->packet_ptr;
  data->l3_ptr = pptrs->iph_ptr;
  data->l4_ptr = pptrs->tlh_ptr;
  data->payload_ptr = pptrs->payload_ptr;
  data->l3_proto = pptrs->l3_proto;
  data->l4_proto = pptrs->l4_proto;
  data->plen = ((struct pcap_pkthdr *)pptrs->pkthdr)->len - (pptrs->payload_ptr - pptrs->packet_ptr); 
  data->tentatives = fp->cst[idx].tentatives;
  data->sampling_rate = 1;
}

/* pmct library function set follows: PMacct Classifier Table.
   Unique assumption is the global "class" Classifier Table */
pm_class_t pmct_register(struct pkt_classifier *css)
{
  int max = pmct_get_num_entries();

  if (!css || !css->id) return 0;

  /* let's check that a) a valid class ID has been supplied, b) the class ID
     is still available. If this is the case, let's proceed with this entry,
     otherwise we will switch to a default behaviour. */ 

  if (!strcmp(css->protocol, "")) return 0; 

  if (css->id && css->id <= max && !class[css->id-1].id) {
    memcpy(&class[css->id-1], css, sizeof(struct pkt_classifier));
    return css->id;
  } 
  else return 0;
}

/* same as pmct_register but without the index decrement */
pm_class_t pmct_ndpi_register(struct pkt_classifier *css)
{
  int max = pmct_get_num_entries();

  if (!css || !css->id) return 0;

  /* let's check that a) a valid class ID has been supplied, b) the class ID
     is still available. If this is the case, let's proceed with this entry,
     otherwise we will switch to a default behaviour. */

  if (!strcmp(css->protocol, "")) return 0;

  if (css->id <= max && !class[css->id-1].id) {
    memcpy(&class[css->id-1], css, sizeof(struct pkt_classifier));
    return css->id;
  }
  else return 0;
}

void pmct_unregister(pm_class_t id)
{
  int max = pmct_get_num_entries();

  if (id && id <= max && class[id-1].id)
    memset(&class[id-1], 0, sizeof(struct pkt_classifier)); 
}

pm_class_t pmct_find_first_free()
{
  int ret, idx = 0, num = pmct_get_num_entries(); 

  while (idx < num) {
    ret = pmct_isfree(idx+1);
    if (ret > 0) return idx+1;
    else if (ret < 0) return 0;
    idx++;
  }

  if (num && idx == num) {
    if (!log_notification_isset(&log_notifications.max_classifiers, FALSE)) {
      Log(LOG_WARNING, "WARN ( %s/%s ): Finished elements in class table (%u). Raise via classifier_table_num.\n", config.name, config.type, num);
      log_notification_set(&log_notifications.max_classifiers, FALSE, FALSE);
    }
  }

  return 0;
}

pm_class_t pmct_find_last_free()
{
  int ret, idx = pmct_get_num_entries(); 

  idx--;
  while (idx) {
    ret = pmct_isfree(idx+1);
    if (ret > 0) return idx+1;
    else if (ret < 0) return 0;
    idx--;
  }

  return 0;
}

int pmct_isfree(pm_class_t id)
{
  int max = pmct_get_num_entries();

  if (!class) return -1;

  if (id && id <= max) {
    if (!class[id-1].id) return 1;
    else return 0;
  }
  else return -1;
}

int pmct_get(pm_class_t id, struct pkt_classifier *css)
{
  int max = pmct_get_num_entries();

  if (!css) return 0;

  if (id && id <= max && class[id-1].id) {
    memcpy(css, &class[id-1], sizeof(struct pkt_classifier)); 
    return 1;
  }
  else { 
    memset(css, 0, sizeof(struct pkt_classifier)); 
    return 1;
  }
}

int pmct_get_num_entries()
{
  if (config.classifier_table_num) return config.classifier_table_num;
  else return MAX_CLASSIFIERS;
}

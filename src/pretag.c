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

/* defines */
#define __PRETAG_C

/* includes */
#include "pmacct.h"
#include "nfacctd.h"
#include "pretag_handlers.h"
#include "pretag-data.h"
#include "tee_plugin/tee_recvs.h"
#include "tee_plugin/tee_recvs-data.h"
#include "isis/isis.h"
#include "isis/isis-data.h"

/*
   XXX: load_id_file() interface cleanup pending:
   - if a table is tag-related then it is passed as argument t
   - else it is passed as argument req->key_value_table 
*/
void load_id_file(int acct_type, char *filename, struct id_table *t, struct plugin_requests *req, int *map_allocated)
{
  struct id_table tmp;
  struct id_entry *ptr, *ptr2;
  FILE *file;
  char buf[LARGEBUFLEN];
  int v4_num = 0, x, tot_lines = 0, err, index, label_solved, sz;
  int ignoring, read_len;
  struct stat st;

#if defined ENABLE_IPV6
  int v6_num = 0;
#endif

  if (!map_allocated) return;

  /* parsing engine vars */
  char *start, *key = NULL, *value = NULL;
  int len;

  Log(LOG_INFO, "INFO ( %s/%s ): Trying to (re)load map: %s\n", config.name, config.type, filename);

  memset(&st, 0, sizeof(st));
  memset(&tmp, 0, sizeof(struct id_table));

  if (!config.pre_tag_map_entries) config.pre_tag_map_entries = MAX_PRETAG_MAP_ENTRIES;

  if (filename) {
    if ((file = fopen(filename, "r")) == NULL) {
      Log(LOG_ERR, "ERROR ( %s/%s ): map '%s' not found.\n", config.name, config.type, filename);
      goto handle_error;
    }

    sz = sizeof(struct id_entry)*config.pre_tag_map_entries;

    if (t) {
      if (*map_allocated == 0) {
        memset(t, 0, sizeof(struct id_table));
        t->e = (struct id_entry *) malloc(sz);
        *map_allocated = TRUE;
      }
      else {
        ptr = t->e ;
        memset(t, 0, sizeof(struct id_table));
        t->e = ptr ;
      }
    }
    else {
      *map_allocated = TRUE;
    }

    tmp.e = (struct id_entry *) malloc(sz);

    memset(tmp.e, 0, sz);
    if (t) memset(t->e, 0, sz);

    if (acct_type == MAP_IGP) {
      igp_daemon_map_initialize(filename, req);
      read_len = LARGEBUFLEN;
    }
    else read_len = SRVBUFLEN;

    /* first stage: reading Agent ID file and arranging it in a temporary memory table */
    while (!feof(file)) {
      ignoring = FALSE;
      req->line_num = ++tot_lines;

      if (tmp.num >= config.pre_tag_map_entries) {
	Log(LOG_WARNING, "WARN ( %s/%s ): map '%s' cut to the first %u entries. Number of entries can be configured via 'pre_tag_map_etries'.\n",
		config.name, config.type, filename, config.pre_tag_map_entries);
	break;
      }
      memset(buf, 0, read_len);
      if (fgets(buf, read_len, file)) {
        if (!iscomment(buf) && !isblankline(buf)) {
	  if (strlen(buf) == (read_len-1) && !strchr(buf, '\n')) {
	    Log(LOG_WARNING, "WARN ( %s/%s ): line too long (max %u chars). Line %d in map '%s' ignored.\n",
			config.name, config.type, read_len, tot_lines, filename);
	    continue;
	  }
          if (!check_not_valid_char(filename, buf, '|')) {
            mark_columns(buf);
            trim_all_spaces(buf);
	    strip_quotes(buf);

	    /* resetting the entry and enforcing defaults */
	    if (acct_type == MAP_IGP) memset(&ime, 0, sizeof(ime));
            memset(&tmp.e[tmp.num], 0, sizeof(struct id_entry));
	    tmp.e[tmp.num].ret = FALSE;

            err = FALSE; key = NULL; value = NULL;
            start = buf;
            len = strlen(buf);

            for (x = 0; x <= len; x++) {
              if (buf[x] == '=') {
                if (start == &buf[x]) continue;
                if (!key) {
                  buf[x] = '\0';
		  key = start;
                  x++;
                  start = &buf[x];
		}
              }
              if ((buf[x] == '|') || (buf[x] == '\0')) {
                if (start == &buf[x]) continue;
                buf[x] = '\0';
                if (value || !key) {
                  Log(LOG_ERR, "ERROR ( %s/%s ): malformed line %d in map '%s'. Ignored.\n", config.name, config.type, tot_lines, filename);
                  err = TRUE;
                  break;
                }
                else value = start;
                x++;
                start = &buf[x];
              }

              if (key && value) {
                int dindex; /* dictionary index */

		/* Processing of source BGP-related primitives kept consistent;
		   This can indeed be split as required in future */
		if (acct_type == MAP_BGP_PEER_AS_SRC || acct_type == MAP_BGP_SRC_LOCAL_PREF ||
		    acct_type == MAP_BGP_SRC_MED) {
                  for (dindex = 0; strcmp(bpas_map_dictionary[dindex].key, ""); dindex++) {
                    if (!strcmp(bpas_map_dictionary[dindex].key, key)) {
                      err = (*bpas_map_dictionary[dindex].func)(filename, &tmp.e[tmp.num], value, req, acct_type);
                      break;
                    }
                    else err = E_NOTFOUND; /* key not found */
                  }
                  if (err) {
                    if (err == E_NOTFOUND) Log(LOG_ERR, "ERROR ( %s/%s ): unknown key '%s' at line %d in map '%s'. Ignored.\n",
						config.name, config.type, key, tot_lines, filename);
                    else Log(LOG_ERR, "Line %d ignored.\n", tot_lines);
                    break;
                  }
                  key = NULL; value = NULL;
		}
		else if (acct_type == MAP_BGP_TO_XFLOW_AGENT) {
                  for (dindex = 0; strcmp(bta_map_dictionary[dindex].key, ""); dindex++) {
                    if (!strcmp(bta_map_dictionary[dindex].key, key)) {
                      err = (*bta_map_dictionary[dindex].func)(filename, &tmp.e[tmp.num], value, req, acct_type);
                      break;
                    }
                    else err = E_NOTFOUND; /* key not found */
                  }
                  if (err) {
                    if (err == E_NOTFOUND) Log(LOG_ERR, "ERROR ( %s/%s ): unknown key '%s' at line %d in map '%s'. Ignored.\n", 
						config.name, config.type, key, tot_lines, filename);
                    else Log(LOG_ERR, "Line %d ignored.\n", tot_lines);
                    break;
                  }
                  key = NULL; value = NULL;
		}
                else if (acct_type == MAP_BGP_IFACE_TO_RD) {
                  for (dindex = 0; strcmp(bitr_map_dictionary[dindex].key, ""); dindex++) {
                    if (!strcmp(bitr_map_dictionary[dindex].key, key)) {
                      err = (*bitr_map_dictionary[dindex].func)(filename, &tmp.e[tmp.num], value, req, acct_type);
                      break;
                    }
                    else err = E_NOTFOUND; /* key not found */
                  }
                  if (err) {
                    if (err == E_NOTFOUND) Log(LOG_ERR, "ERROR ( %s/%s ): unknown key '%s' at line %d in map '%s'. Ignored.\n", 
						config.name, config.type, key, tot_lines, filename);
                    else Log(LOG_ERR, "Line %d ignored.\n", tot_lines);
                    break;
                  }
                  key = NULL; value = NULL;
                }
		else if (acct_type == MAP_SAMPLING) {
                  for (dindex = 0; strcmp(sampling_map_dictionary[dindex].key, ""); dindex++) {
                    if (!strcmp(sampling_map_dictionary[dindex].key, key)) {
                      err = (*sampling_map_dictionary[dindex].func)(filename, &tmp.e[tmp.num], value, req, acct_type);
                      break;
                    }
                    else err = E_NOTFOUND; /* key not found */
                  }
                  if (err) {
                    if (err == E_NOTFOUND) Log(LOG_ERR, "ERROR ( %s/%s ): unknown key '%s' at line %d in map '%s'. Ignored.\n", 
						config.name, config.type, key, tot_lines, filename);
                    else Log(LOG_ERR, "Line %d ignored.\n", tot_lines);
                    break;
                  }
                  key = NULL; value = NULL;
		}
		else if (acct_type == MAP_TEE_RECVS) {
                  for (dindex = 0; strcmp(tee_recvs_map_dictionary[dindex].key, ""); dindex++) {
                    if (!strcmp(tee_recvs_map_dictionary[dindex].key, key)) {
                      err = (*tee_recvs_map_dictionary[dindex].func)(filename, NULL, value, req, acct_type);
                      break;
                    }
                    else err = E_NOTFOUND; /* key not found */
                  }
                  if (err) {
                    if (err == E_NOTFOUND) Log(LOG_ERR, "ERROR ( %s/%s ): unknown key '%s' at line %d in map '%s'. Ignored.\n", 
						config.name, config.type, key, tot_lines, filename);
                    else Log(LOG_ERR, "Line %d ignored in map '%s'.\n", tot_lines, filename);
                    break;
                  }
                  key = NULL; value = NULL;
		}
                else if (acct_type == MAP_IGP) {
                  for (dindex = 0; strcmp(igp_daemon_map_dictionary[dindex].key, ""); dindex++) {
                    if (!strcmp(igp_daemon_map_dictionary[dindex].key, key)) {
                      err = (*igp_daemon_map_dictionary[dindex].func)(filename, NULL, value, req, acct_type);
                      break;
                    }
                    else err = E_NOTFOUND; /* key not found */
                  }
                  if (err) {
                    if (err == E_NOTFOUND) Log(LOG_ERR, "ERROR ( %s/%s ): unknown key '%s' at line %d in map '%s'. Ignored.\n",
                                                config.name, config.type, key, tot_lines, filename);
                    else {
		      Log(LOG_ERR, "Line %d ignored in map '%s'.\n", tot_lines, filename);
		      ignoring = TRUE;
		    }
                  }
                  key = NULL; value = NULL;
                }
		else {
		  if (tee_plugins) {
                    for (dindex = 0; strcmp(tag_map_tee_dictionary[dindex].key, ""); dindex++) {
                      if (!strcmp(tag_map_tee_dictionary[dindex].key, key)) {
                        err = (*tag_map_tee_dictionary[dindex].func)(filename, &tmp.e[tmp.num], value, req, acct_type);
                        break;
                      }
                      else err = E_NOTFOUND; /* key not found */
                    }
		  }
		  else {
                    for (dindex = 0; strcmp(tag_map_dictionary[dindex].key, ""); dindex++) {
                      if (!strcmp(tag_map_dictionary[dindex].key, key)) {
                        err = (*tag_map_dictionary[dindex].func)(filename, &tmp.e[tmp.num], value, req, acct_type);
                        break;
                      }
                      else err = E_NOTFOUND; /* key not found */
		    }
		  }
                  if (err) {
                    if (err == E_NOTFOUND) Log(LOG_ERR, "ERROR ( %s/%s ): unknown key '%s' at line %d in map '%s'. Ignored.\n", 
						config.name, config.type, key, tot_lines, filename);
                    else Log(LOG_ERR, "Line %d ignored in map '%s'.\n", tot_lines, filename);
                    break; 
                  }
                  key = NULL; value = NULL;
		}
              }
            }
	    if (!ignoring) {
              /* verifying errors and required fields */
	      if (acct_type == ACCT_NF || acct_type == ACCT_SF) {
	        if (tmp.e[tmp.num].id && tmp.e[tmp.num].id2) 
		   Log(LOG_ERR, "ERROR ( %s/%s ): set_tag (id) and set_tag2 (id2) are mutual exclusive at line %d in map '%s'.\n", 
			config.name, config.type, tot_lines, filename);
                else if (!err && tmp.e[tmp.num].agent_ip.a.family) {
                  int j, z;

                  for (j = 0; tmp.e[tmp.num].func[j]; j++);
		  for (z = 0; tmp.e[tmp.num].set_func[z]; z++, j++) {
		    tmp.e[tmp.num].func[j] = tmp.e[tmp.num].set_func[z];
		    tmp.e[tmp.num].func_type[j] = tmp.e[tmp.num].set_func_type[z];
		  }

	          if (tmp.e[tmp.num].agent_ip.a.family == AF_INET) v4_num++;
#if defined ENABLE_IPV6
	          else if (tmp.e[tmp.num].agent_ip.a.family == AF_INET6) v6_num++;
#endif
                  tmp.num++;
                }
	        /* if any required field is missing and other errors have been signalled
	           before we will trap an error message */
	        else if (!err && !tmp.e[tmp.num].agent_ip.a.family)
	          Log(LOG_ERR, "ERROR ( %s/%s ): required key missing at line %d in map '%s'. Required key is: 'ip'.\n",
			config.name, config.type, tot_lines, filename); 
	      }
	      else if (acct_type == ACCT_PM) {
	        if (tmp.e[tmp.num].id && tmp.e[tmp.num].id2)
                   Log(LOG_ERR, "ERROR ( %s/%s ): set_tag (id) and set_tag2 (id2) are mutual exclusive at line %d in map '%s'.\n", 
			config.name, config.type, tot_lines, filename);
	        else if (tmp.e[tmp.num].agent_ip.a.family)
		  Log(LOG_ERR, "ERROR ( %s/%s ): key 'ip' not applicable here. Invalid line %d in map '%s'.\n",
			config.name, config.type, tot_lines, filename);
	        else if (!err) {
                  int j, z;

		  for (j = 0; tmp.e[tmp.num].func[j]; j++);
		  for (z = 0; tmp.e[tmp.num].set_func[z]; z++, j++) {
		    tmp.e[tmp.num].func[j] = tmp.e[tmp.num].set_func[z];
		    tmp.e[tmp.num].func_type[j] = tmp.e[tmp.num].set_func_type[z];
		  }
		  tmp.e[tmp.num].agent_ip.a.family = AF_INET; /* we emulate a dummy '0.0.0.0' IPv4 address */
		  v4_num++; tmp.num++;
	        }
	      }
	      else if (acct_type == MAP_BGP_PEER_AS_SRC || acct_type == MAP_BGP_SRC_LOCAL_PREF ||
	  	       acct_type == MAP_BGP_SRC_MED) {
                if (!err && (tmp.e[tmp.num].id || tmp.e[tmp.num].flags) && tmp.e[tmp.num].agent_ip.a.family) {
                  int j;

                  for (j = 0; tmp.e[tmp.num].func[j]; j++);
                  tmp.e[tmp.num].func[j] = pretag_id_handler;
                  if (tmp.e[tmp.num].agent_ip.a.family == AF_INET) v4_num++;
#if defined ENABLE_IPV6
                  else if (tmp.e[tmp.num].agent_ip.a.family == AF_INET6) v6_num++;
#endif
                  tmp.num++;
                }
                else if ((!tmp.e[tmp.num].id || !tmp.e[tmp.num].agent_ip.a.family) && !err)
                  Log(LOG_ERR, "ERROR ( %s/%s ): required key missing at line %d in map '%s'. Required keys are: 'id', 'ip'.\n", 
			config.name, config.type, tot_lines, filename);
	      }
              else if (acct_type == MAP_BGP_TO_XFLOW_AGENT) {
                if (!err && tmp.e[tmp.num].id && tmp.e[tmp.num].agent_ip.a.family) {
                  int j;

                  for (j = 0; tmp.e[tmp.num].func[j]; j++);
                  tmp.e[tmp.num].func[j] = pretag_id_handler;
                  if (tmp.e[tmp.num].agent_ip.a.family == AF_INET) v4_num++;
#if defined ENABLE_IPV6
                  else if (tmp.e[tmp.num].agent_ip.a.family == AF_INET6) v6_num++;
#endif
                  tmp.num++;
                }
                else if ((!tmp.e[tmp.num].id || !tmp.e[tmp.num].agent_ip.a.family) && !err)
                  Log(LOG_ERR, "ERROR ( %s/%s ): required key missing at line %d in map '%s'. Required keys are: 'id', 'ip'.\n",
			config.name, config.type, filename, tot_lines, filename);
              }
              else if (acct_type == MAP_BGP_IFACE_TO_RD) {
                if (!err && tmp.e[tmp.num].id && tmp.e[tmp.num].agent_ip.a.family) {
                  int j;

                  for (j = 0; tmp.e[tmp.num].func[j]; j++);
                  tmp.e[tmp.num].func[j] = pretag_id_handler;
                  if (tmp.e[tmp.num].agent_ip.a.family == AF_INET) v4_num++;
#if defined ENABLE_IPV6
                  else if (tmp.e[tmp.num].agent_ip.a.family == AF_INET6) v6_num++;
#endif
                  tmp.num++;
                }
	      }
              else if (acct_type == MAP_SAMPLING) {
                if (!err && tmp.e[tmp.num].id && tmp.e[tmp.num].agent_ip.a.family) {
                  int j;

                  for (j = 0; tmp.e[tmp.num].func[j]; j++);
                  tmp.e[tmp.num].func[j] = pretag_id_handler;
                  if (tmp.e[tmp.num].agent_ip.a.family == AF_INET) v4_num++;
#if defined ENABLE_IPV6
                  else if (tmp.e[tmp.num].agent_ip.a.family == AF_INET6) v6_num++;
#endif
                  tmp.num++;
                }
                else if ((!tmp.e[tmp.num].id || !tmp.e[tmp.num].agent_ip.a.family) && !err)
                  Log(LOG_ERR, "ERROR ( %s/%s ): required key missing at line %d in map '%s'. Required keys are: 'id', 'ip'.\n",
			config.name, config.type, tot_lines, filename);
              }
	      else if (acct_type == MAP_TEE_RECVS) tee_recvs_map_validate(filename, req); 
	      else if (acct_type == MAP_IGP) igp_daemon_map_validate(filename, req); 
	    }
          }
          else Log(LOG_ERR, "ERROR ( %s/%s ): malformed line %d in map '%s'. Ignored.\n",
			config.name, config.type, tot_lines, filename);
        }
      }
    }
    fclose(file);

    if (acct_type == MAP_IGP) igp_daemon_map_finalize(filename, req);

    if (t) {
      stat(filename, &st);
      t->timestamp = st.st_mtime;

      /* second stage: segregating IPv4, IPv6. No further reordering
         in order to deal smoothly with jumps (ie. JEQs) */

      x = 0;
      t->num = tmp.num;
      t->ipv4_num = v4_num; 
      t->ipv4_base = &t->e[x];
      for (index = 0; index < tmp.num; index++) {
        if (tmp.e[index].agent_ip.a.family == AF_INET) { 
          memcpy(&t->e[x], &tmp.e[index], sizeof(struct id_entry));
	  t->e[x].pos = x;
	  x++;
        }
      }
#if defined ENABLE_IPV6
      t->ipv6_num = v6_num;
      t->ipv6_base = &t->e[x];
      for (index = 0; index < tmp.num; index++) {
        if (tmp.e[index].agent_ip.a.family == AF_INET6) {
          memcpy(&t->e[x], &tmp.e[index], sizeof(struct id_entry));
	  t->e[x].pos = x;
          x++;
        }
      }
#endif

      /* third stage: building short circuits basing on jumps and labels. Only
         forward references are solved. Backward and unsolved references will
         generate errors. */
      for (ptr = t->ipv4_base, x = 0; x < t->ipv4_num; ptr++, x++) {
        if (ptr->jeq.label) {
	  label_solved = FALSE;

	  /* honouring reserved labels (ie. "next"). Then resolving unknown labels */
	  if (!strcmp(ptr->jeq.label, "next")) {
	    ptr->jeq.ptr = ptr+1;
	    label_solved = TRUE;
	  }
	  else {
	    for (ptr2 = ptr+1, index = x+1; index < t->ipv4_num; ptr2++, index++) {
	      if (!strcmp(ptr->jeq.label, ptr2->label)) {
	        ptr->jeq.ptr = ptr2;
	        label_solved = TRUE;
	      }
	    }
	  }
	  if (!label_solved) {
	    ptr->jeq.ptr = NULL;
	    Log(LOG_ERR, "ERROR ( %s/%s ): Unresolved label '%s' in map '%s'. Ignoring it.\n",
			config.name, config.type, ptr->jeq.label, filename);
	  }
	  free(ptr->jeq.label);
	  ptr->jeq.label = NULL;
        }
      }

#if defined ENABLE_IPV6
      for (ptr = t->ipv6_base, x = 0; x < t->ipv6_num; ptr++, x++) {
        if (ptr->jeq.label) {
          label_solved = FALSE;
          for (ptr2 = ptr+1, index = x+1; index < t->ipv6_num; ptr2++, index++) {
            if (!strcmp(ptr->jeq.label, ptr2->label)) {
              ptr->jeq.ptr = ptr2;
              label_solved = TRUE;
            }
          }
          if (!label_solved) {
            ptr->jeq.ptr = NULL;
            Log(LOG_ERR, "ERROR ( %s/%s ): Unresolved label '%s' in map '%s'. Ignoring it.\n",
			config.name, config.type, ptr->jeq.label, filename);
          }
          free(ptr->jeq.label);
          ptr->jeq.label = NULL;
        }
      }
#endif
    }
  }

  if (tmp.e) free(tmp.e) ;
  Log(LOG_INFO, "INFO ( %s/%s ): map '%s' successfully (re)loaded.\n", config.name, config.type, filename);

  return;

  handle_error:
  if (*map_allocated && tmp.e) free(tmp.e) ;
  if (t && t->timestamp) {
    Log(LOG_WARNING, "WARN ( %s/%s ): Rolling back the old map '%s'.\n", config.name, config.type, filename);

    /* we update the timestamp to avoid loops */
    stat(filename, &st);
    t->timestamp = st.st_mtime;
  }
  else exit_all(1);
}

u_int8_t pt_check_neg(char **value)
{
  if (**value == '-') {
    (*value)++;
    return TRUE;
  }
  else return FALSE;
}

char *pt_check_range(char *str)
{
  char *ptr;

  if (ptr = strchr(str, '-')) {
    *ptr = '\0';
    ptr++;
    return ptr;
  }
  else return NULL;
}

void pretag_init_vars(struct packet_ptrs *pptrs)
{
  memset(&pptrs->set_tos, 0, sizeof(s_uint8_t));
}

/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2016 by Paolo Lucente
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
#include "crc32.h"

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
  char *buf = NULL;
  int v4_num = 0, x, tot_lines = 0, err, index, label_solved, sz;
  int ignoring, map_entries, map_row_len;
  struct stat st;

#if defined ENABLE_IPV6
  int v6_num = 0;
#endif

  if (!map_allocated) return;

  if (acct_type == ACCT_NF || acct_type == ACCT_SF || acct_type == ACCT_PM ||
      acct_type == MAP_BGP_PEER_AS_SRC || acct_type == MAP_BGP_TO_XFLOW_AGENT ||
      acct_type == MAP_BGP_SRC_LOCAL_PREF || acct_type == MAP_BGP_SRC_MED ||
      acct_type == MAP_FLOW_TO_RD || acct_type == MAP_SAMPLING) {
    req->key_value_table = (void *) &tmp;
  }

  /* parsing engine vars */
  char *start, *key = NULL, *value = NULL;
  int len;

  Log(LOG_INFO, "INFO ( %s/%s ): [%s] (re)loading map.\n", config.name, config.type, filename);

  memset(&st, 0, sizeof(st));
  memset(&tmp, 0, sizeof(struct id_table));

  if (req->map_entries) map_entries = req->map_entries;
  else if (config.maps_entries) map_entries = config.maps_entries;
  else map_entries = MAX_PRETAG_MAP_ENTRIES;

  if (req->map_row_len) map_row_len = req->map_row_len;
  else if (config.maps_row_len) map_row_len = config.maps_row_len;
  else {
    if (acct_type == MAP_IGP) map_row_len = LARGEBUFLEN;
    else map_row_len = SRVBUFLEN;
  }

  buf = (char *) malloc(map_row_len);
  if (!buf) {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] malloc() failed (readbuf: %u chars).\n", config.name, config.type, filename, map_row_len);
    goto handle_error;
  }
  memset(buf, 0, map_row_len);

  if (filename) {
    if ((file = fopen(filename, "r")) == NULL) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] file not found.\n", config.name, config.type, filename);
      goto handle_error;
    }

    sz = sizeof(struct id_entry)*map_entries;

    if (t) {
      if (*map_allocated == 0) {
        memset(t, 0, sizeof(struct id_table));
        t->e = (struct id_entry *) malloc(sz);
	if (!t->e) {
	  Log(LOG_ERR, "ERROR ( %s/%s ): [%s] malloc() failed.\n", config.name, config.type, filename);
	  goto handle_error;
	}
        *map_allocated = TRUE;
      }
      else {
        ptr = t->e ;

	/* freeing up resources before memset() */
        if (config.maps_index && pretag_index_have_one(t)) {
	  pretag_index_destroy(t);
	}
	for (index = 0; index < t->num; index++) {
	  pcap_freecode(&t->e[index].key.filter);
	  pretag_free_label(&t->e[index].label);
	}

        memset(t, 0, sizeof(struct id_table));
        t->e = ptr ;
      }
    }
    else {
      *map_allocated = TRUE;
    }

    tmp.e = (struct id_entry *) malloc(sz);
    if (!tmp.e) {
      Log(LOG_ERR, "ERROR ( %s/%s ): [%s] malloc() failed.\n", config.name, config.type, filename);
      goto handle_error;
    }

    memset(tmp.e, 0, sz);
    if (t) memset(t->e, 0, sz);

    if (acct_type == MAP_IGP) igp_daemon_map_initialize(filename, req);
    if (acct_type == MAP_CUSTOM_PRIMITIVES) custom_primitives_map_initialize();

    /* first stage: reading Agent ID file and arranging it in a temporary memory table */
    while (!feof(file)) {
      ignoring = FALSE;
      req->line_num = ++tot_lines;

      if (tmp.num >= map_entries) {
	Log(LOG_WARNING, "WARN ( %s/%s ): [%s] file cut to the first %u entries. Number of entries can be configured via 'maps_entries'.\n",
		config.name, config.type, filename, map_entries);
	break;
      }
      memset(buf, 0, map_row_len);
      if (fgets(buf, map_row_len, file)) {
        if (!iscomment(buf) && !isblankline(buf)) {
	  if (strlen(buf) == (map_row_len-1) && !strchr(buf, '\n')) {
	    Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] line too long (max %u chars). Ignored.\n",
			config.name, config.type, filename, tot_lines, map_row_len);
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
                  Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] malformed line. Ignored.\n", config.name, config.type, filename, tot_lines);
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
                    if (err == E_NOTFOUND) Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] unknown key '%s'. Ignored.\n",
						config.name, config.type, filename, tot_lines, key);
                    else Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] Line ignored.\n", config.name, config.type, filename, tot_lines);
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
                    if (err == E_NOTFOUND) Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] unknown key '%s'. Ignored.\n", 
						config.name, config.type, filename, tot_lines, key);
                    else Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] Line ignored.\n", config.name, config.type, filename, tot_lines);
                    break;
                  }
                  key = NULL; value = NULL;
		}
                else if (acct_type == MAP_FLOW_TO_RD) {
                  for (dindex = 0; strcmp(bitr_map_dictionary[dindex].key, ""); dindex++) {
                    if (!strcmp(bitr_map_dictionary[dindex].key, key)) {
                      err = (*bitr_map_dictionary[dindex].func)(filename, &tmp.e[tmp.num], value, req, acct_type);
                      break;
                    }
                    else err = E_NOTFOUND; /* key not found */
                  }
                  if (err) {
                    if (err == E_NOTFOUND) Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] unknown key '%s'. Ignored.\n", 
						config.name, config.type, filename, tot_lines, filename, key);
                    else Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] Line ignored.\n", config.name, config.type, filename, tot_lines);
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
                    if (err == E_NOTFOUND) Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] unknown key '%s'. Ignored.\n", 
						config.name, config.type, filename, tot_lines, key);
                    else Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] Line ignored.\n", config.name, config.type, filename, tot_lines);
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
                    if (err == E_NOTFOUND) Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] unknown key '%s'. Ignored.\n", 
						config.name, config.type, filename, tot_lines, key);
                    else Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] Line ignored.\n", config.name, config.type, filename, tot_lines);
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
                    if (err == E_NOTFOUND) Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] unknown key '%s'. Ignored.\n",
                                                config.name, config.type, filename, tot_lines, key);
                    else {
		      Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] Line ignored.\n", config.name, config.type, filename, tot_lines);
		      ignoring = TRUE;
		    }
                  }
                  key = NULL; value = NULL;
                }
                else if (acct_type == MAP_CUSTOM_PRIMITIVES) {
                  for (dindex = 0; strcmp(custom_primitives_map_dictionary[dindex].key, ""); dindex++) {
                    if (!strcmp(custom_primitives_map_dictionary[dindex].key, key)) {
                      err = (*custom_primitives_map_dictionary[dindex].func)(filename, &tmp.e[tmp.num], value, req, acct_type);
                      break;
                    }
                    else err = E_NOTFOUND; /* key not found */
                  }
                  if (err) {
                    if (err == E_NOTFOUND) Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] unknown key '%s'. Ignored.\n",
                                                config.name, config.type, filename, tot_lines, key);
                    else Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] Line ignored.\n", config.name, config.type, filename, tot_lines);
		    ignoring = TRUE;
                    break;
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
                    if (err == E_NOTFOUND) Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] unknown key '%s'. Ignored.\n", 
						config.name, config.type, filename, tot_lines, key);
                    else Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] Line ignored.\n", config.name, config.type, filename, tot_lines);
                    break; 
                  }
                  key = NULL; value = NULL;
		}
              }
            }
	    if (!ignoring) {
              /* verifying errors and required fields */
	      if (acct_type == ACCT_NF || acct_type == ACCT_SF) {
	        if (tmp.e[tmp.num].id && tmp.e[tmp.num].id2 && tmp.e[tmp.num].label.len) 
		   Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] set_tag (id), set_tag2 (id2) and set_label are mutual exclusive. Line ignored.\n", 
			config.name, config.type, filename, tot_lines);
                else if (!err && tmp.e[tmp.num].key.agent_ip.a.family) {
                  int j, z;

                  for (j = 0; tmp.e[tmp.num].func[j]; j++);
		  for (z = 0; tmp.e[tmp.num].set_func[z]; z++, j++) {
		    tmp.e[tmp.num].func[j] = tmp.e[tmp.num].set_func[z];
		    tmp.e[tmp.num].func_type[j] = tmp.e[tmp.num].set_func_type[z];
		  }

	          if (tmp.e[tmp.num].key.agent_ip.a.family == AF_INET) v4_num++;
#if defined ENABLE_IPV6
	          else if (tmp.e[tmp.num].key.agent_ip.a.family == AF_INET6) v6_num++;
#endif
                  tmp.num++;
                }
	        /* if any required field is missing and other errors have been signalled
	           before we will trap an error message */
	        else if (!err && !tmp.e[tmp.num].key.agent_ip.a.family)
	          Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] required key missing. Required key is: 'ip'. Line ignored.\n",
			config.name, config.type, filename, tot_lines); 
	      }
	      else if (acct_type == ACCT_PM) {
	        if (tmp.e[tmp.num].id && tmp.e[tmp.num].id2 && tmp.e[tmp.num].label.len)
                   Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] set_tag (id), set_tag2 (id2) and set_label are mutual exclusive. Line ignored.\n", 
			config.name, config.type, filename, tot_lines);
	        else if (tmp.e[tmp.num].key.agent_ip.a.family)
		  Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] key 'ip' not applicable. Line ignored.\n",
			config.name, config.type, filename, tot_lines);
	        else if (!err) {
                  int j, z;

		  for (j = 0; tmp.e[tmp.num].func[j]; j++);
		  for (z = 0; tmp.e[tmp.num].set_func[z]; z++, j++) {
		    tmp.e[tmp.num].func[j] = tmp.e[tmp.num].set_func[z];
		    tmp.e[tmp.num].func_type[j] = tmp.e[tmp.num].set_func_type[z];
		  }
		  tmp.e[tmp.num].key.agent_ip.a.family = AF_INET; /* we emulate a dummy '0.0.0.0' IPv4 address */
		  v4_num++; tmp.num++;
	        }
	      }
	      else if (acct_type == MAP_BGP_PEER_AS_SRC || acct_type == MAP_BGP_SRC_LOCAL_PREF ||
	  	       acct_type == MAP_BGP_SRC_MED) {
                if (!err && (tmp.e[tmp.num].id || tmp.e[tmp.num].flags) && tmp.e[tmp.num].key.agent_ip.a.family) {
                  int j;

                  for (j = 0; tmp.e[tmp.num].func[j]; j++);
                  tmp.e[tmp.num].func[j] = pretag_id_handler;
                  if (tmp.e[tmp.num].key.agent_ip.a.family == AF_INET) v4_num++;
#if defined ENABLE_IPV6
                  else if (tmp.e[tmp.num].key.agent_ip.a.family == AF_INET6) v6_num++;
#endif
                  tmp.num++;
                }
                else if ((!tmp.e[tmp.num].id || !tmp.e[tmp.num].key.agent_ip.a.family) && !err)
                  Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] required key missing. Required keys are: 'id', 'ip'. Line ignored.\n", 
			config.name, config.type, filename, tot_lines);
	      }
              else if (acct_type == MAP_BGP_TO_XFLOW_AGENT) {
                if (!err && tmp.e[tmp.num].id && tmp.e[tmp.num].key.agent_ip.a.family) {
                  int j, z;

                  for (j = 0; tmp.e[tmp.num].func[j]; j++);
		  for (z = 0; tmp.e[tmp.num].set_func[z]; z++, j++) {
                    tmp.e[tmp.num].func[j] = tmp.e[tmp.num].set_func[z];
                    tmp.e[tmp.num].func_type[j] = tmp.e[tmp.num].set_func_type[z];
                  }
		  /* imposing pretag_id_handler to be the last one */
		  tmp.e[tmp.num].func[j] = pretag_id_handler;

                  if (tmp.e[tmp.num].key.agent_ip.a.family == AF_INET) v4_num++;
#if defined ENABLE_IPV6
                  else if (tmp.e[tmp.num].key.agent_ip.a.family == AF_INET6) v6_num++;
#endif
                  tmp.num++;
                }
                else if ((!tmp.e[tmp.num].id || !tmp.e[tmp.num].key.agent_ip.a.family) && !err)
                  Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] required key missing. Required keys are: 'id', 'ip'. Line ignored.\n",
                        config.name, config.type, filename, tot_lines);
              }
              else if (acct_type == MAP_FLOW_TO_RD) {
                if (!err && tmp.e[tmp.num].id && tmp.e[tmp.num].key.agent_ip.a.family) {
                  int j;

                  for (j = 0; tmp.e[tmp.num].func[j]; j++);
                  tmp.e[tmp.num].func[j] = pretag_id_handler;
                  if (tmp.e[tmp.num].key.agent_ip.a.family == AF_INET) v4_num++;
#if defined ENABLE_IPV6
                  else if (tmp.e[tmp.num].key.agent_ip.a.family == AF_INET6) v6_num++;
#endif
                  tmp.num++;
                }
	      }
              else if (acct_type == MAP_SAMPLING) {
                if (!err && tmp.e[tmp.num].id && tmp.e[tmp.num].key.agent_ip.a.family) {
                  int j;

                  for (j = 0; tmp.e[tmp.num].func[j]; j++);
                  tmp.e[tmp.num].func[j] = pretag_id_handler;
                  if (tmp.e[tmp.num].key.agent_ip.a.family == AF_INET) v4_num++;
#if defined ENABLE_IPV6
                  else if (tmp.e[tmp.num].key.agent_ip.a.family == AF_INET6) v6_num++;
#endif
                  tmp.num++;
                }
                else if ((!tmp.e[tmp.num].id || !tmp.e[tmp.num].key.agent_ip.a.family) && !err)
                  Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] required key missing. Required keys are: 'id', 'ip'. Line ignored.\n",
			config.name, config.type, filename, tot_lines);
              }
	      else if (acct_type == MAP_TEE_RECVS) tee_recvs_map_validate(filename, req); 
	      else if (acct_type == MAP_IGP) igp_daemon_map_validate(filename, req); 
	      else if (acct_type == MAP_CUSTOM_PRIMITIVES) custom_primitives_map_validate(filename, req); 
	    }
          }
          else Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] malformed line. Ignored.\n",
			config.name, config.type, filename, tot_lines);
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
      t->type = acct_type;
      t->num = tmp.num;
      t->ipv4_num = v4_num; 
      t->ipv4_base = &t->e[x];
      t->flags = tmp.flags;
      for (index = 0; index < tmp.num; index++) {
        if (tmp.e[index].key.agent_ip.a.family == AF_INET) { 
          memcpy(&t->e[x], &tmp.e[index], sizeof(struct id_entry));
	  t->e[x].pos = x;
	  x++;
        }
      }
#if defined ENABLE_IPV6
      t->ipv6_num = v6_num;
      t->ipv6_base = &t->e[x];
      for (index = 0; index < tmp.num; index++) {
        if (tmp.e[index].key.agent_ip.a.family == AF_INET6) {
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
	      if (!strcmp(ptr->jeq.label, ptr2->entry_label)) {
	        ptr->jeq.ptr = ptr2;
	        label_solved = TRUE;
		break;
	      }
	    }
	  }
	  if (!label_solved) {
	    ptr->jeq.ptr = NULL;
	    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Unresolved label '%s'. Ignoring it.\n",
			config.name, config.type, filename, ptr->jeq.label);
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
            if (!strcmp(ptr->jeq.label, ptr2->entry_label)) {
              ptr->jeq.ptr = ptr2;
              label_solved = TRUE;
	      break;
            }
          }
          if (!label_solved) {
            ptr->jeq.ptr = NULL;
            Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Unresolved label '%s'. Ignoring it.\n",
			config.name, config.type, filename, ptr->jeq.label);
          }
          free(ptr->jeq.label);
          ptr->jeq.label = NULL;
        }
      }
#endif

      t->filename = filename;

      /* pre_tag_map indexing here */
      if (config.maps_index &&
	  (acct_type == ACCT_NF || acct_type == ACCT_SF || acct_type == ACCT_PM ||
	   acct_type == MAP_BGP_PEER_AS_SRC || acct_type == MAP_FLOW_TO_RD)) {
	pt_bitmap_t idx_bmap;
	
	t->index_num = MAX_ID_TABLE_INDEXES;

#if defined ENABLE_IPV6
        for (ptr = t->ipv4_base, x = 0; x < MAX(t->ipv4_num, t->ipv6_num); ptr++, x++) {
#else
        for (ptr = t->ipv4_base, x = 0; x < t->ipv4_num; ptr++, x++) {
#endif
	  idx_bmap = pretag_index_build_bitmap(ptr, acct_type);
	  if (!idx_bmap) continue;

	  /* insert bitmap to index list and determine entries per index */ 
	  if (pretag_index_insert_bitmap(t, idx_bmap)) {
	    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Out of indexes. Indexing disabled.\n",
		config.name, config.type, filename);
	    pretag_index_destroy(t);
	    break;
	  }
	}

	/* set handlers */
	pretag_index_set_handlers(t);

	/* allocate indexes */
        pretag_index_allocate(t);

#if defined ENABLE_IPV6
        for (ptr = t->ipv4_base, x = 0; x < MAX(t->ipv4_num, t->ipv6_num); ptr++, x++) {
#else
        for (ptr = t->ipv4_base, x = 0; x < t->ipv4_num; ptr++, x++) {
#endif
          idx_bmap = pretag_index_build_bitmap(ptr, acct_type);
          if (!idx_bmap) continue;

	  /* fill indexes */
	  pretag_index_fill(t, idx_bmap, ptr);
	}
      }

      if (t->flags & PRETAG_FLAG_NEG) {
        Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Negations not supported. Indexing disabled.\n",
                config.name, config.type, filename);
        pretag_index_destroy(t);
      }
      else pretag_index_report(t);
    }
  }

  if (tmp.e) free(tmp.e) ;
  if (buf) free(buf) ;

  Log(LOG_INFO, "INFO ( %s/%s ): [%s] map successfully (re)loaded.\n", config.name, config.type, filename);

  return;

  handle_error:
  if (*map_allocated && tmp.e) free(tmp.e) ;
  if (buf) free(buf);

  if (t && t->timestamp) {
    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Rolling back old map.\n", config.name, config.type, filename);

    /* we update the timestamp to avoid loops */
    stat(filename, &st);
    t->timestamp = st.st_mtime;
  }
  else exit_all(1);
}

u_int8_t pt_check_neg(char **value, u_int32_t *flags)
{
  if (**value == '-') {
    (*value)++;

    if (flags) *flags |= PRETAG_FLAG_NEG;

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

void load_pre_tag_map(int acct_type, char *filename, struct id_table *t, struct plugin_requests *req,
		      int *map_allocated, int map_entries, int map_row_len)
{
  if (req) {
    req->map_entries = map_entries;
    req->map_row_len = map_row_len;
  }

  load_id_file(acct_type, filename, t, req, map_allocated);

  if (req) {
    req->map_entries = FALSE;
    req->map_row_len = FALSE;
  }
}

void pretag_init_vars(struct packet_ptrs *pptrs, struct id_table *t)
{
  if (!pptrs) return;

  if (t->type == ACCT_NF) memset(&pptrs->set_tos, 0, sizeof(s_uint8_t));
  if (t->type == MAP_BGP_TO_XFLOW_AGENT) memset(&pptrs->lookup_bgp_port, 0, sizeof(s_uint16_t));

  if (pptrs->label.val) {
    pretag_free_label(&pptrs->label);
    pptrs->have_label = FALSE;
  }
}

void pretag_init_label(pt_label_t *label)
{
  if (!label) return;

  memset(label, 0, sizeof(pt_label_t));
}

int pretag_malloc_label(pt_label_t *label, int len)
{
  if (!label) return ERR;

  label->val = malloc(len);
  if (!label->val) {
    Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (pretag_malloc_label).\n", config.name, config.type);
    return ERR;
  }
  label->len = len;

  return SUCCESS;
}

int pretag_realloc_label(pt_label_t *label, int len)
{
  if (!label) return ERR;

  label->val = realloc(label->val, len);
  if (!label->val) {
    Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (pretag_realloc_label).\n", config.name, config.type);
    return ERR;
  }
  label->len = len;

  return SUCCESS;
}

int pretag_copy_label(pt_label_t *dst, pt_label_t *src)
{
  if (!src || !dst) return ERR;

  if (dst->val) {
    Log(LOG_WARNING, "WARN ( %s/%s ): pretag_copy_label failed: dst->val not null\n", config.name, config.type);
    return ERR;
  }
  else {
    if (src->len) {
      pretag_malloc_label(dst, src->len);
      if (!dst->val) {
        Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (pretag_copy_label).\n", config.name, config.type);
        return ERR;
      }

      strncpy(dst->val, src->val, src->len);
      dst->val[dst->len] = '\0';
    }
  }
  
  return SUCCESS;
}

void pretag_free_label(pt_label_t *label)
{
  if (label && label->val) {
    free(label->val); 
    label->val = NULL;
    label->len = 0;
  }
}

int pretag_entry_process(struct id_entry *e, struct packet_ptrs *pptrs, pm_id_t *tag, pm_id_t *tag2)
{
  int j = 0;
  pm_id_t id = 0, stop = 0, ret = 0;
  pt_label_t label_local;

  e->last_matched = FALSE;

  for (j = 0, stop = 0, ret = 0; ((!ret || ret > TRUE) && (*e->func[j])); j++) {
    if (e->func_type[j] == PRETAG_SET_LABEL) {
      ret = (*e->func[j])(pptrs, &label_local, e);
    }
    else {
      ret = (*e->func[j])(pptrs, &id, e);
    }

    if (ret > TRUE) stop |= ret;
    else stop = ret;
  }

  if (!stop || stop > TRUE) {
    if (stop & PRETAG_MAP_RCODE_ID) {
      if (e->stack.func) id = (*e->stack.func)(id, *tag);
      *tag = id;
      pptrs->have_tag = TRUE;
    }
    else if (stop & PRETAG_MAP_RCODE_ID2) {
      if (e->stack.func) id = (*e->stack.func)(id, *tag2);
      *tag2 = id;
      pptrs->have_tag2 = TRUE;
    } 
    else if (stop & PRETAG_MAP_RCODE_LABEL) {
      /* auto-stacking if value exists */
      if (pptrs->label.len) {
	char default_sep[] = ",";

        if (pretag_realloc_label(&pptrs->label, label_local.len + pptrs->label.len + 1 /* sep */ + 1 /* null */)) return TRUE;
	strncat(pptrs->label.val, default_sep, 1);
        strncat(pptrs->label.val, label_local.val, label_local.len);
        pptrs->label.val[pptrs->label.len] = '\0';
      }
      else {
	if (pretag_malloc_label(&pptrs->label, label_local.len + 1 /* null */)) return TRUE;
	strncpy(pptrs->label.val, label_local.val, label_local.len);
	pptrs->label.val[pptrs->label.len] = '\0';
      }

      pptrs->have_label = TRUE;
    }
    else if (stop == BTA_MAP_RCODE_ID_ID2) {
      // stack not applicable here
      *tag = id;
      *tag2 = e->id2;
      pptrs->have_tag = TRUE;
      pptrs->have_tag2 = TRUE;
    }

    if (e->jeq.ptr) {
      if (e->ret) {
	exec_plugins(pptrs);
	set_shadow_status(pptrs);
	*tag = 0;
	*tag2 = 0;
	if (pptrs->label.val) pretag_free_label(&pptrs->label);

	pptrs->have_tag = FALSE;
	pptrs->have_tag2 = FALSE;
	pptrs->have_label = FALSE;
      }
      stop |= PRETAG_MAP_RCODE_JEQ;
    }
  }

  return stop;
}

pt_bitmap_t pretag_index_build_bitmap(struct id_entry *ptr, int acct_type)
{
  pt_bitmap_t idx_bmap = 0;
  u_int32_t iterator = 0;

  for (; ptr->func[iterator]; iterator++) idx_bmap |= ptr->func_type[iterator];

  /* 1) invalidate bitmap if we have fields incompatible with indexing */
  if (idx_bmap & PRETAG_FILTER) return 0;

  /* 2) scrub bitmap: remove PRETAG_SET_* fields from the bitmap */
  if (idx_bmap & PRETAG_SET_TOS) idx_bmap ^= PRETAG_SET_TOS;
  if (idx_bmap & PRETAG_SET_TAG) idx_bmap ^= PRETAG_SET_TAG;
  if (idx_bmap & PRETAG_SET_TAG2) idx_bmap ^= PRETAG_SET_TAG2;
  if (idx_bmap & PRETAG_SET_LABEL) idx_bmap ^= PRETAG_SET_LABEL;

  /* 3) add 'ip' to bitmap, if mandated by the map type */
  if (acct_type == ACCT_NF || acct_type == ACCT_SF ||
      acct_type == MAP_BGP_PEER_AS_SRC || acct_type == MAP_FLOW_TO_RD)
    idx_bmap |= PRETAG_IP;

  return idx_bmap;
}

int pretag_index_insert_bitmap(struct id_table *t, pt_bitmap_t idx_bmap)
{
  u_int32_t iterator = 0;

  if (!t) return TRUE;

  for (iterator = 0; iterator < t->index_num; iterator++) {
    if (!t->index[iterator].bitmap || t->index[iterator].bitmap == idx_bmap) {
      t->index[iterator].bitmap = idx_bmap;
      t->index[iterator].entries++;
      return FALSE;
    }
  }

  return TRUE;
}

int pretag_index_set_handlers(struct id_table *t)
{
  pt_bitmap_t residual_idx_bmap = 0;
  u_int32_t index = 0, iterator = 0, handler_index = 0;

  if (!t) return TRUE;
  
  for (iterator = 0; iterator < t->index_num; iterator++) {
    residual_idx_bmap = t->index[iterator].bitmap;

    handler_index = 0;
    memset(t->index[iterator].idt_handler, 0, sizeof(t->index[iterator].idt_handler));
    memset(t->index[iterator].fdata_handler, 0, sizeof(t->index[iterator].fdata_handler));

    for (index = 0; tag_map_index_entries_dictionary[index].key; index++) {
      if (t->index[iterator].bitmap & tag_map_index_entries_dictionary[index].key) {
        t->index[iterator].idt_handler[handler_index] = (*tag_map_index_entries_dictionary[index].func);
	handler_index++;

        residual_idx_bmap ^= tag_map_index_entries_dictionary[index].key;
      }
    }

    handler_index = 0;

    /* we set foreign data handlers here but skip on the residual_idx_bmap */
    for (index = 0; tag_map_index_fdata_dictionary[index].key; index++) {
      if (t->index[iterator].bitmap & tag_map_index_fdata_dictionary[index].key) {
        t->index[iterator].fdata_handler[handler_index] = (*tag_map_index_fdata_dictionary[index].func);
        handler_index++;
      }
    }

    if (residual_idx_bmap) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] maps_index: not supported for field(s) %x. Indexing disabled.\n",
		config.name, config.type, t->filename, residual_idx_bmap);
      pretag_index_destroy(t);
    }
  }

  return FALSE;
}

int pretag_index_allocate(struct id_table *t)
{
  pt_bitmap_t idx_t_size = 0;
  u_int32_t iterator = 0, j = 0;
  int ret, destroy = FALSE;

  if (!t) return TRUE;

  for (iterator = 0; iterator < t->index_num; iterator++) {
    if (t->index[iterator].bitmap) {
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] maps_index: created index %x (%u entries).\n", config.name,
    		config.type, t->filename, t->index[iterator].bitmap, t->index[iterator].entries);

      assert(!t->index[iterator].idx_t);
      idx_t_size = IDT_INDEX_HASH_BASE(t->index[iterator].entries) * sizeof(struct id_index_entry);
      t->index[iterator].idx_t = malloc(idx_t_size);

      if (!t->index[iterator].idx_t) {
        Log(LOG_WARNING, "WARN ( %s/%s ): [%s] maps_index: unable to allocate index %x.\n", config.name,
		config.type, t->filename, t->index[iterator].bitmap);
	t->index[iterator].bitmap = 0;
	t->index[iterator].entries = 0;
	destroy = TRUE;
	break;
      }
      else {
	memset(t->index[iterator].idx_t, 0, idx_t_size); 

	for (j = 0; j < IDT_INDEX_HASH_BASE(t->index[iterator].entries); j++) {
	  t->index[iterator].idx_t[j].depth = ID_TABLE_INDEX_DEPTH;
	}

	hash_init_serial(&t->index[iterator].hash_serializer, 16 /* dummy len for init sake */);
	if (ret == ERR) {
	  Log(LOG_WARNING, "WARN ( %s/%s ): [%s] maps_index: unable to allocate hash serializer for index %x.\n", config.name,
		config.type, t->filename, t->index[iterator].bitmap);
	  destroy = TRUE;
	  break;
	}
      }
    }
  }

  if (destroy) {
    pretag_index_destroy(t);
    return ERR;
  }

  return SUCCESS;
}

int pretag_index_fill(struct id_table *t, pt_bitmap_t idx_bmap, struct id_entry *ptr)
{
  u_int32_t index = 0, iterator = 0, handler_index = 0;

  if (!t) return ERR;

  for (iterator = 0; iterator < t->index_num; iterator++) {
    if (t->index[iterator].bitmap && t->index[iterator].bitmap == idx_bmap) {
      struct id_entry e;
      struct id_index_entry *idie;
      pm_hash_serial_t *hash_serializer;
      pm_hash_key_t *hash_key;
      int modulo, buckets;

      /* fill serializer in and compute modulo */
      memset(&e, 0, sizeof(struct id_entry));
      hash_serializer = &t->index[iterator].hash_serializer;
      hash_serial_set_off(hash_serializer, 0);
      hash_key = hash_serial_get_key(hash_serializer);
      buckets = IDT_INDEX_HASH_BASE(t->index[iterator].entries);

      if (!hash_key) return ERR;

      for (handler_index = 0; t->index[iterator].idt_handler[handler_index]; handler_index++) {
	(*t->index[iterator].idt_handler[handler_index])(&e, hash_serializer, ptr);
      }
      modulo = cache_crc32(hash_key_get_val(hash_key), hash_key_get_len(hash_key)) % buckets;
      idie = &t->index[iterator].idx_t[modulo];

      for (index = 0; index < idie->depth; index++) {
        if (!idie->result[index]) {
	  memcpy(&idie->hash_key[index], hash_key, sizeof(pm_hash_key_t));
          idie->result[index] = ptr;
          break;
        }
        /* removing duplicates */
        else {
	  pm_id_t saved_pos_idie, saved_pos_ptr;
	  int match = FALSE;

	  saved_pos_idie = idie->result[index]->pos; idie->result[index]->pos = 0;
	  saved_pos_ptr = ptr->pos; ptr->pos = 0;

          if (!memcmp(idie->result[index], ptr, sizeof(struct id_entry))) match = TRUE;

          idie->result[index]->pos = saved_pos_idie;
          ptr->pos = saved_pos_ptr;

	  if (match) {
	    hash_destroy_key(hash_key);
	    break;
	  }
        }
      }

      if (index == idie->depth) {
        Log(LOG_WARNING, "WARN ( %s/%s ): [%s] maps_index: out of index space %x. Indexing disabled.\n",
		config.name, config.type, t->filename, idx_bmap);
	pretag_index_destroy(t);
	break;
      }
    }
  }

  return SUCCESS;
}

void pretag_index_report(struct id_table *t)
{
  u_int32_t iterator = 0, buckets = 0, index = 0;

  if (!t) return;

  for (iterator = 0; iterator < t->index_num; iterator++) {
    if (t->index[iterator].entries) {
      u_int32_t bucket_depths[ID_TABLE_INDEX_DEPTH];

      buckets = IDT_INDEX_HASH_BASE(t->index[iterator].entries);
      memset(&bucket_depths, 0, sizeof(bucket_depths));

      for (index = 0; index < buckets; index++) {
	struct id_index_entry *idie = &t->index[iterator].idx_t[index]; 
	u_int32_t depth = 0;

	for (depth = 0; idie->result[depth] && depth < idie->depth; depth++); 

	bucket_depths[depth]++;
      }

      Log(LOG_DEBUG, "DEBUG ( %s/%s ): [%s] maps_index: index %x depths: 0:%u 1:%u 2:%u 3:%u 4:%u 5:%u 6:%u 7:%u size: %u\n",
	  config.name, config.type, t->filename, t->index[iterator].bitmap,
	  bucket_depths[0], bucket_depths[1], bucket_depths[2], bucket_depths[3],
	  bucket_depths[4], bucket_depths[5], bucket_depths[6], bucket_depths[7],
	  (buckets * sizeof(struct id_index_entry)));
    } 
  }
}

void pretag_index_destroy(struct id_table *t)
{
  pm_hash_serial_t *hash_serializer;
  pm_hash_key_t *hash_key;
  u_int32_t iterator = 0, buckets = 0, bucket_idx = 0, depth_idx = 0;

  if (!t) return;

  for (iterator = 0; iterator < t->index_num; iterator++) {
    if (t->index[iterator].idx_t) {
      buckets = IDT_INDEX_HASH_BASE(t->index[iterator].entries);

      for (bucket_idx = 0; bucket_idx < buckets; bucket_idx++) {
        for (depth_idx = 0; depth_idx < ID_TABLE_INDEX_DEPTH; depth_idx++) {
          hash_destroy_key(&t->index[iterator].idx_t[bucket_idx].hash_key[depth_idx]);
        }
      }

      free(t->index[iterator].idx_t);
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] maps_index: destroyed index %x.\n",
                config.name, config.type, t->filename, t->index[iterator].bitmap);
    }

    hash_serializer = &t->index[iterator].hash_serializer;
    hash_key = hash_serial_get_key(hash_serializer);
    hash_destroy_key(hash_key);
    memset(&t->index[iterator], 0, sizeof(struct id_table_index));
  }

  t->index_num = 0;
}

void pretag_index_lookup(struct id_table *t, struct packet_ptrs *pptrs, struct id_entry **index_results, int ir_entries)
{
  struct id_entry res_fdata;
  struct id_index_entry *idie;
  pm_hash_serial_t *hash_serializer;
  pm_hash_key_t *hash_key;
  u_int32_t iterator, iterator_ir, index_cc, index_hdlr;
  int modulo, buckets;

  if (!t || !pptrs || !index_results) return;

  memset(index_results, 0, (sizeof(struct id_entry *) * ir_entries));
  iterator_ir = 0;

  for (iterator = 0; iterator < t->index_num; iterator++) {
    if (t->index[iterator].entries) {
      hash_serializer = &t->index[iterator].hash_serializer;
      hash_serial_set_off(hash_serializer, 0);
      hash_key = hash_serial_get_key(hash_serializer);
      buckets = IDT_INDEX_HASH_BASE(t->index[iterator].entries);

      for (index_hdlr = 0; (*t->index[iterator].fdata_handler[index_hdlr]); index_hdlr++) {
        (*t->index[iterator].fdata_handler[index_hdlr])(&res_fdata, &t->index[iterator].hash_serializer, pptrs);
      }

      modulo = cache_crc32(hash_key_get_val(hash_key), hash_key_get_len(hash_key)) % buckets;
      idie = &t->index[iterator].idx_t[modulo];

      for (index_cc = 0; idie->result[index_cc] && index_cc < idie->depth; index_cc++) {
	if (!hash_key_cmp(&idie->hash_key[index_cc], hash_key)) {
          index_results[iterator_ir] = idie->result[index_cc];
	  if (iterator_ir < ir_entries) iterator_ir++;
	  else {
	    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] maps_index: out of index results space. Indexing disabled.\n",
                config.name, config.type, t->filename);
	    pretag_index_destroy(t);
	    memset(index_results, 0, (sizeof(struct id_entry *) * ir_entries));
	    return;
	  }
	}
      }
    }
    else break;
  }

  // pretag_index_results_compress(index_results, ir_entries);
  pretag_index_results_sort(index_results, ir_entries);
  pretag_index_results_compress_jeqs(index_results, ir_entries);
}

void pretag_index_results_sort(struct id_entry **index_results, int ir_entries)
{
  struct id_entry *ptr = NULL;
  u_int32_t i, j;

  if (!index_results) return;

  for (i = 0, j = 1; index_results[i] && i < ir_entries; i++, j++) {
    if (index_results[j] && j < ir_entries) {
      if (index_results[i]->pos > index_results[j]->pos) {
	ptr = index_results[j];
	index_results[j] = index_results[i];
	index_results[i] = ptr;
      }
    }
  }
}

void pretag_index_results_compress(struct id_entry **index_results, int ir_entries)
{
  struct id_entry *ptr = NULL;
  u_int32_t j, valid;
  int i;

  if (!index_results) return;

  for (i = 0; i < ir_entries; i++) {
    valid = 0;
    if (!index_results[i]) {
      for (j = i + 1; j < ir_entries; j++) {
	if (index_results[j]) valid++;
        index_results[j-1] = index_results[j];
      }
      index_results[ir_entries-1] = NULL;
      if (!index_results[i] && valid) i--;
    }
  }
}

void pretag_index_results_compress_jeqs(struct id_entry **index_results, int ir_entries)
{
  struct id_entry *ptr = NULL;
  u_int32_t i, j, x;

  if (!index_results) return;

  for (i = 0; index_results[i] && i < ir_entries; i++) {
    if (index_results[i]->jeq.ptr) {
      for (j = i + 1; index_results[j] && j < ir_entries; j++) {
        if (index_results[i]->jeq.ptr->pos > index_results[j]->pos) {
	  for (x = j + 1; x < ir_entries; x++) {
	    index_results[x-1] = index_results[x];
	  }

	  index_results[ir_entries-1] = NULL;
	}
      }
    }
  }
}

int pretag_index_have_one(struct id_table *t)
{
  return t->index[0].entries;
}

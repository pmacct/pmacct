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

#define __CFG_C

/* includes */
#include "pmacct.h"
#include "plugin_hooks.h"
#include "pmacct-data.h"
#include "pkt_handlers.h"

/* evaluate_configuration() handles all supported configuration
   keys and inserts them in configuration structure of plugins */
void evaluate_configuration(char *filename, int rows)
{
  char *key, *value, *name, *delim;
  int index = 0, dindex, valid_line, key_found = 0, res;

  while (index < rows) {
    if (*cfg[index] == '\0') valid_line = FALSE;
    else valid_line = TRUE; 

    if (valid_line) {
      /* debugging the line if required */
      if (debug) Log(LOG_DEBUG, "DEBUG: [%s] %s\n", filename, cfg[index]);

      /* splitting key, value and name */
      delim = strchr(cfg[index], ':');
      *delim = '\0';
      key = cfg[index];
      value = delim+1;

      delim = strchr(key, '[');
      if (delim) {
        *delim = '\0';
        name = delim+1;
        delim = strchr(name, ']');
        *delim = '\0';
      }
      else name = NULL;

      /* parsing keys */
      for (dindex = 0; strcmp(dictionary[dindex].key, ""); dindex++) {
        if (!strcmp(dictionary[dindex].key, key)) {
	  res = FALSE;
          if ((*dictionary[dindex].func)) {
	    res = (*dictionary[dindex].func)(filename, name, value);
	    if (res < 0) Log(LOG_WARNING, "WARN: [%s:%u] Invalid value. Ignored.\n", filename, index+1);
	    else if (!res) Log(LOG_WARNING, "WARN: [%s:%u] Unknown symbol '%s'. Ignored.\n", filename, index+1, name);
	  }
	  else Log(LOG_WARNING, "WARN: [%s:%u] Unable to handle key: %s. Ignored.\n", filename, index+1, key);
	  key_found = TRUE;
	  break;
        }
	else key_found = FALSE;
      }

      if (!key_found) Log(LOG_WARNING, "WARN: [%s:%u] Unknown key: %s. Ignored.\n", filename, index+1, key);
    }

    index++;
  }
}

/* parse_configuration_file() reads configuration file
   and stores its content in an array; then creates
   plugin structures and parses supported config keys */
int parse_configuration_file(char *filename)
{
  char localbuf[10240];
  char cmdline [] = "cmdline"; 
  FILE *file;
  int num = 0, cmdlineflag = FALSE, rows_cmdline = rows, idx;
  rows = 0;

  /* NULL filename means we don't have a configuration file; 1st stage: read from
     file and store lines into a first char* array; merge commandline options, if
     required, placing them at the tail - in order to override directives placed
     in the configuration file */
  if (filename) { 
    if ((file = fopen(filename,"r")) == NULL) {
      Log(LOG_ERR, "ERROR: [%s] file not found.\n", filename);
      return ERR;
    }
    else {
      while (!feof(file)) {
        if (rows == LARGEBUFLEN) {
	  Log(LOG_ERR, "ERROR: [%s] maximum number of %d lines reached.\n", filename, LARGEBUFLEN);
	  break;
        }
	memset(localbuf, 0, sizeof(localbuf));
        if (fgets(localbuf, sizeof(localbuf), file) == NULL) break;	
        else {
	  localbuf[sizeof(localbuf)-1] = '\0';
          cfg[rows] = malloc(strlen(localbuf)+2);
	  if (!cfg[rows]) {
	    Log(LOG_ERR, "ERROR: [%s] malloc() failed (parse_configuration_file). Exiting.\n", filename);
	    exit(1);
	  }
          strcpy(cfg[rows], localbuf);
          cfg[rows][strlen(localbuf)+1] = '\0';
          rows++;
        } 
      }
    }
    fclose(file);
  }
  else {
    filename = cmdline;
    cmdlineflag = TRUE;
  }

  if (rows_cmdline) {
    for (idx = 0; idx < rows_cmdline && (rows+idx) < LARGEBUFLEN; idx++) {
      cfg[rows+idx] = cfg_cmdline[idx];
    }
    rows += idx;
  }

  /* 2nd stage: sanitize lines */
  sanitize_cfg(rows, filename);

  /* 3rd stage: plugin structures creation; we discard
     plugin names if 'pmacctd' has been invoked commandline;
     if any plugin has been activated we default to a single
     'imt' plugin */ 
  if (!cmdlineflag) parse_core_process_name(filename, rows, FALSE);
  else parse_core_process_name(filename, rows, TRUE);

  if (!cmdlineflag) num = parse_plugin_names(filename, rows, FALSE);
  else num = parse_plugin_names(filename, rows, TRUE);

  if (!num && config.acct_type < ACCT_FWPLANE_MAX) {
    Log(LOG_WARNING, "WARN: [%s] No plugin has been activated; defaulting to in-memory table.\n", filename); 
    num = create_plugin(filename, "default_memory", "memory");
  }

  if (debug) {
    struct plugins_list_entry *list = plugins_list;
    
    while (list) {
      Log(LOG_DEBUG, "DEBUG: [%s] plugin name/type: '%s'/'%s'.\n", filename, list->name, list->type.string);
      list = list->next;
    }
  }

  /* 4th stage: setting some default value */
  set_default_values();
  
  /* 5th stage: parsing keys and building configurations */ 
  evaluate_configuration(filename, rows);

  return SUCCESS;
}

void sanitize_cfg(int rows, char *filename)
{
  int rindex = 0, len, got_first, got_first_colon;
  char localbuf[10240];

  while (rindex < rows) {
    memset(localbuf, 0, 10240);

    /* checking the whole line: if it's a comment starting with
       '!', it will be removed */
    if (iscomment(cfg[rindex])) memset(cfg[rindex], 0, strlen(cfg[rindex]));

    /* checking the whole line: if it's void, it will be removed */
    if (isblankline(cfg[rindex])) memset(cfg[rindex], 0, strlen(cfg[rindex]));

    /* 
       a pair of syntax checks on the whole line:
       - does the line contain at least a ':' verb ?
       - are the square brackets weighted both in key and value ?
    */
    len = strlen(cfg[rindex]);
    if (len) {
      int symbol = FALSE, cindex = 0, got_first = 0, got_first_colon = 0;

      if (!strchr(cfg[rindex], ':')) {
	Log(LOG_ERR, "ERROR: [%s:%u] Syntax error: missing ':'. Exiting.\n", filename, rindex+1); 
	exit(1);
      }

      while(cindex <= len) {
        if (cfg[rindex][cindex] == '[') symbol++;
        else if (cfg[rindex][cindex] == ']') {
	  symbol--;
	  got_first++;
	}
	
	if (cfg[rindex][cindex] == ':' && !got_first_colon) {
	  got_first_colon = TRUE;

	  if (symbol) {
	    Log(LOG_ERR, "ERROR: [%s:%u] Syntax error: illegal brackets. Exiting.\n", filename, rindex+1);
	    exit(1);
	  }
	}

	if (cfg[rindex][cindex] == '\0') {
	  if (symbol && !got_first) {
            Log(LOG_ERR, "ERROR: [%s:%u] Syntax error: not weighted brackets (1). Exiting.\n", filename, rindex+1);
	    exit(1);
	  }
	}

	if (symbol < 0 && !got_first) {
	  Log(LOG_ERR, "ERROR: [%s:%u] Syntax error: not weighted brackets (2). Exiting.\n", filename, rindex+1);
	  exit(1);
	}

	if (symbol > 1 && !got_first) {
	  Log(LOG_ERR, "ERROR: [%s:%u] Syntax error: nested symbols not allowed. Exiting.\n", filename, rindex+1);
	  exit(1);
	}
	
	cindex++;
      }
    }

    /* checking the whole line: erasing unwanted spaces from key;
       trimming start/end spaces from value; symbols will be left
       untouched */
    len = strlen(cfg[rindex]);
    if (len) {
      int symbol = FALSE, value = FALSE, cindex = 0, lbindex = 0;
      char *valueptr;

      while(cindex <= len) {
	if (!value) {
          if (cfg[rindex][cindex] == '[') symbol++;
          else if (cfg[rindex][cindex] == ']') symbol--;
	  else if (cfg[rindex][cindex] == ':') {
	    value++;
	    valueptr = &localbuf[lbindex+1];
	  }
	}
        if ((!symbol) && (!value)) {
	  if (!isspace(cfg[rindex][cindex])) {
	    localbuf[lbindex] = cfg[rindex][cindex]; 
	    lbindex++;
	  }
        }
        else {
	  localbuf[lbindex] = cfg[rindex][cindex];
	  lbindex++;
        }
        cindex++;
      }
      localbuf[lbindex] = '\0';
      trim_spaces(valueptr);
      strcpy(cfg[rindex], localbuf);
    }

    /* checking key field: each symbol must refer to a key */
    len = strlen(cfg[rindex]);
    if (len) { 
      int symbol = FALSE, key = FALSE, cindex = 0;

      while (cindex < rows) {
        if (cfg[rindex][cindex] == '[') symbol++;
	else if (cfg[rindex][cindex] == ']') {
	  symbol--;
	  key--;
	}

	if (cfg[rindex][cindex] == ':') break;

	if (!symbol) {
	  if (isalpha(cfg[rindex][cindex])) key = TRUE;
	}
	else {
	  if (!key) {
            Log(LOG_ERR, "ERROR: [%s:%u] Syntax error: symbol not referring to any key. Exiting.\n", filename, rindex+1);
	    exit(1);
	  }
	}
        cindex++;
      }
    }


    /* checking key field: does a key still exist ? */
    len = strlen(cfg[rindex]);
    if (len) {
      if (cfg[rindex][0] == ':') {
	Log(LOG_ERR, "ERROR: [%s:%u] Syntax error: missing key. Exiting.\n", filename, rindex+1);
	exit(1);
      }
    }

    /* checking key field: converting key to lower chars */ 
    len = strlen(cfg[rindex]);
    if (len) {
      int symbol = FALSE, cindex = 0;

      while(cindex <= len) {
        if (cfg[rindex][cindex] == '[') symbol++;
	else if (cfg[rindex][cindex] == ']') symbol--;

	if (cfg[rindex][cindex] == ':') break;
	if (!symbol) {
	  if (isalpha(cfg[rindex][cindex]))
	    cfg[rindex][cindex] = tolower(cfg[rindex][cindex]);
	}
	cindex++;
      }
    }

    rindex++;
  }
}

void parse_core_process_name(char *filename, int rows, int ignore_names)
{
  int index = 0, found = 0;
  char key[SRVBUFLEN], name[SRVBUFLEN], *start, *end;

  /* searching for 'core_proc_name' key */
  while (index < rows) {
    memset(key, 0, SRVBUFLEN);
    start = NULL; end = NULL;

    start = cfg[index];
    end = strchr(cfg[index], ':');
    if (end > start) {
      strlcpy(key, cfg[index], (end-start)+1);
      if (!strncmp(key, "core_proc_name", sizeof("core_proc_name"))) {
        start = end+1;
        strlcpy(name, start, SRVBUFLEN);
	found = TRUE;
        break;
      }
    }
    index++;
  }

  if (!found || ignore_names) create_plugin(filename, "default", "core");
  else create_plugin(filename, name, "core");
}

/* parse_plugin_names() leaves cfg array untouched: parses the key 'plugins'
   if it exists and creates the plugins linked list */ 
int parse_plugin_names(char *filename, int rows, int ignore_names)
{
  int index = 0, num = 0, found = 0, default_name = FALSE;
  char *start, *end, *start_name, *end_name;
  char key[SRVBUFLEN], value[10240], token[SRVBUFLEN], name[SRVBUFLEN];

  /* searching for 'plugins' key */
  while (index < rows) {
    memset(key, 0, SRVBUFLEN);
    start = NULL; end = NULL;

    start = cfg[index];
    end = strchr(cfg[index], ':');
    if (end > start) {
      strlcpy(key, cfg[index], (end-start)+1); 
      if (!strncmp(key, "plugins", sizeof("plugins"))) {
	start = end+1;
	strcpy(value, start); 
	found = TRUE;
	break;
      }
    }
    index++;
  }

  if (!found) return 0;

  /* parsing declared plugins */
  start = value;
  while (*end != '\0') {
    memset(token, 0, SRVBUFLEN);
    if (!(end = strchr(start, ','))) end = strchr(start, '\0');
    if (end > start) {
      strlcpy(token, start, (end-start)+1);
      if ((start_name = strchr(token, '[')) && (end_name = strchr(token, ']'))) {
        if (end_name > (start_name+1)) {
          strlcpy(name, (start_name+1), (end_name-start_name));
	  trim_spaces(name);
	  *start_name = '\0';
	}
      }
      else default_name = TRUE;
	
      /* Having already plugins name and type, we'll filter out reserved symbols */
      trim_spaces(token);
      lower_string(token);
      if (!strcmp(token, "core")) {
        Log(LOG_ERR, "ERROR: [%s] plugins of type 'core' are not allowed. Exiting.\n", filename);
        exit(1);
      }

      if (!ignore_names) {
        if (default_name) compose_default_plugin_name(name, SRVBUFLEN, token);
        if (create_plugin(filename, name, token)) num++;
      }
      else {
        compose_default_plugin_name(name, SRVBUFLEN, token);
        if (create_plugin(filename, name, token)) num++;
      }
    }
    start = end+1;
  }

  /* having already processed it, we erase 'plugins' line */
  memset(cfg[index], 0, strlen(cfg[index]));

  return num;
}

/* rough and dirty function to assign default values to
   configuration file of each plugin */
void set_default_values()
{
  struct plugins_list_entry *list = plugins_list;

  while (list) {
    list->cfg.promisc = TRUE;
    list->cfg.maps_refresh = TRUE;

    list = list->next;
  }
}

void compose_default_plugin_name(char *out, int outlen, char *type)
{
  strcpy(out, "default");
  strcat(out, "_");
  strncat(out, type, (outlen - 10));
}

int create_plugin(char *filename, char *name, char *type)
{
  struct plugins_list_entry *plugin, *ptr;
  struct plugin_type_entry *ptype = NULL;
  int index = 0, id = 0;

  /* searching for a valid known plugin type */
  while(strcmp(plugin_types_list[index].string, "")) {
    if (!strcmp(type, plugin_types_list[index].string)) ptype = &plugin_types_list[index];
    index++;
  }

  if (!ptype) {
    Log(LOG_ERR, "ERROR: [%s] Unknown plugin type: %s. Ignoring.\n", filename, type);
    return FALSE;
  }

  /* checks */
  if (plugins_list) {
    id = 0;
    ptr = plugins_list;

    while (ptr) {
      /* plugin id */
      if (ptr->id > id) id = ptr->id;

      /* dupes */
      if (!strcmp(name, ptr->name)) {
        Log(LOG_WARNING, "WARN: [%s] another plugin with the same name '%s' already exists. Preserving first.\n", filename, name);
        return FALSE;
      }
      ptr = ptr->next;
    }
    id++;
  }

  /* creating a new plugin structure */
  plugin = (struct plugins_list_entry *) malloc(sizeof(struct plugins_list_entry));
  if (!plugin) {
    Log(LOG_ERR, "ERROR: [%s] malloc() failed (create_plugin). Exiting.\n", filename);
    exit(1);
  }

  memset(plugin, 0, sizeof(struct plugins_list_entry));
  
  strcpy(plugin->name, name);
  plugin->id = id;
  memcpy(&plugin->type, ptype, sizeof(struct plugin_type_entry));
  plugin->next = NULL;

  /* inserting our object in plugin's linked list */
  if (plugins_list) {
    ptr = plugins_list;
    while(ptr->next) ptr = ptr->next; 
    ptr->next = plugin;
  }
  else plugins_list = plugin;

  return TRUE;
}

int delete_plugin_by_id(int id)
{
  struct plugins_list_entry *list = plugins_list;
  struct plugins_list_entry *aux = plugins_list;
  int highest_id = 0;

  if (id == 0) return ERR;

  while (list) {
    if (list->id == id) {
      aux->next = list->next;
      free(list);
      list = aux;
    }
    else {
      if (list->id > highest_id) highest_id = list->id; 
    }
    aux = list;
    list = list->next; 
  } 

  return highest_id;
}

struct plugins_list_entry *search_plugin_by_pipe(int pipe)
{
  struct plugins_list_entry *list = plugins_list;

  if (pipe < 0) return NULL;

  while (list) {
    if (list->pipe[1] == pipe) return list; 
    else list = list->next; 
  }

  return NULL;
}

struct plugins_list_entry *search_plugin_by_pid(pid_t pid)
{
  struct plugins_list_entry *list = plugins_list;

  if (pid <= 0) return NULL;

  while (list) {
    if (list->pid == pid) return list;
    else list = list->next;
  }

  return NULL;
}

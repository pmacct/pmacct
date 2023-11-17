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
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include "pmacct.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "ip_flow.h"
#include "classifier.h"
#include "jhash.h"

/* Global variables */
struct pkt_classifier *class;
u_int32_t class_trivial_hash_rnd = 140281;

void init_classifiers()
{
  int max = pmct_get_num_entries(); 

  class = map_shared(0, sizeof(struct pkt_classifier) * max, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
  memset(class, 0, sizeof(struct pkt_classifier) * max);
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
      Log(LOG_WARNING, "WARN ( %s/%s ): Finished elements in class table (%u). Raise via classifier_num_roots.\n", config.name, config.type, num);
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

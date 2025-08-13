/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2025 by Paolo Lucente
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

#define NDPI_LIB_COMPILATION
/* 4.2.0-stable trick */
#define SAVED_PACKAGE PACKAGE
#undef PACKAGE
#define SAVED_PACKAGE_BUGREPORT PACKAGE_BUGREPORT
#undef PACKAGE_BUGREPORT
#define SAVED_PACKAGE_NAME PACKAGE_NAME
#undef PACKAGE_NAME
#define SAVED_PACKAGE_STRING PACKAGE_STRING
#undef PACKAGE_STRING
#define SAVED_PACKAGE_TARNAME PACKAGE_TARNAME
#undef PACKAGE_TARNAME
#define SAVED_PACKAGE_VERSION PACKAGE_VERSION
#undef PACKAGE_VERSION
#define SAVED_VERSION VERSION
#undef VERSION

#include "../pmacct.h"

/* 4.2.0-stable trick */
#undef PACKAGE
#define PACKAGE SAVED_PACKAGE
#undef PACKAGE_BUGREPORT
#define PACKAGE_BUGREPORT SAVED_PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#define PACKAGE_NAME SAVED_PACKAGE_NAME
#undef PACKAGE_STRING
#define PACKAGE_STRING SAVED_PACKAGE_STRING
#undef PACKAGE_TARNAME
#define PACKAGE_TARNAME SAVED_PACKAGE_TARNAME
#undef PACKAGE_VERSION
#define PACKAGE_VERSION SAVED_PACKAGE_VERSION
#undef VERSION
#define VERSION SAVED_VERSION
#undef NDPI_LIB_COMPILATION
#include "../ip_flow.h"
#include "../classifier.h"
#include "ndpi.h"

struct pm_ndpi_workflow *pm_ndpi_workflow_init()
{
    
  NDPI_PROTOCOL_BITMASK all;
    
  // XXX ndpi_init_prefs pm_ndpi_init_prefs = ndpi_no_prefs;
  struct ndpi_detection_module_struct *module = ndpi_init_detection_module(NULL); // pm_ndpi_init_prefs);
  struct pm_ndpi_workflow *workflow = ndpi_calloc(1, sizeof(struct pm_ndpi_workflow));

  log_notification_init(&log_notifications.ndpi_cache_full);
  log_notification_init(&log_notifications.ndpi_tmp_frag_warn);

/* XXX
  workflow->prefs.decode_tunnels = FALSE;

  if (config.classifier_table_num) workflow->prefs.num_roots = config.classifier_table_num;
  else workflow->prefs.num_roots = NDPI_NUM_ROOTS;

  if (config.ndpi_max_flows) workflow->prefs.max_ndpi_flows = config.ndpi_max_flows;
  else workflow->prefs.max_ndpi_flows = NDPI_MAXFLOWS;

  if (config.ndpi_proto_guess) workflow->prefs.protocol_guess = config.ndpi_proto_guess;
  else workflow->prefs.protocol_guess = FALSE;

  if (config.ndpi_idle_scan_period) workflow->prefs.idle_scan_period = config.ndpi_idle_scan_period; 
  else workflow->prefs.idle_scan_period = NDPI_IDLE_SCAN_PERIOD;

  if (config.ndpi_idle_max_time) workflow->prefs.idle_max_time = config.ndpi_idle_max_time;
  else workflow->prefs.idle_max_time = NDPI_IDLE_MAX_TIME;

  if (config.ndpi_idle_scan_budget) workflow->prefs.idle_scan_budget = config.ndpi_idle_scan_budget;
  else workflow->prefs.idle_scan_budget = NDPI_IDLE_SCAN_BUDGET; 

  if (config.ndpi_giveup_proto_tcp) workflow->prefs.giveup_proto_tcp = config.ndpi_giveup_proto_tcp;
  else workflow->prefs.giveup_proto_tcp = NDPI_GIVEUP_PROTO_TCP;

  if (config.ndpi_giveup_proto_udp) workflow->prefs.giveup_proto_udp = config.ndpi_giveup_proto_udp;
  else workflow->prefs.giveup_proto_udp = NDPI_GIVEUP_PROTO_UDP;

  if (config.ndpi_giveup_proto_other) workflow->prefs.giveup_proto_other = config.ndpi_giveup_proto_other;
  else workflow->prefs.giveup_proto_other = NDPI_GIVEUP_PROTO_OTHER;
*/

  workflow->ndpi_struct = module;

  if (workflow->ndpi_struct == NULL) {
    Log(LOG_ERR, "ERROR ( %s/core ): nDPI global structure initialization failed.\n", config.name);
    exit_gracefully(1);
  }

  workflow->ndpi_flows_root = ndpi_calloc(workflow->prefs.num_roots, sizeof(void *));
    
  // enable all protocols
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(workflow->ndpi_struct, &all);

  ndpi_finalize_initialization(workflow->ndpi_struct);

  return workflow;
}

void pm_ndpi_export_proto_to_class(struct pm_ndpi_workflow *workflow)
{
  struct pkt_classifier css;
  u_int32_t class_st_sz;
  int idx, ret;

  if (!workflow || !workflow->ndpi_struct) return;

  class_st_sz = sizeof(struct pkt_classifier) * workflow->ndpi_struct->ndpi_num_supported_protocols;
  class = map_shared(0, class_st_sz, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
  memset(class, 0, class_st_sz);

  for (idx = 0; idx < (int) workflow->ndpi_struct->ndpi_num_supported_protocols; idx++) {
    if (workflow->ndpi_struct->proto_defaults[idx].protoId) {
      memset(&css, 0, sizeof(css));
      css.id = workflow->ndpi_struct->proto_defaults[idx].protoId;
      strncpy(css.protocol, workflow->ndpi_struct->proto_defaults[idx].protoName, MAX_PROTOCOL_LEN);
      css.category = workflow->ndpi_struct->proto_defaults[idx].protoCategory;
      ret = pmct_ndpi_register(&css);
      if (!ret) Log(LOG_WARNING, "WARN ( %s/core ): unable to register nDPI class ID %u.\n", config.name, css.id);
    }
  }
}

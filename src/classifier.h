/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2022 by Paolo Lucente
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

#ifndef CLASSIFIER_H
#define CLASSIFIER_H

#include "conntrack.h"

/* defines */
#define MAX_FN_LEN 256
#define MAX_SUBDIRS 128
#define MAX_CLASSIFIERS 512
#define MAX_PATTERN_LEN 2048
#define DEFAULT_TENTATIVES 5 

/* data structures */
struct pkt_classifier {
  pm_class_t id;
  char protocol[MAX_PROTOCOL_LEN];
#if defined (WITH_NDPI)
  ndpi_protocol_category_t category;
#endif
  conntrack_helper ct_helper;
};

/* All but __CLASSIFIER_C are dummy entries. They are required to export locally
   the 'class' array. This is in order to avoid to link extra C files into nfacctd
   and sfacctd */

/* prototypes */
extern void init_classifiers();
extern pm_class_t pmct_register(struct pkt_classifier *);
extern pm_class_t pmct_ndpi_register(struct pkt_classifier *);
extern void pmct_unregister(pm_class_t);
extern pm_class_t pmct_find_first_free();
extern pm_class_t pmct_find_last_free();
extern int pmct_isfree(pm_class_t);
extern int pmct_get(pm_class_t, struct pkt_classifier *);
extern int pmct_get_num_entries();

extern struct pkt_classifier *class;

#endif //CLASSIFIER_H

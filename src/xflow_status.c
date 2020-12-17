/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2020 by Paolo Lucente
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

/* includes */
#include "pmacct.h"
#include "addr.h"

/* Global variables */
xflow_status_table_t xflow_status_table;

/* functions */
u_int32_t hash_status_table(u_int32_t data, struct sockaddr *sa, u_int32_t size)
{
  int hash = -1;

  if (sa->sa_family == AF_INET)
    hash = (data ^ ((struct sockaddr_in *)sa)->sin_addr.s_addr) % size;
  else if (sa->sa_family == AF_INET6) {
    u_int32_t tmp;

    memcpy(&tmp, ((struct sockaddr_in6 *)sa)->sin6_addr.s6_addr+12, 4);
    hash = (data ^ tmp) % size;
  }

  return hash;
}

struct xflow_status_entry *search_status_table(xflow_status_table_t *table, struct sockaddr *sa, u_int32_t aux1, u_int32_t aux2, int hash, int num_entries)
{
  struct xflow_status_entry *entry = table->t[hash], *saved = NULL;
  u_int16_t port;

  cycle_again:
  if (entry) {
    saved = entry;
    if (!sa_addr_cmp(sa, &entry->agent_addr) && aux1 == entry->aux1 && aux2 == entry->aux2); /* FOUND IT: we are done */
    else {
      entry = entry->next;
      goto cycle_again;
    }
  }
  else {
    if (table->entries < num_entries) {
      entry = malloc(sizeof(struct xflow_status_entry));
      if (!entry) goto error;
      else {
	memset(entry, 0, sizeof(struct xflow_status_entry));
	sa_to_addr((struct sockaddr *)sa, &entry->agent_addr, &port);
	entry->aux1 = aux1;
	entry->aux2 = aux2;
	entry->seqno = 0;
	entry->next = FALSE;
        if (!saved) table->t[hash] = entry;
        else saved->next = entry;

	table->memerr = TRUE;
	table->entries++;
      }
    }
    else {
      error:
      if (table->memerr) {
	Log(LOG_ERR, "ERROR ( %s/%s ): unable to allocate more entries into the xFlow status table.\n", config.name, config.type);
	table->memerr = FALSE;
	return NULL;
      }
    }
  }

  return entry;
}

void update_status_table(struct xflow_status_entry *entry, u_int32_t seqno, int bytes)
{
  if (!entry) return;

  entry->counters.total++;
  entry->counters.bytes += bytes;

  if (!entry->seqno || config.nfacctd_disable_checks) {
    entry->counters.good++;
  }
  else {
    if (seqno == entry->seqno + entry->inc) entry->counters.good++;
    else {
      char agent_ip_address[INET6_ADDRSTRLEN];
      char collector_ip_address[INET6_ADDRSTRLEN];
      char null_ip_address[] = "0.0.0.0";

      addr_to_str(agent_ip_address, &entry->agent_addr);
      if (config.nfacctd_ip)
	memcpy(collector_ip_address, config.nfacctd_ip, MAX(strlen(config.nfacctd_ip), INET6_ADDRSTRLEN));
      else
	strcpy(collector_ip_address, null_ip_address);

      Log(LOG_INFO, "INFO ( %s/%s ): expecting flow '%u' but received '%u' collector=%s:%u agent=%s:%u\n",
		config.name, config.type, entry->seqno+entry->inc, seqno, collector_ip_address,
		collector_port, agent_ip_address, entry->aux1);
      if (seqno > (entry->seqno + entry->inc)) entry->counters.jumps_f++;
      else entry->counters.jumps_b++;
    }
  }

  entry->seqno = seqno;
}

void print_status_table(xflow_status_table_t *table, time_t now, int buckets)
{
  struct xflow_status_entry *entry; 
  int idx;
  char agent_ip_address[INET6_ADDRSTRLEN];
  char collector_ip_address[INET6_ADDRSTRLEN];
  char null_ip_address[] = "0.0.0.0";

  Log(LOG_NOTICE, "NOTICE ( %s/%s ): +++\n", config.name, config.type);

  if (config.nfacctd_ip) memcpy(collector_ip_address, config.nfacctd_ip, MAX(strlen(config.nfacctd_ip), INET6_ADDRSTRLEN));
  else strcpy(collector_ip_address, null_ip_address);
  
  for (idx = 0; idx < buckets; idx++) {
    entry = table->t[idx];

    bucket_cycle:
    if (entry && entry->counters.total && entry->counters.bytes) {
      addr_to_str(agent_ip_address, &entry->agent_addr);

      Log(LOG_NOTICE, "NOTICE ( %s/%s ): stats [%s:%u] agent=%s:%u time=%ld packets=%" PRIu64 " bytes=%" PRIu64 " seq_good=%u seq_jmp_fwd=%u seq_jmp_bck=%u\n",
		config.name, config.type, collector_ip_address, collector_port,
		agent_ip_address, entry->aux1, (long)now, entry->counters.total, entry->counters.bytes,
		entry->counters.good, entry->counters.jumps_f, entry->counters.jumps_b);

      if (entry->next) {
	entry = entry->next;
	goto bucket_cycle;
      }
    } 
  }

  Log(LOG_NOTICE, "NOTICE ( %s/%s ): stats [%s:%u] time=%ld discarded_packets=%u\n",
		config.name, config.type, collector_ip_address, collector_port,
		(long)now, table->tot_bad_datagrams);

  Log(LOG_NOTICE, "NOTICE ( %s/%s ): ---\n", config.name, config.type);
}

struct xflow_status_entry_sampling *
search_smp_if_status_table(struct xflow_status_entry_sampling *sentry, u_int32_t interface)
{
  while (sentry) {
    if (sentry->interface == interface) return sentry;
    sentry = sentry->next;
  }

  return NULL;
}

struct xflow_status_entry_sampling *
search_smp_id_status_table(struct xflow_status_entry_sampling *sentry, u_int32_t sampler_id, u_int8_t return_unequal)
{
  /* Match a samplerID or, if samplerID within a data record is zero and no match was
     possible, then return the last samplerID defined -- last part is C7600 workaround */
  while (sentry) {
    if (sentry->sampler_id == sampler_id || (return_unequal && !sampler_id && !sentry->next)) return sentry;
    sentry = sentry->next;
  }

  return NULL;
}

struct xflow_status_entry_sampling *
create_smp_entry_status_table(xflow_status_table_t *table, struct xflow_status_entry *entry)
{
  struct xflow_status_entry_sampling *sentry = entry->sampling, *new = NULL;  

  if (sentry) {
    while (sentry->next) sentry = sentry->next; 
  }

  if (table->entries < XFLOW_STATUS_TABLE_MAX_ENTRIES) {
    new = malloc(sizeof(struct xflow_status_entry_sampling));
    if (!new) {
      if (table->smp_entry_status_table_memerr) {
	Log(LOG_ERR, "ERROR ( %s/%s ): unable to allocate more entries into the xflow renormalization table.\n", config.name, config.type);
	table->smp_entry_status_table_memerr = FALSE;
      }
    }
    else {
      if (!entry->sampling) entry->sampling = new;
      if (sentry) sentry->next = new;
      new->next = FALSE;

      table->smp_entry_status_table_memerr = TRUE;
      table->entries++;
    }
  }

  return new;
}

struct xflow_status_entry_class *
search_class_id_status_table(struct xflow_status_entry_class *centry, pm_class_t class_id)
{
  pm_class_t needle, haystack;

  needle = ntohl(class_id);

  while (centry) {
    haystack = ntohl(centry->class_id);

    if (haystack == needle) return centry;
    centry = centry->next;
  }

  return NULL;
}

struct xflow_status_entry_class *
create_class_entry_status_table(xflow_status_table_t *table, struct xflow_status_entry *entry)
{
  struct xflow_status_entry_class *centry = entry->class, *new = NULL;

  if (centry) {
    while (centry->next) centry = centry->next;
  }

  if (table->entries < XFLOW_STATUS_TABLE_MAX_ENTRIES) {
    new = malloc(sizeof(struct xflow_status_entry_class));
    if (!new) {
      if (table->class_entry_status_table_memerr) {
        Log(LOG_ERR, "ERROR ( %s/%s ): unable to allocate more entries into the xflow classification table.\n", config.name, config.type);
        table->class_entry_status_table_memerr = FALSE;
      }
    }
    else {
      if (!entry->class) entry->class = new;
      if (centry) centry->next = new;
      new->next = FALSE;

      table->class_entry_status_table_memerr = TRUE;
      table->entries++;
    }
  }

  return new;
}

void set_vector_f_status(struct packet_ptrs_vector *pptrsv)
{
  pptrsv->vlan4.f_status = pptrsv->v4.f_status;
  pptrsv->mpls4.f_status = pptrsv->v4.f_status;
  pptrsv->vlanmpls4.f_status = pptrsv->v4.f_status;

  pptrsv->v6.f_status = pptrsv->v4.f_status;
  pptrsv->vlan6.f_status = pptrsv->v4.f_status;
  pptrsv->vlanmpls6.f_status = pptrsv->v4.f_status;
  pptrsv->mpls6.f_status = pptrsv->v4.f_status;
}

void set_vector_f_status_g(struct packet_ptrs_vector *pptrsv)
{
  pptrsv->vlan4.f_status_g = pptrsv->v4.f_status_g;
  pptrsv->mpls4.f_status_g = pptrsv->v4.f_status_g;
  pptrsv->vlanmpls4.f_status_g = pptrsv->v4.f_status_g;

  pptrsv->v6.f_status_g = pptrsv->v4.f_status_g;
  pptrsv->vlan6.f_status_g = pptrsv->v4.f_status_g;
  pptrsv->vlanmpls6.f_status_g = pptrsv->v4.f_status_g;
  pptrsv->mpls6.f_status_g = pptrsv->v4.f_status_g;
}

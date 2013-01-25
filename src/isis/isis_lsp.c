/*
 * IS-IS Rout(e)ing protocol - isis_lsp.c
 *                             LSP processing
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology      
 *                           Institute of Communications Engineering
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public Licenseas published by the Free 
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
 * more details.

 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define __ISIS_LSP_C

#include "pmacct.h"
#include "isis.h"

#include "linklist.h"
#include "thread.h"
#include "stream.h"
#include "prefix.h"
#include "hash.h"

#include "dict.h"
#include "isis_constants.h"
#include "isis_common.h"
#include "isis_circuit.h"
#include "isisd.h"
#include "isis_tlv.h"
#include "isis_lsp.h"
#include "isis_pdu.h"
#include "isis_dynhn.h"
#include "isis_misc.h"
#include "isis_flags.h"
#include "isis_csm.h"
#include "isis_adjacency.h"
#include "isis_spf.h"

#define LSP_MEMORY_PREASSIGN

extern struct isis *isis;

/* staticly assigned vars for printing purposes */
char lsp_bits_string[200];     /* FIXME: enough ? */

int
lsp_id_cmp (u_char * id1, u_char * id2)
{
  return memcmp (id1, id2, ISIS_SYS_ID_LEN + 2);
}

dict_t *
lsp_db_init (void)
{
  dict_t *dict;

  dict = dict_create (DICTCOUNT_T_MAX, (dict_comp_t) lsp_id_cmp);

  return dict;
}

struct isis_lsp *
lsp_search (u_char * id, dict_t * lspdb)
{
  dnode_t *node;

  node = dict_lookup (lspdb, id);

  if (node)
    return (struct isis_lsp *) dnode_get (node);

  return NULL;
}

static void
lsp_clear_data (struct isis_lsp *lsp)
{
  if (!lsp)
    return;

  if (lsp->own_lsp)
    {
      if (lsp->tlv_data.nlpids)
	free(lsp->tlv_data.nlpids);
      if (lsp->tlv_data.hostname)
	free(lsp->tlv_data.hostname);
    }
  if (lsp->tlv_data.is_neighs)
    isis_list_delete (lsp->tlv_data.is_neighs);
  if (lsp->tlv_data.te_is_neighs)
    isis_list_delete (lsp->tlv_data.te_is_neighs);
  if (lsp->tlv_data.area_addrs)
    isis_list_delete (lsp->tlv_data.area_addrs);
  if (lsp->tlv_data.es_neighs)
    isis_list_delete (lsp->tlv_data.es_neighs);
  if (lsp->tlv_data.ipv4_addrs)
    isis_list_delete (lsp->tlv_data.ipv4_addrs);
  if (lsp->tlv_data.ipv4_int_reachs)
    isis_list_delete (lsp->tlv_data.ipv4_int_reachs);
  if (lsp->tlv_data.ipv4_ext_reachs)
    isis_list_delete (lsp->tlv_data.ipv4_ext_reachs);
  if (lsp->tlv_data.te_ipv4_reachs)
    isis_list_delete (lsp->tlv_data.te_ipv4_reachs);
#ifdef ENABLE_IPV6
  if (lsp->tlv_data.ipv6_addrs)
    isis_list_delete (lsp->tlv_data.ipv6_addrs);
  if (lsp->tlv_data.ipv6_reachs)
    isis_list_delete (lsp->tlv_data.ipv6_reachs);
#endif /* ENABLE_IPV6 */

  memset (&lsp->tlv_data, 0, sizeof (struct tlvs));

  return;
}

static void
lsp_destroy (struct isis_lsp *lsp)
{
  if (!lsp)
    return;

  lsp_clear_data (lsp);

  if (LSP_FRAGMENT (lsp->lsp_header->lsp_id) == 0 && lsp->lspu.frags)
    {
      isis_list_delete (lsp->lspu.frags);
    }

  if (lsp->pdu)
    stream_free (lsp->pdu);
  free(lsp);
}

void
lsp_db_destroy (dict_t * lspdb)
{
  dnode_t *dnode, *next;
  struct isis_lsp *lsp;

  dnode = dict_first (lspdb);
  while (dnode)
    {
      next = dict_next (lspdb, dnode);
      lsp = dnode_get (dnode);
      lsp_destroy (lsp);
      dict_delete_free (lspdb, dnode);
      dnode = next;
    }

  dict_free (lspdb);

  return;
}

/*
 * Remove all the frags belonging to the given lsp
 */
static void
lsp_remove_frags (struct list *frags, dict_t * lspdb)
{
  dnode_t *dnode;
  struct listnode *lnode, *lnnode;
  struct isis_lsp *lsp;

  for (ALL_LIST_ELEMENTS (frags, lnode, lnnode, lsp))
    {
      dnode = dict_lookup (lspdb, lsp->lsp_header->lsp_id);
      lsp_destroy (lsp);
      dnode_destroy (dict_delete (lspdb, dnode));
    }

  isis_list_delete_all_node (frags);

  return;
}

void
lsp_search_and_destroy (u_char * id, dict_t * lspdb)
{
  dnode_t *node;
  struct isis_lsp *lsp;

  node = dict_lookup (lspdb, id);
  if (node)
    {
      node = dict_delete (lspdb, node);
      lsp = dnode_get (node);
      /*
       * If this is a zero lsp, remove all the frags now 
       */
      if (LSP_FRAGMENT (lsp->lsp_header->lsp_id) == 0)
	{
	  if (lsp->lspu.frags)
	    lsp_remove_frags (lsp->lspu.frags, lspdb);
	}
      else
	{
	  /* 
	   * else just remove this frag, from the zero lsps' frag list
	   */
	  if (lsp->lspu.zero_lsp && lsp->lspu.zero_lsp->lspu.frags)
	    isis_listnode_delete (lsp->lspu.zero_lsp->lspu.frags, lsp);
	}
      lsp_destroy (lsp);
      dnode_destroy (node);
    }
}

/*
 * Compares a LSP to given values
 * Params are given in net order
 */
int
lsp_compare (char *areatag, struct isis_lsp *lsp, u_int32_t seq_num,
	     u_int16_t checksum, u_int16_t rem_lifetime)
{
  /* no point in double ntohl on seqnum */
  if (lsp->lsp_header->seq_num == seq_num &&
      lsp->lsp_header->checksum == checksum &&
      /*comparing with 0, no need to do ntohl */
      ((lsp->lsp_header->rem_lifetime == 0 && rem_lifetime == 0) ||
       (lsp->lsp_header->rem_lifetime != 0 && rem_lifetime != 0)))
    {
      if (config.nfacctd_isis_msglog)
	{
	  Log(LOG_DEBUG, "DEBUG ( default/core/ISIS ): ISIS-Snp (%s): LSP %s seq 0x%08x, cksum 0x%04x, lifetime %us\n",
		      areatag,
		      rawlspid_print (lsp->lsp_header->lsp_id),
		      ntohl (lsp->lsp_header->seq_num),
		      ntohs (lsp->lsp_header->checksum),
		      ntohs (lsp->lsp_header->rem_lifetime));
	  Log(LOG_DEBUG, "DEBUG ( default/core/ISIS ): ISIS-Snp (%s): is equal to ours seq 0x%08x, cksum 0x%04x, lifetime %us\n",
		      areatag,
		      ntohl (seq_num), ntohs (checksum), ntohs (rem_lifetime));
	}
      return LSP_EQUAL;
    }

  if (ntohl (seq_num) >= ntohl (lsp->lsp_header->seq_num))
    {
      if (config.nfacctd_isis_msglog)
	{
	  Log(LOG_DEBUG, "DEBUG ( default/core/ISIS ): ISIS-Snp (%s): LSP %s seq 0x%08x, cksum 0x%04x, lifetime %us\n",
		      areatag,
		      rawlspid_print (lsp->lsp_header->lsp_id),
		      ntohl (seq_num), ntohs (checksum), ntohs (rem_lifetime));
	  Log(LOG_DEBUG, "DEBUG ( default/core/ISIS ): ISIS-Snp (%s): is newer than ours seq 0x%08x, cksum 0x%04x, lifetime %us\n",
		      areatag,
		      ntohl (lsp->lsp_header->seq_num),
		      ntohs (lsp->lsp_header->checksum),
		      ntohs (lsp->lsp_header->rem_lifetime));
	}
      return LSP_NEWER;
    }
  if (config.nfacctd_isis_msglog)
    {
      Log(LOG_DEBUG, "DEBUG ( default/core/ISIS ): ISIS-Snp (%s): LSP %s seq 0x%08x, cksum 0x%04x, lifetime %us\n",
	 areatag, rawlspid_print (lsp->lsp_header->lsp_id), ntohl (seq_num),
	 ntohs (checksum), ntohs (rem_lifetime));
      Log(LOG_DEBUG, "DEBUG ( default/core/ISIS ): ISIS-Snp (%s): is older than ours seq 0x%08x, cksum 0x%04x, lifetime %us\n", areatag,
		  ntohl (lsp->lsp_header->seq_num),
		  ntohs (lsp->lsp_header->checksum),
		  ntohs (lsp->lsp_header->rem_lifetime));
    }

  return LSP_OLDER;
}

void
lsp_inc_seqnum (struct isis_lsp *lsp, u_int32_t seq_num)
{
  u_int32_t newseq;

  if (seq_num == 0 || ntohl (lsp->lsp_header->seq_num) > seq_num)
    newseq = ntohl (lsp->lsp_header->seq_num) + 1;
  else
    newseq = seq_num++;

  lsp->lsp_header->seq_num = htonl (newseq);
  fletcher_checksum (STREAM_DATA (lsp->pdu) + 12,
		   ntohs (lsp->lsp_header->pdu_len) - 12, 12);

  return;
}

/*
 * Genetates checksum for LSP and its frags
 */
static void
lsp_seqnum_update (struct isis_lsp *lsp0)
{
  struct isis_lsp *lsp;
  struct listnode *node;

  lsp_inc_seqnum (lsp0, 0);

  if (!lsp0->lspu.frags)
    return;

  for (ALL_LIST_ELEMENTS_RO (lsp0->lspu.frags, node, lsp))
    lsp_inc_seqnum (lsp, 0);

  return;
}

int
isis_lsp_authinfo_check (struct stream *stream, struct isis_area *area,
			 int pdulen, struct isis_passwd *passwd)
{
  uint32_t expected = 0, found;
  struct tlvs tlvs;
  int retval = 0;

  expected |= TLVFLAG_AUTH_INFO;
  retval = parse_tlvs (area->area_tag, stream->data +
		       ISIS_FIXED_HDR_LEN + ISIS_LSP_HDR_LEN,
		       pdulen - ISIS_FIXED_HDR_LEN
		       - ISIS_LSP_HDR_LEN, &expected, &found, &tlvs);
  if (retval || !(found & TLVFLAG_AUTH_INFO))
    return 1;			/* Auth fail (parsing failed or no auth-tlv) */

  return authentication_check (passwd, &tlvs.auth_info);
}

static void
lsp_update_data (struct isis_lsp *lsp, struct stream *stream,
		 struct isis_area *area)
{
  uint32_t expected = 0, found;
  int retval;

  /* copying only the relevant part of our stream */
  lsp->pdu = stream_dup (stream);
  
  /* setting pointers to the correct place */
  lsp->isis_header = (struct isis_fixed_hdr *) (STREAM_DATA (lsp->pdu));
  lsp->lsp_header = (struct isis_link_state_hdr *) (STREAM_DATA (lsp->pdu) +
						    ISIS_FIXED_HDR_LEN);
  lsp->age_out = ZERO_AGE_LIFETIME;
  lsp->installed = time (NULL);
  /*
   * Get LSP data i.e. TLVs
   */
  expected |= TLVFLAG_AUTH_INFO;
  expected |= TLVFLAG_AREA_ADDRS;
  expected |= TLVFLAG_IS_NEIGHS;
  if ((lsp->lsp_header->lsp_bits & 3) == 3)	/* a level 2 LSP */
    expected |= TLVFLAG_PARTITION_DESIG_LEVEL2_IS;
  expected |= TLVFLAG_NLPID;
  if (area->dynhostname)
    expected |= TLVFLAG_DYN_HOSTNAME;
  if (area->newmetric)
    {
      expected |= TLVFLAG_TE_IS_NEIGHS;
      expected |= TLVFLAG_TE_IPV4_REACHABILITY;
      expected |= TLVFLAG_TE_ROUTER_ID;
    }
  expected |= TLVFLAG_IPV4_ADDR;
  expected |= TLVFLAG_IPV4_INT_REACHABILITY;
  expected |= TLVFLAG_IPV4_EXT_REACHABILITY;
#ifdef ENABLE_IPV6
  expected |= TLVFLAG_IPV6_ADDR;
  expected |= TLVFLAG_IPV6_REACHABILITY;
#endif /* ENABLE_IPV6 */

  retval = parse_tlvs (area->area_tag, lsp->pdu->data +
		       ISIS_FIXED_HDR_LEN + ISIS_LSP_HDR_LEN,
		       ntohs (lsp->lsp_header->pdu_len) - ISIS_FIXED_HDR_LEN
		       - ISIS_LSP_HDR_LEN, &expected, &found, &lsp->tlv_data);

  if (found & TLVFLAG_DYN_HOSTNAME)
    {
      if (area->dynhostname)
	isis_dynhn_insert (lsp->lsp_header->lsp_id, lsp->tlv_data.hostname,
			   (lsp->lsp_header->lsp_bits & LSPBIT_IST) ==
			   IS_LEVEL_1_AND_2 ? IS_LEVEL_2 :
			   (lsp->lsp_header->lsp_bits & LSPBIT_IST));
    }

}

void
lsp_update (struct isis_lsp *lsp, struct isis_link_state_hdr *lsp_hdr,
	    struct stream *stream, struct isis_area *area, int level)
{
  dnode_t *dnode = NULL;

  /* Remove old LSP from LSP database. */
  dnode = dict_lookup (area->lspdb[level - 1], lsp->lsp_header->lsp_id);
  if (dnode)
    dnode_destroy (dict_delete (area->lspdb[level - 1], dnode));

  /* free the old lsp data */
  free(lsp->pdu);
  lsp_clear_data (lsp);

  /* rebuild the lsp data */
  lsp_update_data (lsp, stream, area);

  /* set the new values for lsp header */
  memcpy (lsp->lsp_header, lsp_hdr, ISIS_LSP_HDR_LEN);

  if (dnode)
    lsp_insert (lsp, area->lspdb[level - 1]);
}

/* creation of LSP directly from what we received */
struct isis_lsp *
lsp_new_from_stream_ptr (struct stream *stream,
			 u_int16_t pdu_len, struct isis_lsp *lsp0,
			 struct isis_area *area)
{
  struct isis_lsp *lsp;

  lsp = calloc(1, sizeof (struct isis_lsp));
  lsp_update_data (lsp, stream, area);

  if (lsp0 == NULL)
    {
      /*
       * zero lsp -> create the list for fragments
       */
      lsp->lspu.frags = isis_list_new ();
    }
  else
    {
      /*
       * a fragment -> set the backpointer and add this to zero lsps frag list
       */
      lsp->lspu.zero_lsp = lsp0;
      isis_listnode_add (lsp0->lspu.frags, lsp);
    }

  return lsp;
}

struct isis_lsp *
lsp_new (u_char * lsp_id, u_int16_t rem_lifetime, u_int32_t seq_num,
	 u_int8_t lsp_bits, u_int16_t checksum, int level)
{
  struct isis_lsp *lsp;

  lsp = calloc(1, sizeof (struct isis_lsp));
  if (!lsp)
    {
      /* FIXME: set lspdbol bit */
      Log(LOG_WARNING, "WARN ( default/core/ISIS ): lsp_new(): out of memory\n");
      return NULL;
    }
#ifdef LSP_MEMORY_PREASSIGN
  lsp->pdu = stream_new (1514);	/*Should be minimal mtu? yup... */
#else
  /* We need to do realloc on TLVs additions */
  lsp->pdu = calloc(1, ISIS_FIXED_HDR_LEN + ISIS_LSP_HDR_LEN);
#endif /* LSP_MEMORY_PREASSIGN */
  if (LSP_FRAGMENT (lsp_id) == 0)
    lsp->lspu.frags = isis_list_new ();
  lsp->isis_header = (struct isis_fixed_hdr *) (STREAM_DATA (lsp->pdu));
  lsp->lsp_header = (struct isis_link_state_hdr *)
    (STREAM_DATA (lsp->pdu) + ISIS_FIXED_HDR_LEN);

  /* at first we fill the FIXED HEADER */
  (level == 1) ? fill_fixed_hdr (lsp->isis_header, L1_LINK_STATE) :
    fill_fixed_hdr (lsp->isis_header, L2_LINK_STATE);

  /* now for the LSP HEADER */
  /* Minimal LSP PDU size */
  lsp->lsp_header->pdu_len = htons (ISIS_FIXED_HDR_LEN + ISIS_LSP_HDR_LEN);
  memcpy (lsp->lsp_header->lsp_id, lsp_id, ISIS_SYS_ID_LEN + 2);
  lsp->lsp_header->checksum = checksum;	/* Provided in network order */
  lsp->lsp_header->seq_num = htonl (seq_num);
  lsp->lsp_header->rem_lifetime = htons (rem_lifetime);
  lsp->lsp_header->lsp_bits = lsp_bits;
  lsp->level = level;
  lsp->age_out = ZERO_AGE_LIFETIME;

  stream_forward_endp (lsp->pdu, ISIS_FIXED_HDR_LEN + ISIS_LSP_HDR_LEN);

  if (config.nfacctd_isis_msglog)
    Log(LOG_DEBUG, "DEBUG ( default/core/ISIS ): New LSP with ID %s-%02x-%02x seqnum %08x\n",
		sysid_print (lsp_id), LSP_PSEUDO_ID (lsp->lsp_header->lsp_id),
		LSP_FRAGMENT (lsp->lsp_header->lsp_id),
		ntohl (lsp->lsp_header->seq_num));

  return lsp;
}

void
lsp_insert (struct isis_lsp *lsp, dict_t * lspdb)
{
  dict_alloc_insert (lspdb, lsp->lsp_header->lsp_id, lsp);
}
/*
 * Build a list of LSPs with non-zero ht bounded by start and stop ids
 */
void
lsp_build_isis_list_nonzero_ht (u_char * start_id, u_char * stop_id,
			   struct list *list, dict_t * lspdb)
{
  dnode_t *first, *last, *curr;

  first = dict_lower_bound (lspdb, start_id);
  if (!first)
    return;

  last = dict_upper_bound (lspdb, stop_id);

  curr = first;

  if (((struct isis_lsp *) (curr->dict_data))->lsp_header->rem_lifetime)
    isis_listnode_add (list, first->dict_data);

  while (curr)
    {
      curr = dict_next (lspdb, curr);
      if (curr &&
	  ((struct isis_lsp *) (curr->dict_data))->lsp_header->rem_lifetime)
	isis_listnode_add (list, curr->dict_data);
      if (curr == last)
	break;
    }

  return;
}

/*
 * Build a list of all LSPs bounded by start and stop ids
 */
void
lsp_build_list (u_char * start_id, u_char * stop_id,
		struct list *list, dict_t * lspdb)
{
  dnode_t *first, *last, *curr;

  first = dict_lower_bound (lspdb, start_id);
  if (!first)
    return;

  last = dict_upper_bound (lspdb, stop_id);

  curr = first;

  isis_listnode_add (list, first->dict_data);

  while (curr)
    {
      curr = dict_next (lspdb, curr);
      if (curr)
	isis_listnode_add (list, curr->dict_data);
      if (curr == last)
	break;
    }

  return;
}

/*
 * Build a list of LSPs with SSN flag set for the given circuit
 */
void
lsp_build_isis_list_ssn (struct isis_circuit *circuit, struct list *list,
		    dict_t * lspdb)
{
  dnode_t *dnode, *next;
  struct isis_lsp *lsp;

  dnode = dict_first (lspdb);
  while (dnode != NULL)
    {
      next = dict_next (lspdb, dnode);
      lsp = dnode_get (dnode);
      if (ISIS_CHECK_FLAG (lsp->SSNflags, circuit))
	isis_listnode_add (list, lsp);
      dnode = next;
    }

  return;
}

static void
lsp_set_time (struct isis_lsp *lsp)
{
  assert (lsp);

  if (lsp->lsp_header->rem_lifetime == 0)
    {
      if (lsp->age_out != 0)
	lsp->age_out--;
      return;
    }

  /* If we are turning 0 */
  /* ISO 10589 - 7.3.16.4 first paragraph */

  if (ntohs (lsp->lsp_header->rem_lifetime) == 1)
    {
      /* 7.3.16.4 a) set SRM flags on all */
      ISIS_FLAGS_SET_ALL (lsp->SRMflags);
      /* 7.3.16.4 b) retain only the header FIXME  */
      /* 7.3.16.4 c) record the time to purge FIXME (other way to do it) */
    }

  lsp->lsp_header->rem_lifetime =
    htons (ntohs (lsp->lsp_header->rem_lifetime) - 1);
}

/* Convert the lsp attribute bits to attribute string */
const char *
lsp_bits2string (u_char * lsp_bits)
{
  char *pos = lsp_bits_string;

  if (!*lsp_bits)
    return " none";

  /* we only focus on the default metric */
  pos += sprintf (pos, "%d/",
		  ISIS_MASK_LSP_ATT_DEFAULT_BIT (*lsp_bits) ? 1 : 0);

  pos += sprintf (pos, "%d/",
		  ISIS_MASK_LSP_PARTITION_BIT (*lsp_bits) ? 1 : 0);

  pos += sprintf (pos, "%d", ISIS_MASK_LSP_OL_BIT (*lsp_bits) ? 1 : 0);

  *(pos) = '\0';

  return lsp_bits_string;
}

#define FRAG_THOLD(S,T) \
((STREAM_SIZE(S)*T)/100)

/* stream*, area->lsp_frag_threshold, increment */
#define FRAG_NEEDED(S,T,I) \
  (STREAM_SIZE(S)-STREAM_REMAIN(S)+(I) > FRAG_THOLD(S,T))

/* FIXME: It shouldn't be necessary to pass tlvsize here, TLVs can have
 * variable length (TE TLVs, sub TLVs). */
static void
lsp_tlv_fit (struct isis_lsp *lsp, struct list **from, struct list **to,
	     int tlvsize, int frag_thold,
	     int tlv_build_func (struct list *, struct stream *))
{
  int count, i;

  /* can we fit all ? */
  if (!FRAG_NEEDED (lsp->pdu, frag_thold, listcount (*from) * tlvsize + 2))
    {
      tlv_build_func (*from, lsp->pdu);
      *to = *from;
      *from = NULL;
    }
  else if (!FRAG_NEEDED (lsp->pdu, frag_thold, tlvsize + 2))
    {
      /* fit all we can */
      count = FRAG_THOLD (lsp->pdu, frag_thold) - 2 -
	(STREAM_SIZE (lsp->pdu) - STREAM_REMAIN (lsp->pdu));
      if (count)
	count = count / tlvsize;
      for (i = 0; i < count; i++)
	{
	  isis_listnode_add (*to, listgetdata (listhead (*from)));
	  isis_listnode_delete (*from, listgetdata (listhead (*from)));
	}
      tlv_build_func (*to, lsp->pdu);
    }
  lsp->lsp_header->pdu_len = htons (stream_get_endp (lsp->pdu));
  return;
}

static struct isis_lsp *
lsp_next_frag (u_char frag_num, struct isis_lsp *lsp0, struct isis_area *area,
	       int level)
{
  struct isis_lsp *lsp;
  u_char frag_id[ISIS_SYS_ID_LEN + 2];

  memcpy (frag_id, lsp0->lsp_header->lsp_id, ISIS_SYS_ID_LEN + 1);
  LSP_FRAGMENT (frag_id) = frag_num;
  lsp = lsp_search (frag_id, area->lspdb[level - 1]);
  if (lsp)
    {
      /*
       * Clear the TLVs, but inherit the authinfo
       */
      lsp_clear_data (lsp);
      if (lsp0->tlv_data.auth_info.type)
	{
	  memcpy (&lsp->tlv_data.auth_info, &lsp->tlv_data.auth_info,
		  sizeof (struct isis_passwd));
	  tlv_add_authinfo (lsp->tlv_data.auth_info.type,
			    lsp->tlv_data.auth_info.len,
			    lsp->tlv_data.auth_info.passwd, lsp->pdu);
	}
      return lsp;
    }
  lsp = lsp_new (frag_id, area->max_lsp_lifetime[level - 1], 0, area->is_type,
		 0, level);
  lsp->own_lsp = 1;
  lsp_insert (lsp, area->lspdb[level - 1]);
  isis_listnode_add (lsp0->lspu.frags, lsp);
  lsp->lspu.zero_lsp = lsp0;
  /*
   * Copy the authinfo from zero LSP
   */
  if (lsp0->tlv_data.auth_info.type)
    {
      memcpy (&lsp->tlv_data.auth_info, &lsp->tlv_data.auth_info,
	      sizeof (struct isis_passwd));
      tlv_add_authinfo (lsp->tlv_data.auth_info.type,
			lsp->tlv_data.auth_info.len,
			lsp->tlv_data.auth_info.passwd, lsp->pdu);
    }
  return lsp;
}

/*
 * Builds the LSP data part. This func creates a new frag whenever 
 * area->lsp_frag_threshold is exceeded.
 */
static void
lsp_build_nonpseudo (struct isis_lsp *lsp, struct isis_area *area)
{
  struct is_neigh *is_neigh;
  struct te_is_neigh *te_is_neigh;
  struct listnode *node, *ipnode;
  int level = lsp->level;
  struct isis_circuit *circuit;
  struct prefix_ipv4 *ipv4;
  struct ipv4_reachability *ipreach;
  struct te_ipv4_reachability *te_ipreach;
  struct isis_adjacency *nei;
#ifdef ENABLE_IPV6
  struct prefix_ipv6 *ipv6, *ip6prefix;
  struct ipv6_reachability *ip6reach;
#endif /* ENABLE_IPV6 */
  struct tlvs tlv_data;
  struct isis_lsp *lsp0 = lsp;
  struct isis_passwd *passwd;
  struct in_addr *routerid;

  /*
   * First add the tlvs related to area
   */

  /* Area addresses */
  if (lsp->tlv_data.area_addrs == NULL)
    lsp->tlv_data.area_addrs = isis_list_new ();
  isis_list_add_list (lsp->tlv_data.area_addrs, area->area_addrs);
  /* Protocols Supported */
  if (area->ip_circuits > 0
#ifdef ENABLE_IPV6
      || area->ipv6_circuits > 0
#endif /* ENABLE_IPV6 */
    )
    {
      lsp->tlv_data.nlpids = calloc(1, sizeof (struct nlpids));
      lsp->tlv_data.nlpids->count = 0;
      if (area->ip_circuits > 0)
	{
	  lsp->tlv_data.nlpids->count++;
	  lsp->tlv_data.nlpids->nlpids[0] = NLPID_IP;
	}
#ifdef ENABLE_IPV6
      if (area->ipv6_circuits > 0)
	{
	  lsp->tlv_data.nlpids->count++;
	  lsp->tlv_data.nlpids->nlpids[lsp->tlv_data.nlpids->count - 1] =
	    NLPID_IPV6;
	}
#endif /* ENABLE_IPV6 */
    }
  /* XXX: Dynamic Hostname */
/*
  if (area->dynhostname)
    {
      lsp->tlv_data.hostname = calloc(1, sizeof (struct hostname));

      memcpy (lsp->tlv_data.hostname->name, unix_hostname (),
	      strlen (unix_hostname ()));
      lsp->tlv_data.hostname->namelen = strlen (unix_hostname ());
    }
*/

  /*
   * Building the zero lsp
   */

  /* Reset stream endp. Stream is always there and on every LSP refresh only
   * TLV part of it is overwritten. So we must seek past header we will not
   * touch. */
  stream_reset (lsp->pdu);
  stream_forward_endp (lsp->pdu, ISIS_FIXED_HDR_LEN + ISIS_LSP_HDR_LEN);

  /*
   * Add the authentication info if its present
   */
  (level == 1) ? (passwd = &area->area_passwd) :
    (passwd = &area->domain_passwd);
  if (passwd->type)
    {
      memcpy (&lsp->tlv_data.auth_info, passwd, sizeof (struct isis_passwd));
      tlv_add_authinfo (passwd->type, passwd->len, passwd->passwd, lsp->pdu);
    }
  if (lsp->tlv_data.nlpids)
    tlv_add_nlpid (lsp->tlv_data.nlpids, lsp->pdu);
  if (lsp->tlv_data.hostname)
    tlv_add_dynamic_hostname (lsp->tlv_data.hostname, lsp->pdu);
  if (lsp->tlv_data.area_addrs && listcount (lsp->tlv_data.area_addrs) > 0)
    tlv_add_area_addrs (lsp->tlv_data.area_addrs, lsp->pdu);

  /* IPv4 address and TE router ID TLVs. In case of the first one we don't
   * follow "C" vendor, but "J" vendor behavior - one IPv4 address is put into
   * LSP and this address is same as router id. */
  if (router_id_zebra.s_addr != 0)
    {
      if (lsp->tlv_data.ipv4_addrs == NULL)
	{
	  lsp->tlv_data.ipv4_addrs = isis_list_new ();
	  lsp->tlv_data.ipv4_addrs->del = free_tlv;
	}

      routerid = calloc(1, sizeof (struct in_addr));
      routerid->s_addr = router_id_zebra.s_addr;
      isis_listnode_add (lsp->tlv_data.ipv4_addrs, routerid);
      tlv_add_in_addr (routerid, lsp->pdu, IPV4_ADDR);

      /* Exactly same data is put into TE router ID TLV, but only if new style
       * TLV's are in use. */
      if (area->newmetric)
	{
	  lsp->tlv_data.router_id = calloc(1, sizeof (struct in_addr));
	  lsp->tlv_data.router_id->id.s_addr = router_id_zebra.s_addr;
	  tlv_add_in_addr (&lsp->tlv_data.router_id->id, lsp->pdu, TE_ROUTER_ID);
	}
    }

  memset (&tlv_data, 0, sizeof (struct tlvs));

  /*
   * Then build lists of tlvs related to circuits
   */
  for (ALL_LIST_ELEMENTS_RO (area->circuit_list, node, circuit))
    {
      if (circuit->state != C_STATE_UP)
	continue;

      /*
       * Add IPv4 internal reachability of this circuit
       */
      if (circuit->ip_router && circuit->ip_addrs &&
	  circuit->ip_addrs->count > 0)
	{
	  if (area->oldmetric)
	    {
	      if (tlv_data.ipv4_int_reachs == NULL)
		{
		  tlv_data.ipv4_int_reachs = isis_list_new ();
		  tlv_data.ipv4_int_reachs->del = free_tlv;
		}
	      for (ALL_LIST_ELEMENTS_RO (circuit->ip_addrs, ipnode, ipv4))
		{
		  ipreach = calloc(1, sizeof (struct ipv4_reachability));
		  ipreach->metrics = circuit->metrics[level - 1];
		  isis_masklen2ip (ipv4->prefixlen, &ipreach->mask);
		  ipreach->prefix.s_addr = ((ipreach->mask.s_addr) &
					    (ipv4->prefix.s_addr));
		  isis_listnode_add (tlv_data.ipv4_int_reachs, ipreach);
		}
	      tlv_data.ipv4_int_reachs->del = free_tlv;
	    }
	  if (area->newmetric)
	    {
	      if (tlv_data.te_ipv4_reachs == NULL)
		{
		  tlv_data.te_ipv4_reachs = isis_list_new ();
		  tlv_data.te_ipv4_reachs->del = free_tlv;
		}
	      for (ALL_LIST_ELEMENTS_RO (circuit->ip_addrs, ipnode, ipv4))
		{
		  /* FIXME All this assumes that we have no sub TLVs. */
		  te_ipreach = calloc(1, sizeof (struct te_ipv4_reachability) +
					((ipv4->prefixlen + 7)/8) - 1);

		  if (area->oldmetric)
		    te_ipreach->te_metric = htonl (circuit->metrics[level - 1].metric_default);
		  else
		    te_ipreach->te_metric = htonl (circuit->te_metric[level - 1]);

		  te_ipreach->control = (ipv4->prefixlen & 0x3F);
		  memcpy (&te_ipreach->prefix_start, &ipv4->prefix.s_addr,
			  (ipv4->prefixlen + 7)/8);
		  isis_listnode_add (tlv_data.te_ipv4_reachs, te_ipreach);
		}
	    }
	}
#ifdef ENABLE_IPV6
      /*
       * Add IPv6 reachability of this circuit
       */
      if (circuit->ipv6_router && circuit->ipv6_non_link &&
	  circuit->ipv6_non_link->count > 0)
	{

	  if (tlv_data.ipv6_reachs == NULL)
	    {
	      tlv_data.ipv6_reachs = isis_list_new ();
	      tlv_data.ipv6_reachs->del = free_tlv;
	    }
          for (ALL_LIST_ELEMENTS_RO (circuit->ipv6_non_link, ipnode, ipv6))
	    {
	      ip6reach = calloc(1, sizeof (struct ipv6_reachability));

	      if (area->oldmetric)
		ip6reach->metric =
			  htonl (circuit->metrics[level - 1].metric_default);
	      else
		  ip6reach->metric = htonl (circuit->te_metric[level - 1]);

	      ip6reach->control_info = 0;
	      ip6reach->prefix_len = ipv6->prefixlen;
	      memcpy (&ip6prefix, &ipv6, sizeof(ip6prefix));
	      isis_apply_mask_ipv6 (ip6prefix);
	      memcpy (ip6reach->prefix, ip6prefix->prefix.s6_addr,
		      sizeof (ip6reach->prefix));
	      isis_listnode_add (tlv_data.ipv6_reachs, ip6reach);
	    }
	}
#endif /* ENABLE_IPV6 */

      switch (circuit->circ_type)
	{
	case CIRCUIT_T_BROADCAST:
	  if (level & circuit->circuit_is_type)
	    {
	      if (area->oldmetric)
		{
		  if (tlv_data.is_neighs == NULL)
		    {
		      tlv_data.is_neighs = isis_list_new ();
		      tlv_data.is_neighs->del = free_tlv;
		    }
		  is_neigh = calloc(1, sizeof (struct is_neigh));
		  if (level == 1)
		    memcpy (is_neigh->neigh_id,
			    circuit->u.bc.l1_desig_is, ISIS_SYS_ID_LEN + 1);
		  else
		    memcpy (is_neigh->neigh_id,
			    circuit->u.bc.l2_desig_is, ISIS_SYS_ID_LEN + 1);
		  is_neigh->metrics = circuit->metrics[level - 1];
		  isis_listnode_add (tlv_data.is_neighs, is_neigh);
		  tlv_data.is_neighs->del = free_tlv;
		}
	      if (area->newmetric)
		{
		  uint32_t metric;

		  if (tlv_data.te_is_neighs == NULL)
		    {
		      tlv_data.te_is_neighs = isis_list_new ();
		      tlv_data.te_is_neighs->del = free_tlv;
		    }
		  te_is_neigh = calloc(1, sizeof (struct te_is_neigh));
		  if (level == 1)
		    memcpy (te_is_neigh->neigh_id,
			    circuit->u.bc.l1_desig_is, ISIS_SYS_ID_LEN + 1);
		  else
		    memcpy (te_is_neigh->neigh_id,
			    circuit->u.bc.l2_desig_is, ISIS_SYS_ID_LEN + 1);
		  if (area->oldmetric)
		    metric =
		      ((htonl(circuit->metrics[level - 1].metric_default) >> 8)
			      & 0xffffff);
		  else
		    metric = ((htonl(*circuit->te_metric) >> 8) & 0xffffff);

		  memcpy (te_is_neigh->te_metric, &metric, 3);
		  isis_listnode_add (tlv_data.te_is_neighs, te_is_neigh);
		}
	    }
	  break;
	case CIRCUIT_T_P2P:
	  nei = circuit->u.p2p.neighbor;
	  if (nei && (level & nei->circuit_t))
	    {
	      if (area->oldmetric)
		{
		  if (tlv_data.is_neighs == NULL)
		    {
		      tlv_data.is_neighs = isis_list_new ();
		      tlv_data.is_neighs->del = free_tlv;
		    }
		  is_neigh = calloc(1, sizeof (struct is_neigh));
		  memcpy (is_neigh->neigh_id, nei->sysid, ISIS_SYS_ID_LEN);
		  is_neigh->metrics = circuit->metrics[level - 1];
		  isis_listnode_add (tlv_data.is_neighs, is_neigh);
		}
	      if (area->newmetric)
		{
		  uint32_t metric;

		  if (tlv_data.te_is_neighs == NULL)
		    {
		      tlv_data.te_is_neighs = isis_list_new ();
		      tlv_data.te_is_neighs->del = free_tlv;
		    }
		  te_is_neigh = calloc(1, sizeof (struct te_is_neigh));
		  memcpy (te_is_neigh->neigh_id, nei->sysid, ISIS_SYS_ID_LEN);
		  metric = ((htonl(*circuit->te_metric) >> 8) & 0xffffff);
		  memcpy (te_is_neigh->te_metric, &metric, 3);
		  isis_listnode_add (tlv_data.te_is_neighs, te_is_neigh);
		}
	    }
	  break;
	case CIRCUIT_T_STATIC_IN:
	  Log(LOG_WARNING, "WARN ( default/core/ISIS ): lsp_area_create: unsupported circuit type\n");
	  break;
	case CIRCUIT_T_STATIC_OUT:
	  Log(LOG_WARNING, "WARN ( default/core/ISIS ): lsp_area_create: unsupported circuit type\n");
	  break;
	case CIRCUIT_T_DA:
	  Log(LOG_WARNING, "WARN ( default/core/ISIS ): lsp_area_create: unsupported circuit type\n");
	  break;
	default:
	  Log(LOG_WARNING, "WARN ( default/core/ISIS ): lsp_area_create: unknown circuit type\n");
	}
    }

  while (tlv_data.ipv4_int_reachs && listcount (tlv_data.ipv4_int_reachs))
    {
      if (lsp->tlv_data.ipv4_int_reachs == NULL)
	lsp->tlv_data.ipv4_int_reachs = isis_list_new ();
      lsp_tlv_fit (lsp, &tlv_data.ipv4_int_reachs,
		   &lsp->tlv_data.ipv4_int_reachs,
		   IPV4_REACH_LEN, area->lsp_frag_threshold,
		   tlv_add_ipv4_reachs);
      if (tlv_data.ipv4_int_reachs && listcount (tlv_data.ipv4_int_reachs))
	lsp = lsp_next_frag (LSP_FRAGMENT (lsp->lsp_header->lsp_id) + 1,
			     lsp0, area, level);
    }
  /* FIXME: We pass maximum te_ipv4_reachability length to the lsp_tlv_fit()
   * for now. lsp_tlv_fit() needs to be fixed to deal with variable length
   * TLVs (sub TLVs!). */
  while (tlv_data.te_ipv4_reachs && listcount (tlv_data.te_ipv4_reachs))
    {
      if (lsp->tlv_data.te_ipv4_reachs == NULL)
	lsp->tlv_data.te_ipv4_reachs = isis_list_new ();
      lsp_tlv_fit (lsp, &tlv_data.te_ipv4_reachs,
		   &lsp->tlv_data.te_ipv4_reachs,
		   9, area->lsp_frag_threshold, tlv_add_te_ipv4_reachs);
      if (tlv_data.te_ipv4_reachs && listcount (tlv_data.te_ipv4_reachs))
	lsp = lsp_next_frag (LSP_FRAGMENT (lsp->lsp_header->lsp_id) + 1,
			     lsp0, area, level);
    }

#ifdef  ENABLE_IPV6
  while (tlv_data.ipv6_reachs && listcount (tlv_data.ipv6_reachs))
    {
      if (lsp->tlv_data.ipv6_reachs == NULL)
	lsp->tlv_data.ipv6_reachs = isis_list_new ();
      lsp_tlv_fit (lsp, &tlv_data.ipv6_reachs,
		   &lsp->tlv_data.ipv6_reachs,
		   IPV6_REACH_LEN, area->lsp_frag_threshold,
		   tlv_add_ipv6_reachs);
      if (tlv_data.ipv6_reachs && listcount (tlv_data.ipv6_reachs))
	lsp = lsp_next_frag (LSP_FRAGMENT (lsp->lsp_header->lsp_id) + 1,
			     lsp0, area, level);
    }
#endif /* ENABLE_IPV6 */

  while (tlv_data.is_neighs && listcount (tlv_data.is_neighs))
    {
      if (lsp->tlv_data.is_neighs == NULL)
	lsp->tlv_data.is_neighs = isis_list_new ();
      lsp_tlv_fit (lsp, &tlv_data.is_neighs,
		   &lsp->tlv_data.is_neighs,
		   IS_NEIGHBOURS_LEN, area->lsp_frag_threshold,
		   tlv_add_is_neighs);
      if (tlv_data.is_neighs && listcount (tlv_data.is_neighs))
	lsp = lsp_next_frag (LSP_FRAGMENT (lsp->lsp_header->lsp_id) + 1,
			     lsp0, area, level);
    }

  while (tlv_data.te_is_neighs && listcount (tlv_data.te_is_neighs))
    {
      if (lsp->tlv_data.te_is_neighs == NULL)
	lsp->tlv_data.te_is_neighs = isis_list_new ();
      lsp_tlv_fit (lsp, &tlv_data.te_is_neighs, &lsp->tlv_data.te_is_neighs,
		   IS_NEIGHBOURS_LEN, area->lsp_frag_threshold,
		   tlv_add_te_is_neighs);
      if (tlv_data.te_is_neighs && listcount (tlv_data.te_is_neighs))
	lsp = lsp_next_frag (LSP_FRAGMENT (lsp->lsp_header->lsp_id) + 1,
			     lsp0, area, level);
    }

  free_tlvs (&tlv_data);
  return;
}

/*
 * 7.3.7 Generation on non-pseudonode LSPs
 */
static int
lsp_generate_non_pseudo (struct isis_area *area, int level)
{
  struct isis_lsp *oldlsp, *newlsp;
  u_int32_t seq_num = 0;
  u_char lspid[ISIS_SYS_ID_LEN + 2];

  memset (&lspid, 0, ISIS_SYS_ID_LEN + 2);
  memcpy (&lspid, isis->sysid, ISIS_SYS_ID_LEN);

  /* only builds the lsp if the area shares the level */
  if ((area->is_type & level) == level)
    {
      oldlsp = lsp_search (lspid, area->lspdb[level - 1]);
      if (oldlsp)
	{
	  seq_num = ntohl (oldlsp->lsp_header->seq_num);
	  lsp_search_and_destroy (oldlsp->lsp_header->lsp_id,
				  area->lspdb[level - 1]);
	  /* FIXME: we should actually initiate a purge */
	}
      newlsp = lsp_new (lspid, area->max_lsp_lifetime[level - 1], seq_num,
			area->is_type, 0, level);
      newlsp->own_lsp = 1;

      lsp_insert (newlsp, area->lspdb[level - 1]);
      /* build_lsp_data (newlsp, area); */
      lsp_build_nonpseudo (newlsp, area);
      /* time to calculate our checksum */
      lsp_seqnum_update (newlsp);
    }

  /* DEBUG_ADJ_PACKETS */
  if (config.nfacctd_isis_msglog)
    {
      /* FIXME: is this place right? fix missing info */
      Log(LOG_DEBUG, "DEBUG ( default/core/ISIS ): ISIS-Upd (%s): Building L%d LSP\n", area->area_tag, level);
    }

  return ISIS_OK;
}

/*
 * 7.3.9 Generation of level 1 LSPs (non-pseudonode)
 */
int
lsp_l1_generate (struct isis_area *area)
{
  THREAD_TIMER_ON (master, area->t_lsp_refresh[0], lsp_refresh_l1, area,
		   MAX_LSP_GEN_INTERVAL);

  return lsp_generate_non_pseudo (area, 1);
}

/*
 * 7.3.9 Generation of level 2 LSPs (non-pseudonode)
 */
int
lsp_l2_generate (struct isis_area *area)
{
  THREAD_TIMER_ON (master, area->t_lsp_refresh[1], lsp_refresh_l2, area,
		   MAX_LSP_GEN_INTERVAL);

  return lsp_generate_non_pseudo (area, 2);
}

static int
lsp_non_pseudo_regenerate (struct isis_area *area, int level)
{
  dict_t *lspdb = area->lspdb[level - 1];
  struct isis_lsp *lsp, *frag;
  struct listnode *node;
  u_char lspid[ISIS_SYS_ID_LEN + 2];

  memset (lspid, 0, ISIS_SYS_ID_LEN + 2);
  memcpy (lspid, isis->sysid, ISIS_SYS_ID_LEN);

  lsp = lsp_search (lspid, lspdb);

  if (!lsp)
    {
      Log(LOG_ERR, "ERROR ( default/core/ISIS ): ISIS-Upd (%s): lsp_non_pseudo_regenerate(): no L%d LSP found!\n",
	 area->area_tag, level);

      return ISIS_ERROR;
    }

  lsp_clear_data (lsp);
  lsp_build_nonpseudo (lsp, area);
  lsp->lsp_header->rem_lifetime = htons (isis_jitter
					 (area->max_lsp_lifetime[level - 1],
					  MAX_AGE_JITTER));
  lsp_seqnum_update (lsp);

  if (config.nfacctd_isis_msglog)
    {
      Log(LOG_DEBUG, "DEBUG ( default/core/ISIS ): ISIS-Upd (%s): refreshing our L%d LSP %s, seq 0x%08x, cksum 0x%04x lifetime %us\n",
		  area->area_tag,
		  level,
		  rawlspid_print (lsp->lsp_header->lsp_id),
		  ntohl (lsp->lsp_header->seq_num),
		  ntohs (lsp->lsp_header->checksum),
		  ntohs (lsp->lsp_header->rem_lifetime));
    }

  lsp->last_generated = time (NULL);
  area->lsp_regenerate_pending[level - 1] = 0;
  ISIS_FLAGS_SET_ALL (lsp->SRMflags);
  for (ALL_LIST_ELEMENTS_RO (lsp->lspu.frags, node, frag))
    {
      frag->lsp_header->rem_lifetime = htons (isis_jitter
					      (area->
					       max_lsp_lifetime[level - 1],
					       MAX_AGE_JITTER));
      ISIS_FLAGS_SET_ALL (frag->SRMflags);
    }

  if (area->ip_circuits)
    isis_spf_schedule (area, level);
#ifdef ENABLE_IPV6
  if (area->ipv6_circuits)
    isis_spf_schedule6 (area, level);
#endif
  return ISIS_OK;
}

/*
 * Done at least every MAX_LSP_GEN_INTERVAL. Search own LSPs, update holding
 * time and set SRM
 */
int
lsp_refresh_l1 (struct thread *thread)
{
  struct isis_area *area;
  unsigned long ref_time;

  area = THREAD_ARG (thread);
  assert (area);

  area->t_lsp_refresh[0] = NULL;
  if (area->is_type & IS_LEVEL_1)
    lsp_non_pseudo_regenerate (area, 1);

  ref_time = area->lsp_refresh[0] > MAX_LSP_GEN_INTERVAL ?
    MAX_LSP_GEN_INTERVAL : area->lsp_refresh[0];

  THREAD_TIMER_ON (master, area->t_lsp_refresh[0], lsp_refresh_l1, area,
		   isis_jitter (ref_time, MAX_AGE_JITTER));

  return ISIS_OK;
}

int
lsp_refresh_l2 (struct thread *thread)
{
  struct isis_area *area;
  unsigned long ref_time;

  area = THREAD_ARG (thread);
  assert (area);

  area->t_lsp_refresh[1] = NULL;
  if (area->is_type & IS_LEVEL_2)
    lsp_non_pseudo_regenerate (area, 2);

  ref_time = area->lsp_refresh[1] > MAX_LSP_GEN_INTERVAL ?
    MAX_LSP_GEN_INTERVAL : area->lsp_refresh[1];

  THREAD_TIMER_ON (master, area->t_lsp_refresh[1], lsp_refresh_l2, area,
		   isis_jitter (ref_time, MAX_AGE_JITTER));

  return ISIS_OK;
}

/*
 * Something has changed -> regenerate LSP
 */

static int
lsp_l1_regenerate (struct thread *thread)
{
  struct isis_area *area;

  area = THREAD_ARG (thread);
  area->lsp_regenerate_pending[0] = 0;

  return lsp_non_pseudo_regenerate (area, 1);
}

static int
lsp_l2_regenerate (struct thread *thread)
{
  struct isis_area *area;

  area = THREAD_ARG (thread);
  area->lsp_regenerate_pending[1] = 0;

  return lsp_non_pseudo_regenerate (area, 2);
}

int
lsp_regenerate_schedule (struct isis_area *area)
{
  struct isis_lsp *lsp;
  u_char id[ISIS_SYS_ID_LEN + 2];
  time_t now, diff;
  memcpy (id, isis->sysid, ISIS_SYS_ID_LEN);
  LSP_PSEUDO_ID (id) = LSP_FRAGMENT (id) = 0;
  now = time (NULL);
  /*
   * First level 1
   */
  if (area->is_type & IS_LEVEL_1)
    {
      lsp = lsp_search (id, area->lspdb[0]);
      if (!lsp || area->lsp_regenerate_pending[0])
	goto L2;
      /*
       * Throttle avoidance
       */
      diff = now - lsp->last_generated;
      if (diff < MIN_LSP_GEN_INTERVAL)
	{
	  area->lsp_regenerate_pending[0] = 1;
	  area->t_lsp_l1_regenerate=thread_add_timer (master, lsp_l1_regenerate, area,
			    MIN_LSP_GEN_INTERVAL - diff);
	  goto L2;
	}
      else
	lsp_non_pseudo_regenerate (area, 1);
    }
  /*
   * then 2
   */
L2:
  if (area->is_type & IS_LEVEL_2)
    {
      lsp = lsp_search (id, area->lspdb[1]);
      if (!lsp || area->lsp_regenerate_pending[1])
	return ISIS_OK;
      /*
       * Throttle avoidance
       */
      diff = now - lsp->last_generated;
      if (diff < MIN_LSP_GEN_INTERVAL)
	{
	  area->lsp_regenerate_pending[1] = 1;
	  area->t_lsp_l2_regenerate=thread_add_timer (master, lsp_l2_regenerate, area,
			    MIN_LSP_GEN_INTERVAL - diff);
	  return ISIS_OK;
	}
      else
	lsp_non_pseudo_regenerate (area, 2);
    }

  return ISIS_OK;
}

/*
 * Funcs for pseudonode LSPs
 */

/*
 * 7.3.8 and 7.3.10 Generation of level 1 and 2 pseudonode LSPs 
 */
static void
lsp_build_pseudo (struct isis_lsp *lsp, struct isis_circuit *circuit,
		  int level)
{
  struct isis_adjacency *adj;
  struct is_neigh *is_neigh;
  struct te_is_neigh *te_is_neigh;
  struct es_neigh *es_neigh;
  struct list *adj_list;
  struct listnode *node;
  struct isis_passwd *passwd;

  assert (circuit);
  assert (circuit->circ_type == CIRCUIT_T_BROADCAST);

  if (!circuit->u.bc.is_dr[level - 1])
    return;			/* we are not DIS on this circuit */

  lsp->level = level;
  if (level == 1)
    lsp->lsp_header->lsp_bits |= IS_LEVEL_1;
  else
    lsp->lsp_header->lsp_bits |= IS_LEVEL_2;

  /*
   * add self to IS neighbours 
   */
  if (circuit->area->oldmetric)
    {
      if (lsp->tlv_data.is_neighs == NULL)
	{
	  lsp->tlv_data.is_neighs = isis_list_new ();
	  lsp->tlv_data.is_neighs->del = free_tlv;
	}
      is_neigh = calloc(1, sizeof (struct is_neigh));

      memcpy (&is_neigh->neigh_id, isis->sysid, ISIS_SYS_ID_LEN);
      isis_listnode_add (lsp->tlv_data.is_neighs, is_neigh);
    }
  if (circuit->area->newmetric)
    {
      if (lsp->tlv_data.te_is_neighs == NULL)
	{
	  lsp->tlv_data.te_is_neighs = isis_list_new ();
	  lsp->tlv_data.te_is_neighs->del = free_tlv;
	}
      te_is_neigh = calloc(1, sizeof (struct te_is_neigh));

      memcpy (&te_is_neigh->neigh_id, isis->sysid, ISIS_SYS_ID_LEN);
      isis_listnode_add (lsp->tlv_data.te_is_neighs, te_is_neigh);
    }

  adj_list = isis_list_new ();
  isis_adj_build_up_list (circuit->u.bc.adjdb[level - 1], adj_list);

  for (ALL_LIST_ELEMENTS_RO (adj_list, node, adj))
    {
      if (adj->circuit_t & level)
	{
	  if ((level == 1 && adj->sys_type == ISIS_SYSTYPE_L1_IS) ||
	      (level == 1 && adj->sys_type == ISIS_SYSTYPE_L2_IS &&
	      adj->adj_usage == ISIS_ADJ_LEVEL1AND2) ||
	      (level == 2 && adj->sys_type == ISIS_SYSTYPE_L2_IS))
	    {
	      /* an IS neighbour -> add it */
	      if (circuit->area->oldmetric)
		{
		  is_neigh = calloc(1, sizeof (struct is_neigh));

		  memcpy (&is_neigh->neigh_id, adj->sysid, ISIS_SYS_ID_LEN);
		  isis_listnode_add (lsp->tlv_data.is_neighs, is_neigh);
		}
	      if (circuit->area->newmetric)
		{
		  te_is_neigh = calloc(1, sizeof (struct te_is_neigh));
		  memcpy (&te_is_neigh->neigh_id, adj->sysid, ISIS_SYS_ID_LEN);
		  isis_listnode_add (lsp->tlv_data.te_is_neighs, te_is_neigh);
		}
	    }
	  else if (level == 1 && adj->sys_type == ISIS_SYSTYPE_ES)
	    {
	      /* an ES neigbour add it, if we are building level 1 LSP */
	      /* FIXME: the tlv-format is hard to use here */
	      if (lsp->tlv_data.es_neighs == NULL)
		{
		  lsp->tlv_data.es_neighs = isis_list_new ();
		  lsp->tlv_data.es_neighs->del = free_tlv;
		}
	      es_neigh = calloc(1, sizeof (struct es_neigh));
	      
	      memcpy (&es_neigh->first_es_neigh, adj->sysid, ISIS_SYS_ID_LEN);
	      isis_listnode_add (lsp->tlv_data.es_neighs, es_neigh);
	    }
	}
    }

  /* Reset endp of stream to overwrite only TLV part of it. */
  stream_reset (lsp->pdu);
  stream_forward_endp (lsp->pdu, ISIS_FIXED_HDR_LEN + ISIS_LSP_HDR_LEN);

  /*
   * Add the authentication info if it's present
   */
  (level == 1) ? (passwd = &circuit->area->area_passwd) :
    (passwd = &circuit->area->domain_passwd);
  if (passwd->type)
    {
      memcpy (&lsp->tlv_data.auth_info, passwd, sizeof (struct isis_passwd));
      tlv_add_authinfo (passwd->type, passwd->len, passwd->passwd, lsp->pdu);
    }

  if (lsp->tlv_data.is_neighs && listcount (lsp->tlv_data.is_neighs) > 0)
    tlv_add_is_neighs (lsp->tlv_data.is_neighs, lsp->pdu);

  if (lsp->tlv_data.te_is_neighs && listcount (lsp->tlv_data.te_is_neighs) > 0)
    tlv_add_te_is_neighs (lsp->tlv_data.te_is_neighs, lsp->pdu);

  if (lsp->tlv_data.es_neighs && listcount (lsp->tlv_data.es_neighs) > 0)
    tlv_add_is_neighs (lsp->tlv_data.es_neighs, lsp->pdu);

  lsp->lsp_header->pdu_len = htons (stream_get_endp (lsp->pdu));
  fletcher_checksum (STREAM_DATA (lsp->pdu) + 12,
		   ntohs (lsp->lsp_header->pdu_len) - 12, 12);

  isis_list_delete (adj_list);

  return;
}

static int
lsp_pseudo_regenerate (struct isis_circuit *circuit, int level)
{
  dict_t *lspdb = circuit->area->lspdb[level - 1];
  struct isis_lsp *lsp;
  u_char lsp_id[ISIS_SYS_ID_LEN + 2];

  memcpy (lsp_id, isis->sysid, ISIS_SYS_ID_LEN);
  LSP_PSEUDO_ID (lsp_id) = circuit->circuit_id;
  LSP_FRAGMENT (lsp_id) = 0;

  lsp = lsp_search (lsp_id, lspdb);

  if (!lsp)
    {
      Log(LOG_ERR, "ERROR ( default/core/ISIS ): lsp_pseudo_regenerate(): no l%d LSP %s found!\n", level,
		rawlspid_print (lsp_id));
      return ISIS_ERROR;
    }
  lsp_clear_data (lsp);

  lsp_build_pseudo (lsp, circuit, level);

  lsp->lsp_header->rem_lifetime =
    htons (isis_jitter (circuit->area->max_lsp_lifetime[level - 1],
			MAX_AGE_JITTER));

  lsp_inc_seqnum (lsp, 0);

  if (config.nfacctd_isis_msglog)
    {
      Log(LOG_DEBUG, "DEBUG ( default/core/ISIS ): ISIS-Upd (%s): refreshing pseudo LSP L%d %s\n",
		  circuit->area->area_tag, level,
		  rawlspid_print (lsp->lsp_header->lsp_id));
    }

  lsp->last_generated = time (NULL);
  ISIS_FLAGS_SET_ALL (lsp->SRMflags);

  return ISIS_OK;
}

int
lsp_l1_refresh_pseudo (struct thread *thread)
{
  struct isis_circuit *circuit;
  int retval;
  unsigned long ref_time;

  circuit = THREAD_ARG (thread);

  if (!circuit->u.bc.is_dr[0])
    return ISIS_ERROR;		/* FIXME: purge and such */

  circuit->u.bc.t_refresh_pseudo_lsp[0] = NULL;

  retval = lsp_pseudo_regenerate (circuit, 1);

  ref_time = circuit->area->lsp_refresh[0] > MAX_LSP_GEN_INTERVAL ?
    MAX_LSP_GEN_INTERVAL : circuit->area->lsp_refresh[0];

  THREAD_TIMER_ON (master, circuit->u.bc.t_refresh_pseudo_lsp[0],
		   lsp_l1_refresh_pseudo, circuit,
		   isis_jitter (ref_time, MAX_AGE_JITTER));

  return retval;
}

int
lsp_l1_pseudo_generate (struct isis_circuit *circuit)
{
  struct isis_lsp *lsp;
  u_char id[ISIS_SYS_ID_LEN + 2];
  unsigned long ref_time;

  memcpy (id, isis->sysid, ISIS_SYS_ID_LEN);
  LSP_FRAGMENT (id) = 0;
  LSP_PSEUDO_ID (id) = circuit->circuit_id;

  /*
   * If for some reason have a pseudo LSP in the db already -> regenerate
   */
  if (lsp_search (id, circuit->area->lspdb[0]))
    return lsp_pseudo_regenerate (circuit, 1);
  lsp = lsp_new (id, circuit->area->max_lsp_lifetime[0],
		 1, circuit->area->is_type, 0, 1);

  lsp_build_pseudo (lsp, circuit, 1);

  lsp->own_lsp = 1;
  lsp_insert (lsp, circuit->area->lspdb[0]);
  ISIS_FLAGS_SET_ALL (lsp->SRMflags);

  ref_time = circuit->area->lsp_refresh[0] > MAX_LSP_GEN_INTERVAL ?
    MAX_LSP_GEN_INTERVAL : circuit->area->lsp_refresh[0];

  THREAD_TIMER_ON (master, circuit->u.bc.t_refresh_pseudo_lsp[0],
		   lsp_l1_refresh_pseudo, circuit,
		   isis_jitter (ref_time, MAX_AGE_JITTER));

  return lsp_regenerate_schedule (circuit->area);
}

int
lsp_l2_refresh_pseudo (struct thread *thread)
{
  struct isis_circuit *circuit;
  int retval;
  unsigned long ref_time;
  circuit = THREAD_ARG (thread);

  if (!circuit->u.bc.is_dr[1])
    return ISIS_ERROR;		/* FIXME: purge and such */

  circuit->u.bc.t_refresh_pseudo_lsp[1] = NULL;

  retval = lsp_pseudo_regenerate (circuit, 2);

  ref_time = circuit->area->lsp_refresh[1] > MAX_LSP_GEN_INTERVAL ?
    MAX_LSP_GEN_INTERVAL : circuit->area->lsp_refresh[1];

  THREAD_TIMER_ON (master, circuit->u.bc.t_refresh_pseudo_lsp[1],
		   lsp_l2_refresh_pseudo, circuit,
		   isis_jitter (ref_time, MAX_AGE_JITTER));

  return retval;
}

int
lsp_l2_pseudo_generate (struct isis_circuit *circuit)
{
  struct isis_lsp *lsp;
  u_char id[ISIS_SYS_ID_LEN + 2];
  unsigned long ref_time;

  memcpy (id, isis->sysid, ISIS_SYS_ID_LEN);
  LSP_FRAGMENT (id) = 0;
  LSP_PSEUDO_ID (id) = circuit->circuit_id;

  if (lsp_search (id, circuit->area->lspdb[1]))
    return lsp_pseudo_regenerate (circuit, 2);

  lsp = lsp_new (id, circuit->area->max_lsp_lifetime[1],
		 1, circuit->area->is_type, 0, 2);

  lsp_build_pseudo (lsp, circuit, 2);

  ref_time = circuit->area->lsp_refresh[1] > MAX_LSP_GEN_INTERVAL ?
    MAX_LSP_GEN_INTERVAL : circuit->area->lsp_refresh[1];


  lsp->own_lsp = 1;
  lsp_insert (lsp, circuit->area->lspdb[1]);
  ISIS_FLAGS_SET_ALL (lsp->SRMflags);

  THREAD_TIMER_ON (master, circuit->u.bc.t_refresh_pseudo_lsp[1],
		   lsp_l2_refresh_pseudo, circuit,
		   isis_jitter (ref_time, MAX_AGE_JITTER));

  return lsp_regenerate_schedule (circuit->area);
}

void
lsp_purge_dr (u_char * id, struct isis_circuit *circuit, int level)
{
  struct isis_lsp *lsp;

  lsp = lsp_search (id, circuit->area->lspdb[level - 1]);

  if (lsp && lsp->purged == 0)
    {
      lsp->lsp_header->rem_lifetime = htons (0);
      lsp->lsp_header->pdu_len =
	htons (ISIS_FIXED_HDR_LEN + ISIS_LSP_HDR_LEN);
      lsp->purged = 0;
      fletcher_checksum (STREAM_DATA (lsp->pdu) + 12,
		       ntohs (lsp->lsp_header->pdu_len) - 12, 12);
      ISIS_FLAGS_SET_ALL (lsp->SRMflags);
    }

  return;
}

/*
 * Purge own LSP that is received and we don't have. 
 * -> Do as in 7.3.16.4
 */
void
lsp_purge_non_exist (struct isis_link_state_hdr *lsp_hdr,
		     struct isis_area *area)
{
  struct isis_lsp *lsp;

  /*
   * We need to create the LSP to be purged 
   */
  Log(LOG_DEBUG, "DEBUG ( default/core/ISIS ): LSP PURGE NON EXIST\n");
  lsp = calloc(1, sizeof (struct isis_lsp));
  /*FIXME: BUG BUG BUG! the lsp doesn't exist here! */
  /*did smt here, maybe good probably not */
  lsp->level = ((lsp_hdr->lsp_bits & LSPBIT_IST) == IS_LEVEL_1) ? 1 : 2;
  lsp->pdu = stream_new (ISIS_FIXED_HDR_LEN + ISIS_LSP_HDR_LEN);
  lsp->isis_header = (struct isis_fixed_hdr *) STREAM_DATA (lsp->pdu);
  fill_fixed_hdr (lsp->isis_header, (lsp->level == 1) ? L1_LINK_STATE
		  : L2_LINK_STATE);
  lsp->lsp_header = (struct isis_link_state_hdr *) (STREAM_DATA (lsp->pdu) +
						    ISIS_FIXED_HDR_LEN);
  memcpy (lsp->lsp_header, lsp_hdr, ISIS_LSP_HDR_LEN);

  /*
   * Retain only LSP header
   */
  lsp->lsp_header->pdu_len = htons (ISIS_FIXED_HDR_LEN + ISIS_LSP_HDR_LEN);
  /*
   * Set the remaining lifetime to 0
   */
  lsp->lsp_header->rem_lifetime = 0;
  /*
   * Put the lsp into LSPdb
   */
  lsp_insert (lsp, area->lspdb[lsp->level - 1]);

  /*
   * Send in to whole area
   */
  ISIS_FLAGS_SET_ALL (lsp->SRMflags);

  return;
}

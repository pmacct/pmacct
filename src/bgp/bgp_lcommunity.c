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

/*  Based on BGP standard and extended communities implementation from Quagga  */

#include "pmacct.h"
#include "bgp_prefix.h"
#include "bgp.h"

/* Allocate a new lcommunities.  */
struct lcommunity *
lcommunity_new (struct bgp_peer *peer)
{
  struct bgp_misc_structs *bms;
  void *tmp;

  if (!peer) return NULL;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) return NULL;

  tmp = malloc(sizeof (struct lcommunity));
  if (!tmp) {
    Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (lcommunity_new). Exiting ..\n", config.name, bms->log_str);
    exit_gracefully(1);
  }
  memset(tmp, 0, sizeof (struct lcommunity));

  return (struct lcommunity *) tmp;
}

/* Allocate lcommunities.  */
void
lcommunity_free (struct lcommunity *lcom)
{
  if (lcom->val) free(lcom->val);
  if (lcom->str) free(lcom->str);
  free(lcom);
}

/* Add a new Large Communities value to Large Communities
   Attribute structure.  When the value already exists in
   the structure, we don't add the value.  Newly added
   value is sorted by numerical order.  When the value is
   added to the structure return 1 else return 0.  */
static int
lcommunity_add_val (struct bgp_peer *peer, struct lcommunity *lcom, struct lcommunity_val *lval)
{
  struct bgp_misc_structs *bms;
  u_int8_t *p;
  int ret;
  int c;

  if (!peer) return ERR;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) return ERR;

  /* When this is fist value, just add it.  */
  if (lcom->val == NULL)
    {
      lcom->size++;
      lcom->val = malloc(lcom_length (lcom));
      if (!lcom->val) {
	Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (lcommunity_add_val). Exiting ..\n", config.name, bms->log_str);
	exit_gracefully(1);
      }
      memcpy (lcom->val, lval->val, LCOMMUNITY_SIZE);
      return 1;
    }

  /* If the value already exists in the structure return 0.  */
  c = 0;
  for (p = lcom->val; c < lcom->size; p += LCOMMUNITY_SIZE, c++)
    {
      ret = memcmp (p, lval->val, LCOMMUNITY_SIZE);
      if (ret == 0)
        return 0;
      if (ret > 0)
        break;
    }

  /* Add the value to the structure with numerical sorting.  */
  lcom->size++;
  lcom->val = realloc(lcom->val, lcom_length (lcom));

  memmove (lcom->val + (c + 1) * LCOMMUNITY_SIZE,
	   lcom->val + c * LCOMMUNITY_SIZE,
	   (lcom->size - 1 - c) * LCOMMUNITY_SIZE);
  memcpy (lcom->val + c * LCOMMUNITY_SIZE, lval->val, LCOMMUNITY_SIZE);

  return 1;
}

/* This function takes pointer to Large Communites strucutre then
   create a new Large Communities structure by uniq and sort each
   Exteneded Communities value.  */
static struct lcommunity *
lcommunity_uniq_sort (struct bgp_peer *peer, struct lcommunity *lcom)
{
  int i;
  struct lcommunity *new;
  struct lcommunity_val *lval;
  
  if (!lcom) return NULL;
  
  new = lcommunity_new (peer);
  
  for (i = 0; i < lcom->size; i++)
    {
      lval = (struct lcommunity_val *) (lcom->val + (i * LCOMMUNITY_SIZE));
      lcommunity_add_val (peer, new, lval);
    }
  return new;
}

/* Parse Large Communites Attribute in BGP packet.  */
struct lcommunity *
lcommunity_parse (struct bgp_peer *peer, u_int8_t *pnt, u_short length)
{
  struct lcommunity tmp;
  struct lcommunity *new;

  /* Length check.  */
  if (length % LCOMMUNITY_SIZE)
    return NULL;

  /* Prepare tmporary structure for making a new Large Communities
     Attribute.  */
  tmp.size = length / LCOMMUNITY_SIZE;
  tmp.val = pnt;

  /* Create a new Large Communities Attribute by uniq and sort each
     Large Communities value  */
  new = lcommunity_uniq_sort (peer, &tmp);

  return lcommunity_intern (peer, new);
}

/* Intern Large Communities Attribute.  */
struct lcommunity *
lcommunity_intern (struct bgp_peer *peer, struct lcommunity *lcom)
{
  struct bgp_rt_structs *inter_domain_routing_db;
  struct lcommunity *find;

  if (!peer) return NULL;

  inter_domain_routing_db = bgp_select_routing_db(peer->type);

  if (!inter_domain_routing_db) return NULL;

  assert (lcom->refcnt == 0);

  find = (struct lcommunity *) hash_get(peer, inter_domain_routing_db->lcomhash, lcom, hash_alloc_intern);

  if (find != lcom)
    lcommunity_free (lcom);

  find->refcnt++;

  if (! find->str)
    find->str = lcommunity_lcom2str (peer, find);

  return find;
}

/* Unintern Large Communities Attribute.  */
void
lcommunity_unintern (struct bgp_peer *peer, struct lcommunity *lcom)
{
  struct bgp_rt_structs *inter_domain_routing_db;
  struct lcommunity *ret = NULL;
  (void) ret;

  if (!peer) return;

  inter_domain_routing_db = bgp_select_routing_db(peer->type);

  if (!inter_domain_routing_db) return;

  if (lcom->refcnt)
    lcom->refcnt--;

  /* Pull off from hash.  */
  if (lcom->refcnt == 0) {
    /* Large community must be in the hash.  */
    ret = (struct lcommunity *) hash_release(inter_domain_routing_db->lcomhash, lcom);
    assert (ret != NULL);

    lcommunity_free(lcom);
  }
}

/* Utinity function to make hash key.  */
unsigned int
lcommunity_hash_make (void *arg)
{
  const struct lcommunity *lcom = arg;
  int c;
  unsigned int key;
  u_int8_t *pnt;

  key = 0;
  pnt = lcom->val;
  
  for (c = 0; c < lcom->size * LCOMMUNITY_SIZE; c++)
    key += pnt[c];

  return key;
}

/* Compare two Large Communities Attribute structure.  */
int
lcommunity_cmp (const void *arg1, const void *arg2)
{
  const struct lcommunity *lcom1 = arg1;
  const struct lcommunity *lcom2 = arg2;
  
  return (lcom1->size == lcom2->size
	  && memcmp (lcom1->val, lcom2->val, lcom1->size * LCOMMUNITY_SIZE) == 0);
}

/* Initialize Large Comminities related hash. */
void
lcommunity_init (int buckets, struct hash **loc_lcomhash)
{
  (*loc_lcomhash) = hash_create (buckets, lcommunity_hash_make, lcommunity_cmp);
}

char *
lcommunity_lcom2str (struct bgp_peer *peer, struct lcommunity *lcom)
{
  struct bgp_misc_structs *bms;
  int idx, str_pnt, str_size, first = TRUE;
  u_int32_t npart1, npart2, npart3;
  u_int32_t hpart1, hpart2, hpart3;
  char *str_buf = NULL;
  u_int8_t *pnt;

  if (!peer) return NULL;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) return NULL;

  if (lcom->size == 0) {
    str_buf = malloc(1);
    if (!str_buf) goto exit_lane;

    str_buf[0] = '\0';

    return str_buf;
  }

  for (idx = 0, str_pnt = 0, str_size = 0; idx < lcom->size; idx++) {
    str_size += (LCOMMUNITY_STR_DEFAULT_LEN + 1);

    if (!first) str_buf = realloc(str_buf, str_size);
    else str_buf = malloc(str_size);

    if (!str_buf) goto exit_lane;
    
    if (!first) str_buf[str_pnt++] = ' ';
    pnt = lcom->val + (idx * LCOMMUNITY_SIZE);
    memcpy(&npart1, pnt, LCOMMUNITY_PART_SIZE);
    memcpy(&npart2, (pnt + LCOMMUNITY_PART_SIZE), LCOMMUNITY_PART_SIZE);
    memcpy(&npart3, (pnt + LCOMMUNITY_PART_SIZE + LCOMMUNITY_PART_SIZE), LCOMMUNITY_PART_SIZE);
    hpart1 = ntohl(npart1);
    hpart2 = ntohl(npart2);
    hpart3 = ntohl(npart3);
    sprintf(&str_buf[str_pnt], "%u:%u:%u", hpart1, hpart2, hpart3);
    str_pnt = strlen(str_buf);

    first = FALSE;
  }

  return str_buf;

  exit_lane:
  Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (lcommunity_lcom2str). Exiting ..\n", config.name, bms->log_str);
  exit_gracefully(1);

  return NULL; /* silence compiler warning */
}

struct lcommunity *lcommunity_dup(struct lcommunity *lcom)
{
  struct lcommunity *new;

  new = malloc(sizeof(struct lcommunity));

  new->size = lcom->size;

  if (new->size) {
    new->val = malloc(lcom->size * LCOMMUNITY_SIZE);
    memcpy (new->val, lcom->val, lcom->size * LCOMMUNITY_SIZE);
  }
  else new->val = NULL;

  return new;
}

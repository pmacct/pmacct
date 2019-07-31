/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2019 by Paolo Lucente
*/

/* 
 Originally based on Quagga BGP community attribute related functions
 which is:

 Copyright (C) 1998, 2001 Kunihiro Ishiguro

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#include "pmacct.h"
#include "bgp.h"

/* Allocate a new communities value.  */
struct community *community_new (struct bgp_peer *peer)
{
  struct bgp_misc_structs *bms;
  void *tmp;

  if (!peer) return NULL;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) return NULL;

  tmp = malloc(sizeof (struct community));
  if (!tmp) {
    Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (community_new). Exiting ..\n", config.name, bms->log_str);
    exit_gracefully(1);
  }
  memset(tmp, 0, sizeof (struct community));

  return (struct community *) tmp;
}

/* Free communities value.  */
void
community_free (struct community *com)
{
  if (com->val) free(com->val);
  if (com->str) free(com->str);
  free(com);
}

/* Add one community value to the community. */
void community_add_val (struct bgp_peer *peer, struct community *com, u_int32_t val)
{
  struct bgp_misc_structs *bms;

  if (!peer) return;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  com->size++;
  if (com->val)
    com->val = realloc(com->val, com_length (com));
  else {
    com->val = malloc(com_length (com));
    if (!com->val) {
      Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (community_add_val). Exiting ..\n", config.name, bms->log_str);
      exit_gracefully(1);
    }
  }

  val = htonl (val);
  memcpy (com_lastval (com), &val, sizeof (u_int32_t));
}

/* Delete one community. */
void
community_del_val (struct community *com, u_int32_t *val)
{
  int i = 0;
  int c = 0;

  if (! com->val)
    return;

  while (i < com->size)
    {
      if (memcmp (com->val + i, val, sizeof (u_int32_t)) == 0)
	{
	  c = com->size -i -1;

	  if (c > 0)
	    memcpy (com->val + i, com->val + (i + 1), c * sizeof (val));

	  com->size--;

	  if (com->size > 0)
	    com->val = realloc(com->val, com_length (com));
	  else
	    {
	      free(com->val);
	      com->val = NULL;
	    }
	  return;
	}
      i++;
    }
}

/* Delete all communities listed in com2 from com1 */
struct community *
community_delete (struct community *com1, struct community *com2)
{
  int i = 0;

  while(i < com2->size)
    {
      community_del_val (com1, com2->val + i);
      i++;
    }

  return com1;
}

/* Callback function from qsort(). */
int community_compare (const void *a1, const void *a2)
{
  u_int32_t v1;
  u_int32_t v2;

  memcpy (&v1, a1, sizeof (u_int32_t));
  memcpy (&v2, a2, sizeof (u_int32_t));
  v1 = ntohl (v1);
  v2 = ntohl (v2);

  if (v1 < v2)
    return -1;
  if (v1 > v2)
    return 1;
  return 0;
}

int
community_include (struct community *com, u_int32_t val)
{
  int i;

  val = htonl (val);

  for (i = 0; i < com->size; i++)
    if (memcmp (&val, com_nthval (com, i), sizeof (u_int32_t)) == 0)
      return 1;

  return 0;
}

u_int32_t community_val_get(struct community *com, int i)
{
  u_char *p;
  u_int32_t val;

  p = (u_char *) com->val;
  p += (i * 4);

  memcpy (&val, p, sizeof (u_int32_t));

  return ntohl (val);
}

/* Sort and uniq given community. */
struct community *
community_uniq_sort (struct bgp_peer *peer, struct community *com)
{
  int i;
  struct community *new;
  u_int32_t val;

  if (! com)
    return NULL;
  
  new = community_new (peer);
  
  for (i = 0; i < com->size; i++)
    {
      val = community_val_get (com, i);

      if (! community_include (new, val))
	community_add_val (peer, new, val);
    }

  qsort (new->val, new->size, sizeof (u_int32_t), community_compare);

  return new;
}

/* Convert communities attribute to string.

   For Well-known communities value, below keyword is used.

   0x0             "internet"    
   0xFFFFFF01      "no-export"
   0xFFFFFF02      "no-advertise"
   0xFFFFFF03      "local-AS"

   For other values, "AS:VAL" format is used.  */
static char *
community_com2str  (struct bgp_peer *peer, struct community *com)
{
  struct bgp_misc_structs *bms;
  int i;
  char *str;
  char *pnt;
  int len;
  int first;
  u_int32_t comval;
  u_int16_t as;
  u_int16_t val;

  if (!com || !peer) return NULL;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) return NULL;
  
  /* When communities attribute is empty.  */
  if (com->size == 0)
    {
      str = malloc(1);
      if (!str) {
	Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (community_com2str). Exiting ..\n", config.name, bms->log_str);
	exit_gracefully(1);
      }
      str[0] = '\0';
      return str;
    }

  /* Memory allocation is time consuming work.  So we calculate
     required string length first.  */
  len = 0;

  for (i = 0; i < com->size; i++)
    {
      memcpy (&comval, com_nthval (com, i), sizeof (u_int32_t));
      comval = ntohl (comval);

      switch (comval) 
	{
	case COMMUNITY_INTERNET:
	  len += strlen (" internet");
	  break;
	case COMMUNITY_NO_EXPORT:
	  len += strlen (" no-export");
	  break;
	case COMMUNITY_NO_ADVERTISE:
	  len += strlen (" no-advertise");
	  break;
	case COMMUNITY_LOCAL_AS:
	  len += strlen (" local-AS");
	  break;
	default:
	  len += strlen (" 65536:65535");
	  break;
	}
    }

  /* Allocate memory.  */
  str = pnt = malloc(len);
  if (!str) {
    Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (community_com2str). Exiting ..\n", config.name, bms->log_str);
    exit_gracefully(1);
  }
  first = 1;

  /* Fill in string.  */
  for (i = 0; i < com->size; i++)
    {
      memcpy (&comval, com_nthval (com, i), sizeof (u_int32_t));
      comval = ntohl (comval);

      if (first)
	first = 0;
      else
	*pnt++ = ' ';

      switch (comval) 
	{
	case COMMUNITY_INTERNET:
	  strcpy (pnt, "internet");
	  pnt += strlen ("internet");
	  break;
	case COMMUNITY_NO_EXPORT:
	  strcpy (pnt, "no-export");
	  pnt += strlen ("no-export");
	  break;
	case COMMUNITY_NO_ADVERTISE:
	  strcpy (pnt, "no-advertise");
	  pnt += strlen ("no-advertise");
	  break;
	case COMMUNITY_LOCAL_AS:
	  strcpy (pnt, "local-AS");
	  pnt += strlen ("local-AS");
	  break;
	default:
	  as = (comval >> 16) & 0xFFFF;
	  val = comval & 0xFFFF;
	  sprintf (pnt, "%d:%d", as, val);
	  pnt += strlen (pnt);
	  break;
	}
    }
  *pnt = '\0';

  return str;
}

/* Intern communities attribute.  */
struct community *
community_intern (struct bgp_peer *peer, struct community *com)
{
  struct bgp_rt_structs *inter_domain_routing_db;
  struct community *find;

  if (!peer) return NULL;

  inter_domain_routing_db = bgp_select_routing_db(peer->type);

  if (!inter_domain_routing_db) return NULL;

  /* Assert this community structure is not interned. */
  assert (com->refcnt == 0);

  /* Lookup community hash. */
  find = (struct community *) hash_get(peer, inter_domain_routing_db->comhash, com, hash_alloc_intern);

  /* Arguemnt com is allocated temporary.  So when it is not used in
     hash, it should be freed.  */
  if (find != com)
    community_free (com);

  /* Increment refrence counter.  */
  find->refcnt++;

  /* Make string.  */
  if (! find->str)
    find->str = community_com2str (peer, find);

  return find;
}

/* Free community attribute. */
void
community_unintern (struct bgp_peer *peer, struct community *com)
{
  struct bgp_rt_structs *inter_domain_routing_db;
  struct community *ret = NULL;
  (void) ret;

  if (!peer) return;
  
  inter_domain_routing_db = bgp_select_routing_db(peer->type);

  if (!inter_domain_routing_db) return;

  if (com->refcnt)
    com->refcnt--;

  /* Pull off from hash.  */
  if (com->refcnt == 0) {
    /* Community value com must exist in hash. */
    ret = (struct community *) hash_release(inter_domain_routing_db->comhash, com);
    assert (ret != NULL);

    community_free (com);
  }
}

/* Create new community attribute. */
struct community *
community_parse (struct bgp_peer *peer, u_int32_t *pnt, u_short length)
{
  struct community tmp;
  struct community *new;

  /* If length is malformed return NULL. */
  if (length % 4)
    return NULL;

  /* Make temporary community for hash look up. */
  tmp.size = length / 4;
  tmp.val = pnt;

  new = community_uniq_sort (peer, &tmp);

  return community_intern (peer, new);
}

/* Make hash value of community attribute. This function is used by
   hash package.*/
unsigned int
community_hash_make (struct community *com)
{
  int c;
  unsigned int key;
  unsigned char *pnt;

  key = 0;
  pnt = (unsigned char *)com->val;
  
  for(c = 0; c < com->size * 4; c++)
    key += pnt[c];
      
  return key;
}

/* If two aspath have same value then return 1 else return 0. This
   function is used by hash package. */
int
community_cmp (const struct community *com1, const struct community *com2)
{
  if (com1 == NULL && com2 == NULL)
    return 1;
  if (com1 == NULL || com2 == NULL)
    return 0;

  if (com1->size == com2->size)
    if (memcmp (com1->val, com2->val, com1->size * 4) == 0)
      return 1;
  return 0;
}

/* Initialize comminity related hash. */
void
community_init (int buckets, struct hash **loc_comhash)
{
  (*loc_comhash) = hash_create (buckets, (unsigned int (*) (void *))community_hash_make,
			 (int (*) (const void *, const void *))community_cmp);
}


int community_str2com_simple(const char *buf, u_int32_t *val)
{
  const char *p = buf;

  /* Skip white space. */
  while (isspace ((int) (*p))) p++;

  /* Check the end of the line. */
  if (*p == '\0') return ERR;

  /* Community value. */
  if (isdigit ((int) (*p))) {
    int separator = 0;
    int digit = 0;
    u_int32_t community_low = 0;
    u_int32_t community_high = 0;

    while (isdigit ((int) (*p)) || (*p) == ':') {
      if ((*p) == ':') {
	if (separator) return ERR;
	else {
	  separator = TRUE;
	  digit = FALSE;
	  community_high = community_low << 16;
	  community_low = 0;
	}
      }
      else {
        digit = TRUE;
        community_low *= 10;
        community_low += (*p - '0');
      }

      p++;
    }

    if (!digit) return ERR;

    (*val) = community_high + community_low;

    return FALSE;
  }

  return ERR;
}

struct community *community_dup(struct community *com)
{
  struct community *new;

  new = malloc(sizeof(struct community));

  new->size = com->size;

  if (new->size) {
    new->val = malloc(com->size * 4);
    memcpy(new->val, com->val, com->size * 4);
  }
  else new->val = NULL;

  return new;
}

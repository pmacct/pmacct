/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2019 by Paolo Lucente
*/

/* 
 Originally based on Quagga AS path management routines which is:

 Copyright (C) 1996, 97, 98, 99 Kunihiro Ishiguro
 Copyright (C) 2005 Sun Microsystems, Inc.

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
#include "jhash.h"
#include "bgp.h"

void *
assegment_data_new (int num)
{
  return (malloc(ASSEGMENT_DATA_SIZE (num, TRUE)));
}

__attribute__((unused)) static inline void
assegment_data_free (as_t *asdata)
{
  free(asdata);
}

/* Get a new segment. Note that 0 is an allowed length,
 * and will result in a segment with no allocated data segment.
 * the caller should immediately assign data to the segment, as the segment
 * otherwise is not generally valid
 */
static struct assegment *
assegment_new (u_char type, u_short length)
{
  struct assegment *new;
  
  new = malloc(sizeof (struct assegment));
  if (!new) {
    Log(LOG_ERR, "ERROR ( %s/core/BGP ): malloc() failed (assegment_new: new). Exiting ..\n", config.name); // XXX
    exit_gracefully(1);
  }
  memset(new, 0, sizeof (struct assegment));
  
  if (length) {
    new->as = assegment_data_new (length);
    if (!new->as) {
      Log(LOG_ERR, "ERROR ( %s/core/BGP ): malloc() failed (assegment_new: new->as). Exiting ..\n", config.name); // XXX
      exit_gracefully(1);
    }
    memset(new->as, 0, length);
  }
  
  new->length = length;
  new->type = type;
  
  return new;
}

static void
assegment_free (struct assegment *seg)
{
  if (!seg)
    return;
  
  if (seg->as)
    free(seg->as);
  memset (seg, 0xfe, sizeof(struct assegment));
  free(seg);
  
  return;
}

/* free entire chain of segments */
static void
assegment_free_all (struct assegment *seg)
{
  struct assegment *prev;
  
  while (seg)
    {
      prev = seg;
      seg = seg->next;
      assegment_free (prev);
    }
}

/* Duplicate just the given assegment and its data */
static struct assegment *
assegment_dup (struct assegment *seg)
{
  struct assegment *new;
  
  new = assegment_new (seg->type, seg->length);
  memcpy (new->as, seg->as, ASSEGMENT_DATA_SIZE (new->length, TRUE /* 32-bit ASN */) );
    
  return new;
}

/* Duplicate entire chain of assegments, return the head */
static struct assegment *
assegment_dup_all (struct assegment *seg)
{
  struct assegment *new = NULL;
  struct assegment *head = NULL;
  
  while (seg)
    {
      if (head)
        {
          new->next = assegment_dup (seg);
          new = new->next;
        }
      else
        head = new = assegment_dup (seg);
      
      seg = seg->next;
    }
  return head;
}

/* append given array of as numbers to the segment */
static struct assegment *
assegment_append_asns (struct assegment *seg, as_t *asnos, int num)
{
  as_t *newas;
  
  newas = realloc(seg->as, ASSEGMENT_DATA_SIZE (seg->length + num, TRUE));

  if (newas)
    {
      seg->as = newas;
      memcpy (seg->as + seg->length, asnos, ASSEGMENT_DATA_SIZE(num, TRUE));
      seg->length += num;
      return seg;
    }

  assegment_free_all (seg);
  return NULL;
}

static int
int_cmp (const void *p1, const void *p2)
{
  const as_t *as1 = p1;
  const as_t *as2 = p2;
  
  return (*as1 == *as2) 
          ? 0 : ( (*as1 > *as2) ? 1 : -1);
}

/* normalise the segment.
 * In particular, merge runs of AS_SEQUENCEs into one segment
 * Internally, we do not care about the wire segment length limit, and
 * we want each distinct AS_PATHs to have the exact same internal
 * representation - eg, so that our hashing actually works..
 */
static struct assegment *
assegment_normalise (struct assegment *head)
{
  struct assegment *seg = head, *pin;
  struct assegment *tmp;
  
  if (!head)
    return head;
  
  while (seg)
    {
      pin = seg;
      
      /* Sort values SET segments, for determinism in paths to aid
       * creation of hash values / path comparisons
       * and because it helps other lesser implementations ;)
       */
      if (seg->type == AS_SET || seg->type == AS_CONFED_SET)
      	{
	  int tail = 0;
	  int i;
	  
	  qsort (seg->as, seg->length, sizeof(as_t), int_cmp);
	  
	  /* weed out dupes */
	  for (i=1; i < seg->length; i++)
	    {
	      if (seg->as[tail] == seg->as[i])
	      	continue;
	      
	      tail++;
	      if (tail < i)
	      	seg->as[tail] = seg->as[i];
	    }
	  /* seg->length can be 0.. */
	  if (seg->length)
	    seg->length = tail + 1;
	}

      /* read ahead from the current, pinned segment while the segments
       * are packable/mergeable. Append all following packable segments
       * to the segment we have pinned and remove these appended
       * segments.
       */      
      while (pin->next && ASSEGMENT_TYPES_PACKABLE(pin, pin->next))
        {
          tmp = pin->next;
          seg = pin->next;
          
          /* append the next sequence to the pinned sequence */
          pin = assegment_append_asns (pin, seg->as, seg->length);
          
          /* bypass the next sequence */
          pin->next = seg->next;
          
          /* get rid of the now referenceless segment */
          assegment_free (tmp);
          
        }

      seg = pin->next;
    }
  return head;
}

static struct aspath *
aspath_new ()
{
  struct aspath *aspath;

  aspath = malloc(sizeof (struct aspath));

  if (!aspath) {
    Log(LOG_ERR, "ERROR ( %s/core/BGP ): malloc() failed (aspath_new). Exiting ..\n", config.name); // XXX
    exit_gracefully(1);
  }
  memset (aspath, 0, sizeof (struct aspath));

  return aspath;
}

/* Free AS path structure. */
void
aspath_free (struct aspath *aspath)
{
  if (!aspath)
    return;
  if (aspath->segments)
    assegment_free_all (aspath->segments);
  if (aspath->str) free(aspath->str);
  free(aspath);
}

/* Unintern aspath from AS path bucket. */
void
aspath_unintern(struct bgp_peer *peer, struct aspath *aspath)
{
  struct bgp_rt_structs *inter_domain_routing_db;
  struct aspath *ret = NULL;
  (void) ret;

  if (!peer) return;

  inter_domain_routing_db = bgp_select_routing_db(peer->type);

  if (!inter_domain_routing_db) return;

  if (aspath->refcnt)
    aspath->refcnt--;

  if (aspath->refcnt == 0) {
    /* This aspath must exist in aspath hash table. */
    ret = hash_release(inter_domain_routing_db->ashash, aspath);
    assert (ret != NULL);
    aspath_free (aspath);
  }
}

/* Add new as segment to the as path. */
static void
aspath_segment_add (struct aspath *as, int type)
{
  struct assegment *seg = as->segments;
  struct assegment *new = assegment_new (type, 0);

  if (seg) {
    while (seg->next) seg = seg->next;
    seg->next = new;
  }
  else as->segments = new;
}

/* Add new as value to as path structure. */
static void
aspath_as_add (struct aspath *as, as_t asno)
{
  struct assegment *seg = as->segments;

  if (!seg) return;

  /* Last segment search procedure. */
  while (seg->next) seg = seg->next;

  assegment_append_asns (seg, &asno, 1);
}

/* Return the start or end delimiters for a particular Segment type */
#define AS_SEG_START 0
#define AS_SEG_END 1
static char
aspath_delimiter_char (u_char type, u_char which)
{
  int i;
  struct
  {
    int type;
    char start;
    char end;
  } aspath_delim_char [] =
    {
      { AS_SET,             '{', '}' },
      { AS_CONFED_SET,      '[', ']' },
      { AS_CONFED_SEQUENCE, '(', ')' },
      { 0 }
    };

  for (i = 0; aspath_delim_char[i].type != 0; i++)
    {
      if (aspath_delim_char[i].type == type)
	{
	  if (which == AS_SEG_START)
	    return aspath_delim_char[i].start;
	  else if (which == AS_SEG_END)
	    return aspath_delim_char[i].end;
	}
    }
  return ' ';
}

/* countup asns from this segment and index onward */
static int
assegment_count_asns (struct assegment *seg, int from)
{
  int count = 0;
  while (seg)
    {
      if (!from)
        count += seg->length;
      else
        {
          count += (seg->length - from);
          from = 0;
        }
      seg = seg->next;
    }
  return count;
}

unsigned int
aspath_count_confeds (struct aspath *aspath)
{
  int count = 0;
  struct assegment *seg = aspath->segments;
  
  while (seg)
    {
      if (seg->type == AS_CONFED_SEQUENCE)
        count += seg->length;
      else if (seg->type == AS_CONFED_SET)
        count++;
      
      seg = seg->next;
    }
  return count;
}

unsigned int
aspath_count_hops (struct aspath *aspath)
{
  int count = 0;
  struct assegment *seg = aspath->segments;
  
  while (seg)
    {
      if (seg->type == AS_SEQUENCE)
        count += seg->length;
      else if (seg->type == AS_SET)
        count++;
      
      seg = seg->next;
    }
  return count;
}

/* Estimate size aspath /might/ take if encoded into an
 * ASPATH attribute.
 *
 * This is a quick estimate, not definitive! aspath_put()
 * may return a different number!!
 */
unsigned int
aspath_size (struct aspath *aspath)
{
  int size = 0;
  struct assegment *seg = aspath->segments;
  
  while (seg)
    {
      size += ASSEGMENT_SIZE(seg->length, 1);
      seg = seg->next;
    }
  return size;
}

/* Return highest public ASN in path */
as_t
aspath_highest (struct aspath *aspath)
{
  struct assegment *seg = aspath->segments;
  as_t highest = 0;
  unsigned int i;
  
  while (seg)
    {
      for (i = 0; i < seg->length; i++)
        if (seg->as[i] > highest
            && (seg->as[i] < BGP_PRIVATE_AS_MIN
                || seg->as[i] > BGP_PRIVATE_AS_MAX))
	  highest = seg->as[i];
      seg = seg->next;
    }
  return highest;
}

/* Return 1 if there are any 4-byte ASes in the path */
unsigned int
aspath_has_as4 (struct aspath *aspath)
{
  struct assegment *seg = aspath->segments;
  unsigned int i;
  
  while (seg)
    {
      for (i = 0; i < seg->length; i++)
        if (seg->as[i] > BGP_AS_MAX)
	  return 1;
      seg = seg->next;
    }
  return 0;
}

/* Return number of as numbers in in path */
unsigned int
aspath_count_numas (struct aspath *aspath)
{
  struct assegment *seg = aspath->segments;
  unsigned int num;
  
  num=0;
  while (seg)
    {
      num += seg->length;
      seg = seg->next;
    }
  return num;
}

char *aspath_make_empty()
{
  char *str_buf;

  str_buf = malloc(1);

  if (!str_buf) {
    Log(LOG_ERR, "ERROR ( %s/core/BGP ): malloc() failed (aspath_make_str_count). Exiting ..\n", config.name); // XXX
    exit_gracefully(1);
  }

  str_buf[0] = '\0';

  return str_buf;
}

/* Convert aspath structure to string expression. */
static char *
aspath_make_str_count (struct aspath *as)
{
  struct assegment *seg;
  int str_size;
  int len = 0;
  char *str_buf;

  /* Empty aspath. */
  if (!as->segments) {
    str_buf = aspath_make_empty();
    return str_buf;
  }

  seg = as->segments;
  
  /* ASN takes 5 chars at least, plus seperator, see below.
   * If there is one differing segment type, we need an additional
   * 2 chars for segment delimiters, and the final '\0'.
   * Hopefully this is large enough to avoid hitting the realloc
   * code below for most common sequences.
   *
   * With 32bit ASNs, this range will increase, but only worth changing
   * once there are significant numbers of ASN >= 100000
   */
#define ASN_STR_LEN (10 + 1)
  str_size = MAX (assegment_count_asns (seg, 0) * ASN_STR_LEN + 2 + 1,
                  ASPATH_STR_DEFAULT_LEN);
  str_buf = malloc(str_size);
  if (!str_buf) {
    Log(LOG_ERR, "ERROR ( %s/core/BGP ): malloc() failed (aspath_make_str_count). Exiting ..\n", config.name); // XXX
    exit_gracefully(1);
  }

  while (seg)
    {
      int i;
      char seperator;

      /* Check AS type validity. Set seperator for segment */
      switch (seg->type)
        {
          case AS_SET:
          case AS_CONFED_SET:
            seperator = ',';
            break;
          case AS_SEQUENCE:
          case AS_CONFED_SEQUENCE:
            seperator = ' ';
            break;
          default:
            free(str_buf);
	    str_buf = aspath_make_empty();
	    return str_buf;
        }
      
      /* We might need to increase str_buf, particularly if path has
       * differing segments types, our initial guesstimate above will
       * have been wrong.  need 5 chars for ASN, a seperator each and
       * potentially two segment delimiters, plus a space between each
       * segment and trailing zero.
       *
       * This may need to revised if/when significant numbers of
       * ASNs >= 100000 are assigned and in-use on the internet...
       */
#define SEGMENT_STR_LEN(X) (((X)->length * ASN_STR_LEN) + 2 + 1 + 1)
      if ( (len + SEGMENT_STR_LEN(seg)) > str_size)
        {
          str_size = len + SEGMENT_STR_LEN(seg);
          str_buf = realloc(str_buf, str_size);
        }
#undef ASN_STR_LEN
#undef SEGMENT_STR_LEN
      
      if (seg->type != AS_SEQUENCE)
        len += snprintf (str_buf + len, str_size - len, 
			 "%c", 
                         aspath_delimiter_char (seg->type, AS_SEG_START));
      
      /* write out the ASNs, with their seperators, bar the last one*/
      for (i = 0; i < seg->length; i++)
        {
          len += snprintf (str_buf + len, str_size - len, "%u", seg->as[i]);
	  as->last_as = seg->as[i];
          
          if (i < (seg->length - 1))
            len += snprintf (str_buf + len, str_size - len, "%c", seperator);
        }
      
      if (seg->type != AS_SEQUENCE)
        len += snprintf (str_buf + len, str_size - len, "%c", 
                        aspath_delimiter_char (seg->type, AS_SEG_END));
      if (seg->next)
        len += snprintf (str_buf + len, str_size - len, " ");
      
      seg = seg->next;
    }
  
  assert (len < str_size);
  
  str_buf[len] = '\0';

  return str_buf;
}

static void
aspath_str_update (struct aspath *as)
{
  if (as->str) free(as->str);
  as->str = aspath_make_str_count (as);
}

/* Intern allocated AS path. */
struct aspath *
aspath_intern (struct bgp_peer *peer, struct aspath *aspath)
{
  struct bgp_rt_structs *inter_domain_routing_db;
  struct aspath *find;

  if (!peer) return NULL;

  inter_domain_routing_db = bgp_select_routing_db(peer->type);

  if (!inter_domain_routing_db) return NULL;
  
  /* Assert this AS path structure is not interned. */
  assert (aspath->refcnt == 0);

  /* Check AS path hash. */
  find = hash_get(peer, inter_domain_routing_db->ashash, aspath, hash_alloc_intern);

  if (find != aspath)
    aspath_free (aspath);

  find->refcnt++;

  if (! find->str)
    find->str = aspath_make_str_count (find);

  return find;
}

/* Duplicate aspath structure.  Created same aspath structure but
   reference count and AS path string is cleared. */
struct aspath *
aspath_dup (struct aspath *aspath)
{
  struct aspath *new;

  new = malloc(sizeof (struct aspath));
  if (!new) {
    Log(LOG_ERR, "ERROR ( %s/core/BGP ): malloc() failed (aspath_dup). Exiting ..\n", config.name); // XXX
    exit_gracefully(1);
  }
  memset(new, 0, sizeof(struct aspath));

  if (aspath->segments)
    new->segments = assegment_dup_all (aspath->segments);
  else
    new->segments = NULL;

  new->str = aspath_make_str_count (aspath);
  new->last_as = aspath->last_as;

  return new;
}

static void *
aspath_hash_alloc (void *arg)
{
  struct aspath *aspath;
  
  /* New aspath structure is needed. */
  aspath = aspath_dup (arg);
  
  /* Malformed AS path value. */
  if (! aspath->str)
    {
      aspath_free (aspath);
      return NULL;
    }

  return aspath;
}

/* parse as-segment in struct assegment */
static struct assegment *
assegments_parse(char *s, size_t length, int use32bit)
{
  struct assegment_header segh;
  struct assegment *seg, *prev = NULL, *head = NULL;
  size_t bytes = 0, aspathlen;
  u_char *tmp8;
  u_int16_t tmp16;
  u_int32_t tmp32;

  /* empty aspath (ie iBGP or somesuch) */
  if (length == 0) return NULL;
  
  /* basic checks; XXX: length? */
  if (length % AS16_VALUE_SIZE) return NULL;

  aspathlen = length;
  
  while (aspathlen > 0) {
      int i;
      int seg_size;

      /* softly softly, get the header first on its own */
      tmp8 = (u_char *) s; segh.type = *tmp8; s++;
      tmp8 = (u_char *) s; segh.length = *tmp8; s++;
      
      seg_size = ASSEGMENT_SIZE(segh.length, use32bit);

      /* check it.. */
      if ( ((bytes + seg_size) > length)
          /* 1771bis 4.3b: seg length contains one or more */
          || (segh.length == 0) 
          /* Paranoia in case someone changes type of segment length */
          || ((sizeof(segh.length) > 1) && (segh.length > AS_SEGMENT_MAX)) )
        {
          if (head)
            assegment_free_all (head);
          return NULL;
        }
      
      /* now its safe to trust lengths */
      seg = assegment_new (segh.type, segh.length);
      
      if (head)
        prev->next = seg;
      else /* it's the first segment */
        head = prev = seg;
      
      for (i = 0; i < segh.length; i++) {
		if (use32bit) {
		  memcpy(&tmp32, s, 4); seg->as[i] = ntohl(tmp32); s += 4;
		}
		else {
		  memcpy(&tmp16, s, 2); seg->as[i] = ntohs(tmp16); s += 2;
		}
      }
	  
      bytes += seg_size;
      aspathlen -= seg_size;
      prev = seg;
    }
 
  return assegment_normalise (head);
}

/* AS path parse function. If there is same AS path in the the AS
   path hash then return it else make new AS path structure. */
struct aspath *aspath_parse(struct bgp_peer *peer, char *s, size_t length, int use32bit)
{
  struct bgp_rt_structs *inter_domain_routing_db;
  struct aspath as;
  struct aspath *find;

  if (!peer) return NULL;

  inter_domain_routing_db = bgp_select_routing_db(peer->type);

  if (!inter_domain_routing_db) return NULL;

  /* If length is odd it's malformed AS path. */
  /* Nit-picking: if (use32bit == 0) it is malformed if odd,
   * otherwise its malformed when length is larger than 2 and (length-2) 
   * is not dividable by 4.
   * But... this time we're lazy
   */
  if (length % AS16_VALUE_SIZE ) return NULL;

  memset (&as, 0, sizeof (struct aspath));
  as.segments = assegments_parse(s, length, use32bit);
  
  /* If already same aspath exist then return it. */
  find = hash_get (peer, inter_domain_routing_db->ashash, &as, aspath_hash_alloc);
  
  /* aspath_hash_alloc dupes segments too. that probably could be
   * optimised out.
   */
  assegment_free_all (as.segments);
  if (as.str)
    free(as.str);
  
  if (! find)
    return NULL;
  find->refcnt++;

  return find;
}

/* When a BGP router receives an UPDATE with an MP_REACH_NLRI
   attribute, check the leftmost AS number in the AS_PATH attribute is
   or not the peer's AS number. */ 
int
aspath_firstas_check (struct aspath *aspath, as_t asno)
{
  if ( (aspath == NULL) || (aspath->segments == NULL) )
    return 0;
  
  if (aspath->segments
      && (aspath->segments->type == AS_SEQUENCE)
      && (aspath->segments->as[0] == asno ))
    return 1;

  return 0;
}

/* AS path loop check.  If aspath contains asno then return >= 1. */
int
aspath_loop_check (struct aspath *aspath, as_t asno)
{
  struct assegment *seg;
  int count = 0;

  if ( (aspath == NULL) || (aspath->segments == NULL) )
    return 0;
  
  seg = aspath->segments;
  
  while (seg)
    {
      int i;
      
      for (i = 0; i < seg->length; i++)
	if (seg->as[i] == asno)
	  count++;
      
      seg = seg->next;
    }
  return count;
}

/* When all of AS path is private AS return 1.  */
int
aspath_private_as_check (struct aspath *aspath)
{
  struct assegment *seg;
  
  if ( !(aspath && aspath->segments) )
    return 0;
    
  seg = aspath->segments;

  while (seg)
    {
      int i;
      
      for (i = 0; i < seg->length; i++)
	{
	  if ( (seg->as[i] < BGP_PRIVATE_AS_MIN)
	      || (seg->as[i] > BGP_PRIVATE_AS_MAX) )
	    return 0;
	}
      seg = seg->next;
    }
  return 1;
}

/* Merge as1 to as2.  as2 should be uninterned aspath. */
static struct aspath *
aspath_merge (struct aspath *as1, struct aspath *as2)
{
  struct assegment *last, *new;

  if (! as1 || ! as2)
    return NULL;

  last = new = assegment_dup_all (as1->segments);
  
  /* find the last valid segment */
  while (last && last->next)
    last = last->next;
  
  last->next = as2->segments;
  as2->segments = new;
  aspath_str_update (as2);
  return as2;
}

/* Compare leftmost AS value for MED check.  If as1's leftmost AS and
   as2's leftmost AS is same return 1. */
int
aspath_cmp_left (const struct aspath *aspath1, const struct aspath *aspath2)
{
  const struct assegment *seg1 = NULL;
  const struct assegment *seg2 = NULL;

  if (!(aspath1 && aspath2))
    return 0;

  seg1 = aspath1->segments;
  seg2 = aspath2->segments;

  /* find first non-confed segments for each */
  while (seg1 && ((seg1->type == AS_CONFED_SEQUENCE)
		  || (seg1->type == AS_CONFED_SET)))
    seg1 = seg1->next;

  while (seg2 && ((seg2->type == AS_CONFED_SEQUENCE)
		  || (seg2->type == AS_CONFED_SET)))
    seg2 = seg2->next;

  /* Check as1's */
  if (!(seg1 && seg2
	&& (seg1->type == AS_SEQUENCE) && (seg2->type == AS_SEQUENCE)))
    return 0;
  
  if (seg1->as[0] == seg2->as[0])
    return 1;

  return 0;
}

/* Truncate an aspath after a number of hops, and put the hops remaining
 * at the front of another aspath.  Needed for AS4 compat.
 *
 * Returned aspath is a /new/ aspath, which should either by free'd or
 * interned by the caller, as desired.
 */
struct aspath *
aspath_reconcile_as4 (struct aspath *aspath, struct aspath *as4path)
{
  struct assegment *seg, *newseg, *prevseg = NULL;
  struct aspath *newpath = NULL, *mergedpath;
  int hops, cpasns = 0;
  
  if (!aspath) return NULL;
  
  seg = aspath->segments;
  
  /* CONFEDs should get reconciled too.. */
  hops = (aspath_count_hops (aspath) + aspath_count_confeds (aspath))
         - aspath_count_hops (as4path);
  
  if (hops < 0)
    {
      /* Something's gone wrong. The RFC says we should now ignore AS4_PATH,
       * which is daft behaviour - it contains vital loop-detection
       * information which must have been removed from AS_PATH.
       */
       hops = aspath_count_hops (aspath);
    }
  
  if (!hops)
   return aspath_dup (as4path);
  
  while (seg && hops > 0)
    {
      switch (seg->type)
        {
          case AS_SET:
          case AS_CONFED_SET:
            hops--;
            cpasns = seg->length;
            break;
          case AS_CONFED_SEQUENCE:
	    /* Should never split a confed-sequence, if hop-count
	     * suggests we must then something's gone wrong somewhere.
	     *
	     * Most important goal is to preserve AS_PATHs prime function
	     * as loop-detector, so we fudge the numbers so that the entire
	     * confed-sequence is merged in.
	     */
	    if (hops < seg->length)
	      {
	        hops = seg->length;
	      }
	  case AS_SEQUENCE:
	    cpasns = MIN(seg->length, hops);
	    hops -= seg->length;
	}
      
      assert (cpasns <= seg->length);
      
      newseg = assegment_new (seg->type, 0);
      newseg = assegment_append_asns (newseg, seg->as, cpasns);

      if (!newpath)
        {
          newpath = aspath_new ();
          newpath->segments = newseg;
        }
      else
        prevseg->next = newseg;

      prevseg = newseg;
      seg = seg->next;
    }
    
  /* We may be able to join some segments here, and we must
   * do this because... we want normalised aspaths in out hash
   * and we do not want to stumble in aspath_put.
   */
  mergedpath = aspath_merge (newpath, aspath_dup(as4path));
  aspath_free (newpath);
  mergedpath->segments = assegment_normalise (mergedpath->segments);
  aspath_str_update (mergedpath);
  
  return mergedpath;
}

/* Compare leftmost AS value for MED check.  If as1's leftmost AS and
   as2's leftmost AS is same return 1. (confederation as-path
   only).  */
int
aspath_cmp_left_confed (const struct aspath *aspath1, const struct aspath *aspath2)
{
  if (! (aspath1 && aspath2) )
    return 0;
  
  if ( !(aspath1->segments && aspath2->segments) )
    return 0;
  
  if ( (aspath1->segments->type != AS_CONFED_SEQUENCE)
      || (aspath2->segments->type != AS_CONFED_SEQUENCE) )
    return 0;
  
  if (aspath1->segments->as[0] == aspath2->segments->as[0])
    return 1;

  return 0;
}

/* Make hash value by raw aspath data. */
unsigned int
aspath_key_make (void *p)
{
  struct aspath * aspath = (struct aspath *) p;
  unsigned int key = 0;

  if (!aspath->str)
    aspath_str_update (aspath);

  key = jhash (aspath->str, strlen(aspath->str), 2334325);

  return key;
}

/* If two aspath have same value then return 1 else return 0 */
static int
aspath_cmp (const void *arg1, const void *arg2)
{
  const struct assegment *seg1 = ((struct aspath *)arg1)->segments;
  const struct assegment *seg2 = ((struct aspath *)arg2)->segments;

  while (seg1 || seg2)
    {
      int i;
      if ((!seg1 && seg2) || (seg1 && !seg2))
	return 0;
      if (seg1->type != seg2->type)
        return 0;      
      if (seg1->length != seg2->length)
        return 0;
      for (i = 0; i < seg1->length; i++)
        if (seg1->as[i] != seg2->as[i])
          return 0;
      seg1 = seg1->next;
      seg2 = seg2->next;
    }
  return 1;
}

/* AS path hash initialize. */
void
aspath_init (int buckets, struct hash **loc_ashash)
{
  (*loc_ashash) = hash_create_size (32767, aspath_key_make, aspath_cmp);
}

/* return and as path value */
const char *
aspath_print (struct aspath *as)
{
  return (as ? as->str : NULL);
}

/* Return next token and point for string parse. */
const char *
aspath_gettoken (const char *buf, enum as_token *token, as_t *asno)
{
  const char *p = buf;

  /* Skip seperators (space for sequences, ',' for sets). */
  while (isspace ((int) *p) || *p == ',') p++;

  /* Check the end of the string and type specify characters
     (e.g. {}()). */
  switch (*p) {
  case '\0':
    return NULL;
  case '{':
    *token = as_token_set_start;
    p++;
    return p;
  case '}':
    *token = as_token_set_end;
    p++;
    return p;
  case '(':
    *token = as_token_confed_seq_start;
    p++;
    return p;
  case ')':
    *token = as_token_confed_seq_end;
    p++;
    return p;
  case '[':
    *token = as_token_confed_set_start;
    p++;
    return p;
  case ']':
    *token = as_token_confed_set_end;
    p++;
    return p;
  }

  /* Check actual AS value. */
  if (isdigit ((int) *p)) {
    as_t asval;

    *token = as_token_asval;
    asval = (*p - '0');
    p++;

    while (isdigit ((int) *p)) {
      asval *= 10;
      asval += (*p - '0');
      p++;
    }

    *asno = asval;
    return p;
  }

  /* There is no match then return unknown token. */
  *token = as_token_unknown;
  return  p++;
}

struct aspath *
aspath_str2aspath (const char *str)
{
  enum as_token token = as_token_unknown;
  u_short as_type;
  as_t asno = 0;
  struct aspath *aspath;
  int needtype;

  aspath = aspath_new ();

  /* We start default type as AS_SEQUENCE. */
  as_type = AS_SEQUENCE;
  needtype = 1;

  while ((str = aspath_gettoken (str, &token, &asno)) != NULL) {
    switch (token) {
    case as_token_asval:
      if (needtype) {
        aspath_segment_add (aspath, as_type);
        needtype = 0;
      }

      aspath_as_add (aspath, asno);
      break;
    case as_token_set_start:
      as_type = AS_SET;
      aspath_segment_add (aspath, as_type);
      needtype = 0;
      break;
    case as_token_set_end:
      as_type = AS_SEQUENCE;
      needtype = 1;
      break;
    case as_token_confed_seq_start:
      as_type = AS_CONFED_SEQUENCE;
      aspath_segment_add (aspath, as_type);
      needtype = 0;
      break;
    case as_token_confed_seq_end:
      as_type = AS_SEQUENCE;
      needtype = 1;
      break;
    case as_token_confed_set_start:
      as_type = AS_CONFED_SET;
      aspath_segment_add (aspath, as_type);
      needtype = 0;
      break;
    case as_token_confed_set_end:
      as_type = AS_SEQUENCE;
      needtype = 1;
      break;
    case as_token_unknown:
    default:
      aspath_free (aspath);
      return NULL;
    }
  }

  aspath_make_str_count (aspath);

  return aspath;
}

struct aspath *
aspath_ast2aspath (as_t asn)
{
  struct aspath *aspath;

  aspath = aspath_new ();
  aspath_segment_add (aspath, AS_SEQUENCE);
  aspath_as_add (aspath, asn);
  aspath_make_str_count (aspath);

  return aspath;
}

struct aspath *
aspath_parse_ast(struct bgp_peer *peer, as_t asn)
{
  struct bgp_rt_structs *inter_domain_routing_db;
  struct aspath *aspath, *find;

  if (!peer) return NULL;

  inter_domain_routing_db = bgp_select_routing_db(peer->type);

  if (!inter_domain_routing_db) return NULL;

  aspath = aspath_ast2aspath(asn);
  find = hash_get (peer, inter_domain_routing_db->ashash, aspath, aspath_hash_alloc);

  /* aspath_hash_alloc dupes stuff */
  assegment_free_all (aspath->segments);
  if (aspath->str) free(aspath->str);
  free(aspath);

  if (!find) return NULL;

  find->refcnt++;

  return find;
}

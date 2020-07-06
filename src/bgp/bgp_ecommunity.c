/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2020 by Paolo Lucente
*/

/*
 Originally based on Quagga BGP extended community attribute related
 functions which is:

 Copyright (C) 2000 Kunihiro Ishiguro <kunihiro@zebra.org>

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
#include "bgp_prefix.h"
#include "bgp.h"

/* Allocate a new ecommunities.  */
struct ecommunity *
ecommunity_new (struct bgp_peer *peer)
{
  struct bgp_misc_structs *bms;
  void *tmp;

  if (!peer) return NULL;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) return NULL;

  tmp = malloc(sizeof (struct ecommunity));
  if (!tmp) {
    Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (ecommunity_new). Exiting ..\n", config.name, bms->log_str);
    exit_gracefully(1);
  }
  memset(tmp, 0, sizeof (struct ecommunity));

  return (struct ecommunity *) tmp;
}

/* Allocate ecommunities.  */
void
ecommunity_free (struct ecommunity *ecom)
{
  if (ecom->val) free(ecom->val);
  if (ecom->str) free(ecom->str);
  free(ecom);
}

/* Add a new Extended Communities value to Extended Communities
   Attribute structure.  When the value is already exists in the
   structure, we don't add the value.  Newly added value is sorted by
   numerical order.  When the value is added to the structure return 1
   else return 0.  */
static int
ecommunity_add_val (struct bgp_peer *peer, struct ecommunity *ecom, struct ecommunity_val *eval)
{
  struct bgp_misc_structs *bms;
  u_int8_t *p;
  int ret;
  int c;

  if (!peer) return ERR;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) return ERR;

  /* When this is fist value, just add it.  */
  if (ecom->val == NULL)
    {
      ecom->size++;
      ecom->val = malloc(ecom_length (ecom));
      if (!ecom->val) {
	Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (ecommunity_add_val). Exiting ..\n", config.name, bms->log_str);
	exit_gracefully(1);
      }
      memcpy (ecom->val, eval->val, ECOMMUNITY_SIZE);
      return 1;
    }

  /* If the value already exists in the structure return 0.  */
  c = 0;
  for (p = ecom->val; c < ecom->size; p += ECOMMUNITY_SIZE, c++)
    {
      ret = memcmp (p, eval->val, ECOMMUNITY_SIZE);
      if (ret == 0)
        return 0;
      if (ret > 0)
        break;
    }

  /* Add the value to the structure with numerical sorting.  */
  ecom->size++;
  ecom->val = realloc(ecom->val, ecom_length (ecom));

  memmove (ecom->val + (c + 1) * ECOMMUNITY_SIZE,
	   ecom->val + c * ECOMMUNITY_SIZE,
	   (ecom->size - 1 - c) * ECOMMUNITY_SIZE);
  memcpy (ecom->val + c * ECOMMUNITY_SIZE, eval->val, ECOMMUNITY_SIZE);

  return 1;
}

/* This function takes pointer to Extended Communites strucutre then
   create a new Extended Communities structure by uniq and sort each
   Exteneded Communities value.  */
static struct ecommunity *
ecommunity_uniq_sort (struct bgp_peer *peer, struct ecommunity *ecom)
{
  int i;
  struct ecommunity *new;
  struct ecommunity_val *eval;
  
  if (!ecom) return NULL;
  
  new = ecommunity_new (peer);
  
  for (i = 0; i < ecom->size; i++)
    {
      eval = (struct ecommunity_val *) (ecom->val + (i * ECOMMUNITY_SIZE));
      ecommunity_add_val (peer, new, eval);
    }
  return new;
}

/* Parse Extended Communites Attribute in BGP packet.  */
struct ecommunity *
ecommunity_parse (struct bgp_peer *peer, u_int8_t *pnt, u_short length)
{
  struct ecommunity tmp;
  struct ecommunity *new;

  /* Length check.  */
  if (length % ECOMMUNITY_SIZE)
    return NULL;

  /* Prepare tmporary structure for making a new Extended Communities
     Attribute.  */
  tmp.size = length / ECOMMUNITY_SIZE;
  tmp.val = pnt;

  /* Create a new Extended Communities Attribute by uniq and sort each
     Extended Communities value  */
  new = ecommunity_uniq_sort (peer, &tmp);

  return ecommunity_intern (peer, new);
}

/* Intern Extended Communities Attribute.  */
struct ecommunity *
ecommunity_intern (struct bgp_peer *peer, struct ecommunity *ecom)
{
  struct bgp_rt_structs *inter_domain_routing_db;
  struct ecommunity *find;

  if (!peer) return NULL;

  inter_domain_routing_db = bgp_select_routing_db(peer->type);

  if (!inter_domain_routing_db) return NULL;

  assert (ecom->refcnt == 0);

  find = (struct ecommunity *) hash_get(peer, inter_domain_routing_db->ecomhash, ecom, hash_alloc_intern);

  if (find != ecom)
    ecommunity_free (ecom);

  find->refcnt++;

  if (! find->str)
    find->str = ecommunity_ecom2str (peer, find, ECOMMUNITY_FORMAT_DISPLAY);

  return find;
}

/* Unintern Extended Communities Attribute.  */
void
ecommunity_unintern (struct bgp_peer *peer, struct ecommunity *ecom)
{
  struct bgp_rt_structs *inter_domain_routing_db;
  struct ecommunity *ret = NULL;
  (void) ret;

  if (!peer) return;

  inter_domain_routing_db = bgp_select_routing_db(peer->type);

  if (!inter_domain_routing_db) return;

  if (ecom->refcnt)
    ecom->refcnt--;

  /* Pull off from hash.  */
  if (ecom->refcnt == 0) {
    /* Extended community must be in the hash.  */
    ret = (struct ecommunity *) hash_release(inter_domain_routing_db->ecomhash, ecom);
    assert (ret != NULL);

    ecommunity_free(ecom);
  }
}

/* Utinity function to make hash key.  */
unsigned int
ecommunity_hash_make (void *arg)
{
  const struct ecommunity *ecom = arg;
  int c;
  unsigned int key;
  u_int8_t *pnt;

  key = 0;
  pnt = ecom->val;
  
  for (c = 0; c < ecom->size * ECOMMUNITY_SIZE; c++)
    key += pnt[c];

  return key;
}

/* Compare two Extended Communities Attribute structure.  */
int
ecommunity_cmp (const void *arg1, const void *arg2)
{
  const struct ecommunity *ecom1 = arg1;
  const struct ecommunity *ecom2 = arg2;
  
  return (ecom1->size == ecom2->size
	  && memcmp (ecom1->val, ecom2->val, ecom1->size * ECOMMUNITY_SIZE) == 0);
}

/* Initialize Extended Comminities related hash. */
void
ecommunity_init (int buckets, struct hash **loc_ecomhash)
{
  (*loc_ecomhash) = hash_create (buckets, ecommunity_hash_make, ecommunity_cmp);
}

/* Convert extended community attribute to string.  

   Due to historical reason of industry standard implementation, there
   are three types of format.

   route-map set extcommunity format
        "rt 100:1 100:2"
        "soo 100:3"

   extcommunity-list
        "rt 100:1 rt 100:2 soo 100:3"

   "show ip bgp" and extcommunity-list regular expression matching
        "RT:100:1 RT:100:2 SoO:100:3"

   For each formath please use below definition for format:

   ECOMMUNITY_FORMAT_ROUTE_MAP
   ECOMMUNITY_FORMAT_COMMUNITY_LIST
   ECOMMUNITY_FORMAT_DISPLAY
*/
char *
ecommunity_ecom2str (struct bgp_peer *peer, struct ecommunity *ecom, int format)
{
  struct bgp_misc_structs *bms;
  int i;
  u_int8_t *pnt;
  int encode = 0;
  int type = 0;
#define ECOMMUNITY_STR_DEFAULT_LEN  27
  int str_size;
  int str_pnt;
  char *str_buf;
  const char *prefix;
  int len = 0;
  int first = 1;

  /* For parse Extended Community attribute tupple. */
  struct ecommunity_as
  {
    as_t as;
    u_int32_t val;
  } eas;

  struct ecommunity_ip
  {
    struct in_addr ip;
    u_int16_t val;
  } eip;

  if (!peer) return NULL;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) return NULL;

  if (ecom->size == 0)
    {
      str_buf = malloc(1);
      if (!str_buf) {
	Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (ecommunity_ecom2str). Exiting ..\n", config.name, bms->log_str);
	exit_gracefully(1);
      }
      str_buf[0] = '\0';
      return str_buf;
    }

  /* Prepare buffer.  */
  str_buf = malloc(ECOMMUNITY_STR_DEFAULT_LEN + 1);
  if (!str_buf) {
    Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (ecommunity_ecom2str). Exiting ..\n", config.name, bms->log_str);
    exit_gracefully(1);
  }
  str_size = ECOMMUNITY_STR_DEFAULT_LEN + 1;
  str_pnt = 0;

  for (i = 0; i < ecom->size; i++)
    {
      /* Make it sure size is enough.  */
      while (str_pnt + ECOMMUNITY_STR_DEFAULT_LEN >= str_size)
        {
          str_size *= 2;
          str_buf = realloc(str_buf, str_size);
        }

      /* Space between each value.  */
      if (! first)
	str_buf[str_pnt++] = ' ';

      pnt = ecom->val + (i * 8);

      /* High-order octet of type. */
      encode = *pnt++;
      if (encode != ECOMMUNITY_ENCODE_AS && encode != ECOMMUNITY_ENCODE_IP
		      && encode != ECOMMUNITY_ENCODE_AS4)
	{
	  len = sprintf (str_buf + str_pnt, "?");
	  str_pnt += len;
	  first = 0;
	  continue;
	}
      
      /* Low-order octet of type. */
      type = *pnt++;
      if (type !=  ECOMMUNITY_ROUTE_TARGET && type != ECOMMUNITY_SITE_ORIGIN)
	{
	  len = sprintf (str_buf + str_pnt, "?");
	  str_pnt += len;
	  first = 0;
	  continue;
	}

      switch (format)
	{
	case ECOMMUNITY_FORMAT_COMMUNITY_LIST:
	  prefix = (type == ECOMMUNITY_ROUTE_TARGET ? "rt " : "soo ");
	  break;
	case ECOMMUNITY_FORMAT_DISPLAY:
	  prefix = (type == ECOMMUNITY_ROUTE_TARGET ? "RT:" : "SoO:");
	  break;
	case ECOMMUNITY_FORMAT_ROUTE_MAP:
	  prefix = "";
	  break;
	default:
	  prefix = "";
	  break;
	}

      /* Put string into buffer.  */
      if (encode == ECOMMUNITY_ENCODE_AS4)
	{
	  eas.as = (*pnt++ << 24);
	  eas.as |= (*pnt++ << 16);
	  eas.as |= (*pnt++ << 8);
	  eas.as |= (*pnt++);

	  eas.val = (*pnt++ << 8);
	  eas.val |= (*pnt++);

	  len = sprintf( str_buf + str_pnt, "%s%u:%u", prefix,
                        eas.as, eas.val );
	  str_pnt += len;
	  first = 0;
	}
      if (encode == ECOMMUNITY_ENCODE_AS)
	{
	  eas.as = (*pnt++ << 8);
	  eas.as |= (*pnt++);

	  eas.val = (*pnt++ << 24);
	  eas.val |= (*pnt++ << 16);
	  eas.val |= (*pnt++ << 8);
	  eas.val |= (*pnt++);

	  len = sprintf (str_buf + str_pnt, "%s%u:%u", prefix,
			 eas.as, eas.val);
	  str_pnt += len;
	  first = 0;
	}
      else if (encode == ECOMMUNITY_ENCODE_IP)
	{
	  memcpy (&eip.ip, pnt, 4);
	  pnt += 4;
	  eip.val = (*pnt++ << 8);
	  eip.val |= (*pnt++);

	  len = sprintf (str_buf + str_pnt, "%s%s:%u", prefix,
			 inet_ntoa (eip.ip), eip.val);
	  str_pnt += len;
	  first = 0;
	}
    }
  return str_buf;
}

struct ecommunity *ecommunity_dup(struct ecommunity *ecom)
{
  struct ecommunity *new;

  new = malloc(sizeof(struct ecommunity));

  new->size = ecom->size;

  if (new->size) {
    new->val = malloc(ecom->size * ECOMMUNITY_SIZE);
    memcpy (new->val, ecom->val, ecom->size * ECOMMUNITY_SIZE);
  }
  else new->val = NULL;

  return new;
}

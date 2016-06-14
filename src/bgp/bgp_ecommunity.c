/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2016 by Paolo Lucente
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

#define __BGP_ECOMMUNITY_C

#include "pmacct.h"
#include "bgp_prefix.h"
#include "bgp.h"

/* Hash of community attribute. */
// struct hash *ecomhash;

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
    exit_all(1);
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
	exit_all(1);
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

/* Retrun string representation of communities attribute. */
char *
ecommunity_str (struct bgp_peer *peer, struct ecommunity *ecom)
{
  if (! ecom->str)
    ecom->str = ecommunity_ecom2str (peer, ecom, ECOMMUNITY_FORMAT_DISPLAY);
  return ecom->str;
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
  struct ecommunity *ret;

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

/* Extended Communities token enum. */
enum ecommunity_token
{
  ecommunity_token_rt,
  ecommunity_token_soo,
  ecommunity_token_val,
  ecommunity_token_unknown
};

/* Get next Extended Communities token from the string. */
static const char *
ecommunity_gettoken (const char *str, struct ecommunity_val *eval,
		     enum ecommunity_token *token)
{
  int ret;
  int dot = 0;
  int digit = 0;
  int separator = 0;
  const char *p = str;
  char *endptr;
  struct in_addr ip;
  as_t as = 0;
  u_int32_t val = 0;
  char buf[INET_ADDRSTRLEN + 1];

  /* Skip white space. */
  while (isspace ((int) *p))
    {
      p++;
      str++;
    }

  /* Check the end of the line. */
  if (*p == '\0')
    return NULL;

  /* "rt" and "soo" keyword parse. */
  if (! isdigit ((int) *p)) 
    {
      /* "rt" match check.  */
      if (tolower ((int) *p) == 'r')
	{
	  p++;
 	  if (tolower ((int) *p) == 't')
	    {
	      p++;
	      *token = ecommunity_token_rt;
	      return p;
	    }
	  if (isspace ((int) *p) || *p == '\0')
	    {
	      *token = ecommunity_token_rt;
	      return p;
	    }
	  goto error;
	}
      /* "soo" match check.  */
      else if (tolower ((int) *p) == 's')
	{
	  p++;
 	  if (tolower ((int) *p) == 'o')
	    {
	      p++;
	      if (tolower ((int) *p) == 'o')
		{
		  p++;
		  *token = ecommunity_token_soo;
		  return p;
		}
	      if (isspace ((int) *p) || *p == '\0')
		{
		  *token = ecommunity_token_soo;
		  return p;
		}
	      goto error;
	    }
	  if (isspace ((int) *p) || *p == '\0')
	    {
	      *token = ecommunity_token_soo;
	      return p;
	    }
	  goto error;
	}
      goto error;
    }
  
  /* What a mess, there are several possibilities:
   *
   * a) A.B.C.D:MN
   * b) EF:OPQR
   * c) GHJK:MN
   *
   * A.B.C.D: Four Byte IP
   * EF:      Two byte ASN
   * GHJK:    Four-byte ASN
   * MN:      Two byte value
   * OPQR:    Four byte value
   *
   */
  while (isdigit ((int) *p) || *p == ':' || *p == '.') 
    {
      if (*p == ':')
	{
	  if (separator)
	    goto error;

	  separator = 1;
	  digit = 0;
	  
	  if ((p - str) > INET_ADDRSTRLEN)
	    goto error;
          memset (buf, 0, INET_ADDRSTRLEN + 1);
          memcpy (buf, str, p - str);
          
	  if (dot)
	    {
	      /* Parsing A.B.C.D in:
               * A.B.C.D:MN
               */
	      ret = inet_aton (buf, &ip);
	      if (ret == 0)
	        goto error;
	    }
          else
            {
              /* ASN */
              as = strtoul (buf, &endptr, 10);
              if (*endptr != '\0' || as == BGP_AS4_MAX)
                goto error;
            }
	}
      else if (*p == '.')
	{
	  if (separator)
	    goto error;
	  dot++;
	  if (dot > 4)
	    goto error;
	}
      else
	{
	  digit = 1;
	  
	  /* We're past the IP/ASN part */
	  if (separator)
	    {
	      val *= 10;
	      val += (*p - '0');
            }
	}
      p++;
    }

  /* Low digit part must be there. */
  if (!digit || !separator)
    goto error;

  /* Encode result into routing distinguisher.  */
  if (dot)
    {
      if (val > UINT16_MAX)
        goto error;
      
      eval->val[0] = ECOMMUNITY_ENCODE_IP;
      eval->val[1] = 0;
      memcpy (&eval->val[2], &ip, sizeof (struct in_addr));
      eval->val[6] = (val >> 8) & 0xff;
      eval->val[7] = val & 0xff;
    }
  else if (as > BGP_AS_MAX)
    {
      if (val > UINT16_MAX)
        goto error;
      
      eval->val[0] = ECOMMUNITY_ENCODE_AS4;
      eval->val[1] = 0;
      eval->val[2] = (as >>24) & 0xff;
      eval->val[3] = (as >>16) & 0xff;
      eval->val[4] = (as >>8) & 0xff;
      eval->val[5] =  as & 0xff;
      eval->val[6] = (val >> 8) & 0xff;
      eval->val[7] = val & 0xff;
    }
  else
    {
      eval->val[0] = ECOMMUNITY_ENCODE_AS;
      eval->val[1] = 0;
      
      eval->val[2] = (as >>8) & 0xff;
      eval->val[3] = as & 0xff;
      eval->val[4] = (val >>24) & 0xff;
      eval->val[5] = (val >>16) & 0xff;
      eval->val[6] = (val >>8) & 0xff;
      eval->val[7] = val & 0xff;
    }
  *token = ecommunity_token_val;
  return p;

 error:
  *token = ecommunity_token_unknown;
  return p;
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
	exit_all(1);
      }
      str_buf[0] = '\0';
      return str_buf;
    }

  /* Prepare buffer.  */
  str_buf = malloc(ECOMMUNITY_STR_DEFAULT_LEN + 1);
  if (!str_buf) {
    Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (ecommunity_ecom2str). Exiting ..\n", config.name, bms->log_str);
    exit_all(1);
  }
  str_size = ECOMMUNITY_STR_DEFAULT_LEN + 1;
  str_pnt = 0;

  for (i = 0; i < ecom->size; i++)
    {
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

      /* Make it sure size is enough.  */
      while (str_pnt + ECOMMUNITY_STR_DEFAULT_LEN >= str_size)
	{
	  str_size *= 2;
	  str_buf = realloc(str_buf, str_size);
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

	  len = sprintf( str_buf + str_pnt, "%s%d:%d", prefix,
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

	  len = sprintf (str_buf + str_pnt, "%s%d:%d", prefix,
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

	  len = sprintf (str_buf + str_pnt, "%s%s:%d", prefix,
			 inet_ntoa (eip.ip), eip.val);
	  str_pnt += len;
	  first = 0;
	}
    }
  return str_buf;
}

int
ecommunity_match (const struct ecommunity *ecom1, 
                  const struct ecommunity *ecom2)
{
  int i = 0;
  int j = 0;

  if (ecom1 == NULL && ecom2 == NULL)
    return 1;

  if (ecom1 == NULL || ecom2 == NULL)
    return 0;

  if (ecom1->size < ecom2->size)
    return 0;

  /* Every community on com2 needs to be on com1 for this to match */
  while (i < ecom1->size && j < ecom2->size)
    {
      if (memcmp (ecom1->val + i, ecom2->val + j, ECOMMUNITY_SIZE) == 0)
        j++;
      i++;
    }

  if (j == ecom2->size)
    return 1;
  else
    return 0;
}


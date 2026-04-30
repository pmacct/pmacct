/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2025 by Paolo Lucente
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
#include <stddef.h>
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
int
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

static int
ecommunity_snprintf_hex_full(char *dst, size_t dst_sz, const u_int8_t *ec)
{
  return snprintf(dst, dst_sz,
                  "EC:0x%02x%02x%02x%02x%02x%02x%02x%02x",
                  ec[0], ec[1], ec[2], ec[3], ec[4], ec[5], ec[6], ec[7]);
}

static int
ecommunity_snprintf_evpn_unknown(char *dst, size_t dst_sz, u_int8_t subtype, const u_int8_t *val)
{
  return snprintf(dst, dst_sz,
                  "EVPN:Unknown(0x%02x):0x%02x%02x%02x%02x%02x%02x",
                  subtype, val[0], val[1], val[2], val[3], val[4], val[5]);
}

static const char *
ecommunity_tunnel_type_name(u_int16_t t)
{
  switch (t) {
  case 1: return "UDP";
  case 2: return "TCP";
  case 3: return "IP-in-IP";
  case 4: return "GRE";
  case 5: return "MPLS";
  case 8: return "VXLAN";
  case 9: return "NVGRE";
  case 12: return "MPLS-in-GRE";
  default: return NULL;
  }
}

/*
   Encapsulation Extended Community (RFC 5512 / RFC 9012):
   Transitive Opaque, sub-type Encapsulation; tunnel type in last two octets of value.
*/
static int
ecommunity_encap_val2str(char *dst, size_t dst_sz, const u_int8_t *val)
{
  u_int16_t tun = ((u_int16_t)val[4] << 8) | (u_int16_t)val[5];
  const char *tn = ecommunity_tunnel_type_name(tun);

  if (tn)
    return snprintf(dst, dst_sz,
                    "Encapsulation:tunnel-type=%u(%s):reserved=0x%02x%02x%02x%02x",
                    (unsigned)tun, tn, val[0], val[1], val[2], val[3]);
  return snprintf(dst, dst_sz,
                  "Encapsulation:tunnel-type=%u:reserved=0x%02x%02x%02x%02x",
                  (unsigned)tun, val[0], val[1], val[2], val[3]);
}

static int
ecommunity_legacy_ospf_val2str(char *dst, size_t dst_sz, u_int8_t subtype, const u_int8_t *val)
{
  if (subtype == 0x00) {
    u_int32_t area = ((u_int32_t)val[0] << 24) | ((u_int32_t)val[1] << 16) |
                     ((u_int32_t)val[2] << 8) | (u_int32_t)val[3];
    return snprintf(dst, dst_sz, "OSPF-RT:area=%u:route-type=%u:options=0x%02x",
                    area, val[4], val[5]);
  }
  else if (subtype == 0x01) {
    return snprintf(dst, dst_sz, "OSPF-RID:%u.%u.%u.%u",
                    val[0], val[1], val[2], val[3]);
  }

  return ERR;
}

static int
ecommunity_evpn_val2str(char *dst, size_t dst_sz, u_int8_t subtype, const u_int8_t *val)
{
  u_int32_t seq;

  switch (subtype) {
  case ECOMMUNITY_EVPN_MAC_MOBILITY:
    seq = ((u_int32_t)val[2] << 24) | ((u_int32_t)val[3] << 16) |
          ((u_int32_t)val[4] << 8) | (u_int32_t)val[5];
    return snprintf(dst, dst_sz,
                    "MACMobility:flags=0x%02x:reserved=0x%02x:seq=%u",
                    val[0], val[1], seq);

  case ECOMMUNITY_EVPN_ESI_LABEL:
    return snprintf(dst, dst_sz,
                    "ESILabel:flags=0x%02x:value=0x%02x%02x%02x%02x%02x",
                    val[0], val[1], val[2], val[3], val[4], val[5]);

  case ECOMMUNITY_EVPN_ES_IMPORT:
    return snprintf(dst, dst_sz,
                    "ESImport:%02x:%02x:%02x:%02x:%02x:%02x",
                    val[0], val[1], val[2], val[3], val[4], val[5]);

  case ECOMMUNITY_EVPN_ROUTER_MAC:
    return snprintf(dst, dst_sz,
                    "EVPNRouterMAC:%02x:%02x:%02x:%02x:%02x:%02x",
                    val[0], val[1], val[2], val[3], val[4], val[5]);

  case ECOMMUNITY_EVPN_LAYER2_ATTR:
    return snprintf(dst, dst_sz,
                    "L2Attrs:0x%02x%02x%02x%02x%02x%02x",
                    val[0], val[1], val[2], val[3], val[4], val[5]);

  case ECOMMUNITY_EVPN_ETREE:
    return snprintf(dst, dst_sz,
                    "ETree:0x%02x%02x%02x%02x%02x%02x",
                    val[0], val[1], val[2], val[3], val[4], val[5]);

  case ECOMMUNITY_EVPN_DF_ELECTION:
    return snprintf(dst, dst_sz,
                    "DFElection:0x%02x%02x%02x%02x%02x%02x",
                    val[0], val[1], val[2], val[3], val[4], val[5]);

  case ECOMMUNITY_EVPN_ARP_ND:
    return snprintf(dst, dst_sz,
                    "ARP/ND:0x%02x%02x%02x%02x%02x%02x",
                    val[0], val[1], val[2], val[3], val[4], val[5]);

  case ECOMMUNITY_EVPN_MCAST_FLAGS:
    return snprintf(dst, dst_sz,
                    "MulticastFlags:0x%02x%02x%02x%02x%02x%02x",
                    val[0], val[1], val[2], val[3], val[4], val[5]);

  case ECOMMUNITY_EVPN_EVI_RT0:
    return snprintf(dst, dst_sz,
                    "EVI-RT-Type0:0x%02x%02x%02x%02x%02x%02x",
                    val[0], val[1], val[2], val[3], val[4], val[5]);

  case ECOMMUNITY_EVPN_EVI_RT1:
    return snprintf(dst, dst_sz,
                    "EVI-RT-Type1:0x%02x%02x%02x%02x%02x%02x",
                    val[0], val[1], val[2], val[3], val[4], val[5]);

  case ECOMMUNITY_EVPN_EVI_RT2:
    return snprintf(dst, dst_sz,
                    "EVI-RT-Type2:0x%02x%02x%02x%02x%02x%02x",
                    val[0], val[1], val[2], val[3], val[4], val[5]);

  case ECOMMUNITY_EVPN_EVI_RT3:
    return snprintf(dst, dst_sz,
                    "EVI-RT-Type3:0x%02x%02x%02x%02x%02x%02x",
                    val[0], val[1], val[2], val[3], val[4], val[5]);

  case ECOMMUNITY_EVPN_AC:
    return snprintf(dst, dst_sz,
                    "EVPN-AC:0x%02x%02x%02x%02x%02x%02x",
                    val[0], val[1], val[2], val[3], val[4], val[5]);

  case ECOMMUNITY_EVPN_SVC_CARVING:
    return snprintf(dst, dst_sz,
                    "ServiceCarvingTime:0x%02x%02x%02x%02x%02x%02x",
                    val[0], val[1], val[2], val[3], val[4], val[5]);

  case ECOMMUNITY_EVPN_LINK_BANDWIDTH:
    return snprintf(dst, dst_sz,
                    "EVPNLinkBandwidth:0x%02x%02x%02x%02x%02x%02x",
                    val[0], val[1], val[2], val[3], val[4], val[5]);

  default:
    return ecommunity_snprintf_evpn_unknown(dst, dst_sz, subtype, val);
  }
}

#if defined(WITH_JANSSON)
static void
ecommunity_json_set_hex_full(char *dst, size_t dst_sz, const u_int8_t *ec)
{
  snprintf(dst, dst_sz, "0x%02x%02x%02x%02x%02x%02x%02x%02x",
           ec[0], ec[1], ec[2], ec[3], ec[4], ec[5], ec[6], ec[7]);
}

static void
ecommunity_json_set_hex_value(char *dst, size_t dst_sz, const u_int8_t *val)
{
  snprintf(dst, dst_sz, "0x%02x%02x%02x%02x%02x%02x",
           val[0], val[1], val[2], val[3], val[4], val[5]);
}

static void
ecommunity_json_append_string(json_t *obj, const char *key, const char *value)
{
  json_t *arr = json_object_get(obj, key);

  if (!arr) {
    arr = json_array();
    if (!arr) return;

    json_object_set_new_nocheck(obj, key, arr);
  }

  json_array_append_new(arr, json_string(value));
}

static void
ecommunity_json_append_integer(json_t *obj, const char *key, u_int32_t value)
{
  json_t *arr = json_object_get(obj, key);

  if (!arr) {
    arr = json_array();
    if (!arr) return;

    json_object_set_new_nocheck(obj, key, arr);
  }

  json_array_append_new(arr, json_integer((json_int_t)value));
}

json_t *
ecommunity_ecom2json_list(struct bgp_peer *peer, struct ecommunity *ecom)
{
  int i;
  json_t *obj;

  if (!peer || !ecom) return NULL;

  obj = json_object();
  if (!obj) return NULL;

  for (i = 0; i < ecom->size; i++) {
    u_int8_t *ec = ecom->val + (i * ECOMMUNITY_SIZE);
    u_int8_t encode = ec[0];
    u_int8_t type = ec[1];
    const u_int8_t *val = ec + 2;

    if ((encode & 0x7F) == ECOMMUNITY_TYPE_EVPN) {
      if (type == ECOMMUNITY_EVPN_ROUTER_MAC) {
        char mac[18];

        if (!json_object_get(obj, "evpn_router_mac")) {
          snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                   val[0], val[1], val[2], val[3], val[4], val[5]);
          json_object_set_new_nocheck(obj, "evpn_router_mac", json_string(mac));
        }
      }
      else if (type == ECOMMUNITY_EVPN_MAC_MOBILITY) {
        u_int32_t seq = ((u_int32_t)val[2] << 24) | ((u_int32_t)val[3] << 16) |
                        ((u_int32_t)val[4] << 8) | (u_int32_t)val[5];

        if (!json_object_get(obj, "evpn_mac_mobility_flags")) {
          json_object_set_new_nocheck(obj, "evpn_mac_mobility_flags", json_integer((json_int_t)val[0]));
        }
        if (!json_object_get(obj, "evpn_mac_mobility_seq")) {
          json_object_set_new_nocheck(obj, "evpn_mac_mobility_seq", json_integer((json_int_t)seq));
        }
      }
      else {
        char raw[24];

        ecommunity_json_set_hex_value(raw, sizeof(raw), val);
        ecommunity_json_append_integer(obj, "evpn_subtype", type);
        ecommunity_json_append_string(obj, "raw", raw);
      }
      continue;
    }

    if ((encode & 0x7F) == ECOMMUNITY_TYPE_OPAQUE && type == ECOMMUNITY_OPAQUE_ENCAPSULATION) {
      u_int16_t tun = ((u_int16_t)val[4] << 8) | (u_int16_t)val[5];

      ecommunity_json_append_integer(obj, "encapsulation_tunnel_type", tun);
      continue;
    }

    if (encode == 0x80 && type == 0x00) {
      u_int32_t area = ((u_int32_t)val[0] << 24) | ((u_int32_t)val[1] << 16) |
                       ((u_int32_t)val[2] << 8) | (u_int32_t)val[3];

      if (!json_object_get(obj, "ospf_rt_area")) {
        json_object_set_new_nocheck(obj, "ospf_rt_area", json_integer((json_int_t)area));
      }
      if (!json_object_get(obj, "ospf_rt_route_type")) {
        json_object_set_new_nocheck(obj, "ospf_rt_route_type", json_integer((json_int_t)val[4]));
      }
      if (!json_object_get(obj, "ospf_rt_options")) {
        json_object_set_new_nocheck(obj, "ospf_rt_options", json_integer((json_int_t)val[5]));
      }
      continue;
    }

    if (encode == 0x80 && type == 0x01) {
      char rid[16];

      if (!json_object_get(obj, "ospf_rid")) {
        snprintf(rid, sizeof(rid), "%u.%u.%u.%u", val[0], val[1], val[2], val[3]);
        json_object_set_new_nocheck(obj, "ospf_rid", json_string(rid));
      }
      continue;
    }

    if ((encode == ECOMMUNITY_ENCODE_AS || encode == ECOMMUNITY_ENCODE_IP || encode == ECOMMUNITY_ENCODE_AS4) &&
        (type == ECOMMUNITY_ROUTE_TARGET || type == ECOMMUNITY_SITE_ORIGIN)) {
      char comm[64];
      u_int8_t *pnt = ec + 2;
      const char *key = (type == ECOMMUNITY_ROUTE_TARGET ? "rt" : "soo");

      if (encode == ECOMMUNITY_ENCODE_AS4) {
        as_t as = (as_t)(pnt[0] << 24 | pnt[1] << 16 | pnt[2] << 8 | pnt[3]);
        u_int32_t n = (u_int32_t)(pnt[4] << 8 | pnt[5]);
        snprintf(comm, sizeof(comm), "%u:%u", as, n);
      }
      else if (encode == ECOMMUNITY_ENCODE_AS) {
        as_t as = (as_t)(pnt[0] << 8 | pnt[1]);
        u_int32_t n = (u_int32_t)(pnt[2] << 24 | pnt[3] << 16 | pnt[4] << 8 | pnt[5]);
        snprintf(comm, sizeof(comm), "%u:%u", as, n);
      }
      else {
        struct in_addr ip;
        u_int16_t n = (u_int16_t)(pnt[4] << 8 | pnt[5]);
        memcpy(&ip, pnt, 4);
        snprintf(comm, sizeof(comm), "%s:%u", inet_ntoa(ip), n);
      }

      if (type == ECOMMUNITY_SITE_ORIGIN) {
        if (!json_object_get(obj, "soo")) {
          json_object_set_new_nocheck(obj, "soo", json_string(comm));
        }
      }
      else {
        ecommunity_json_append_string(obj, key, comm);
      }
      continue;
    }

    {
      char raw[32];

      ecommunity_json_set_hex_full(raw, sizeof(raw), ec);
      ecommunity_json_append_string(obj, "raw", raw);
    }
  }

  return obj;
}
#endif

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
      u_int8_t *ec;

      /* Make it sure size is enough.  */
      while (str_pnt + ECOMMUNITY_STR_DEFAULT_LEN >= str_size)
        {
          str_size *= 2;
          str_buf = realloc(str_buf, str_size);
        }

      /* Space between each value.  */
      if (! first)
	str_buf[str_pnt++] = ' ';

      ec = ecom->val + (i * ECOMMUNITY_SIZE);
      encode = ec[0];
      type = ec[1];

      /* EVPN Extended Community (IANA type high-order octet 0x06).  */
      if ((encode & 0x7F) == ECOMMUNITY_TYPE_EVPN) {
        while (str_pnt + 160 >= str_size) {
          str_size *= 2;
          str_buf = realloc(str_buf, str_size);
        }
        len = ecommunity_evpn_val2str(str_buf + str_pnt, str_size - str_pnt, (u_int8_t) type, ec + 2);
        str_pnt += len;
        first = 0;
        continue;
      }

      /* Encapsulation Extended Community (Transitive Opaque, sub-type 0x0c).  */
      if ((encode & 0x7F) == ECOMMUNITY_TYPE_OPAQUE && type == ECOMMUNITY_OPAQUE_ENCAPSULATION) {
        while (str_pnt + 160 >= str_size) {
          str_size *= 2;
          str_buf = realloc(str_buf, str_size);
        }
        len = ecommunity_encap_val2str(str_buf + str_pnt, str_size - str_pnt, ec + 2);
        str_pnt += len;
        first = 0;
        continue;
      }

      /* RFC4577 legacy compatibility types: 0x8000 (OSPF-RT), 0x8001 (OSPF-RID). */
      if (encode == 0x80 && (type == 0x00 || type == 0x01)) {
        while (str_pnt + 96 >= str_size) {
          str_size *= 2;
          str_buf = realloc(str_buf, str_size);
        }
        len = ecommunity_legacy_ospf_val2str(str_buf + str_pnt, str_size - str_pnt,
                                             (u_int8_t) type, ec + 2);
        if (len > 0) {
          str_pnt += len;
          first = 0;
          continue;
        }
      }

      /* Unknown extended community types: full 8-octet hex (no "?").  */
      if (encode != ECOMMUNITY_ENCODE_AS && encode != ECOMMUNITY_ENCODE_IP
		      && encode != ECOMMUNITY_ENCODE_AS4)
	{
	  while (str_pnt + 64 >= str_size) {
	    str_size *= 2;
	    str_buf = realloc(str_buf, str_size);
	  }
	  len = ecommunity_snprintf_hex_full(str_buf + str_pnt, str_size - str_pnt, ec);
	  str_pnt += len;
	  first = 0;
	  continue;
	}

      /* Low-order octet of type. */
      if (type !=  ECOMMUNITY_ROUTE_TARGET && type != ECOMMUNITY_SITE_ORIGIN)
	{
	  while (str_pnt + 64 >= str_size) {
	    str_size *= 2;
	    str_buf = realloc(str_buf, str_size);
	  }
	  len = ecommunity_snprintf_hex_full(str_buf + str_pnt, str_size - str_pnt, ec);
	  str_pnt += len;
	  first = 0;
	  continue;
	}

      pnt = ec + 2;

      if (!config.bgp_comms_num) {
        switch (format) {
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
      }
      else {
	prefix = "";
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

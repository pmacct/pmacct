/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2012 by Paolo Lucente
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

#define TH_MAGIC 11071945

struct template_header {
  u_int32_t magic;
  u_int16_t num;   /* number of template entries */
  u_int16_t sz;    /* total size of template entries */ 
  u_char pad[8];
};

struct template_entry {
  u_int64_t tag;
  /* u_int64_t tag_2; XXX: not supported */
  u_int8_t size;
  u_int8_t type;  /* unused */
};

typedef void (*template_func) (u_char **, const struct db_cache *);

/* prototypes */
#if (!defined __LOG_TEMPLATES_C)
#define EXT extern
#else
#define EXT
#endif
EXT template_func template_funcs[N_PRIMITIVES];
EXT void set_template_funcs(struct template_header *, struct template_entry *);
EXT struct template_entry *build_template(struct template_header *);
EXT void TPL_check_sizes(struct template_header *, struct db_cache *, u_char *);
EXT u_int16_t TPL_push(u_char *, const struct db_cache *);
EXT void TPL_pop(u_char *, struct db_cache *, struct template_header *, u_char *);
EXT void TPL_push_src_mac(u_char **, const struct db_cache *);
EXT void TPL_push_dst_mac(u_char **, const struct db_cache *);
EXT void TPL_push_vlan(u_char **, const struct db_cache *);
EXT void TPL_push_src_ip(u_char **, const struct db_cache *);
EXT void TPL_push_dst_ip(u_char **, const struct db_cache *);
EXT void TPL_push_src_as(u_char **, const struct db_cache *);
EXT void TPL_push_dst_as(u_char **, const struct db_cache *);
EXT void TPL_push_src_port(u_char **, const struct db_cache *);
EXT void TPL_push_dst_port(u_char **, const struct db_cache *);
EXT void TPL_push_tos(u_char **, const struct db_cache *);
EXT void TPL_push_proto(u_char **, const struct db_cache *);
EXT void TPL_push_id(u_char **, const struct db_cache *);
EXT void TPL_push_class(u_char **, const struct db_cache *);
EXT void TPL_push_bytes_counter(u_char **, const struct db_cache *);
EXT void TPL_push_packet_counter(u_char **, const struct db_cache *);
EXT void TPL_push_flows_counter(u_char **, const struct db_cache *);
EXT void TPL_push_timestamp(u_char **, const struct db_cache *);
EXT void TPL_push_nol2(u_char **, const struct db_cache *);
#undef EXT

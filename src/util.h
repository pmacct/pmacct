/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2017 by Paolo Lucente
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

/* defines */
#define ADD 0
#define SUB 1

#ifdef WITH_AVRO
#define check_i(call) \
  do { \
    if ((call) != 0) { \
      Log(LOG_ERR, "Error: %s\n", avro_strerror()); \
      exit_plugin(1); \
    } \
} while (0)
#endif

/* prototypes */
#if (!defined __UTIL_C)
#define EXT extern
#else
#define EXT
#endif
EXT void setnonblocking(int);
EXT void setblocking(int);
EXT int daemonize();
EXT char *copy_argv(register char **);
EXT char *extract_token(char **, int);
EXT char *extract_plugin_name(char **);
EXT void trim_spaces(char *);
EXT void trim_all_spaces(char *);
EXT void strip_quotes(char *);
EXT void string_add_newline(char *);
EXT int isblankline(char *);
EXT int iscomment(char *);
EXT int check_not_valid_char(char *, char *, int);
EXT time_t roundoff_time(time_t, char *);
EXT time_t calc_monthly_timeslot(time_t, int, int);
EXT void write_pid_file(char *);
EXT void write_pid_file_plugin(char *, char *, char *);
EXT void remove_pid_file(char *);
EXT int sanitize_buf_net(char *, char *, int);
EXT int sanitize_buf(char *);
EXT void mark_columns(char *);
EXT int Setsocksize(int, int, int, void *, int);
EXT void *map_shared(void *, size_t, int, int, int, off_t);
EXT void lower_string(char *);
EXT void evaluate_sums(u_int64_t *, u_int64_t *, char *, char *);
EXT void stop_all_childs();
EXT int file_lock(int);
EXT int file_unlock(int);
EXT void strftime_same(char *, int, char *, const time_t *);
EXT int read_SQLquery_from_file(char *, char *, int);
EXT void stick_bosbit(u_char *);
EXT int check_bosbit(u_char *);
EXT u_int32_t decode_mpls_label(char *);
EXT int timeval_cmp(struct timeval *, struct timeval *);
EXT void exit_all(int);
EXT void exit_plugin(int);
EXT void reset_tag_label_status(struct packet_ptrs_vector *);
EXT void reset_net_status(struct packet_ptrs *);
EXT void reset_net_status_v(struct packet_ptrs_vector *);
EXT void reset_shadow_status(struct packet_ptrs_vector *);
EXT void reset_fallback_status(struct packet_ptrs *);
EXT void set_sampling_table(struct packet_ptrs_vector *, u_char *);
EXT void set_shadow_status(struct packet_ptrs *);
EXT void set_default_preferences(struct configuration *);
EXT FILE *open_output_file(char *, char *, int);
EXT void link_latest_output_file(char *, char *);
EXT void close_output_file(FILE *);
EXT void handle_dynname_internal_strings(char *, int, char *, struct primitives_ptrs *);
EXT void handle_dynname_internal_strings_same(char *, int, char *, struct primitives_ptrs *);
EXT void escape_ip_uscores(char *);
EXT int sql_history_to_secs(int, int);
EXT void *pm_malloc(size_t);
EXT void load_allow_file(char *, struct hosts_table *);
EXT int check_allow(struct hosts_table *, struct sockaddr *);
EXT int BTA_find_id(struct id_table *, struct packet_ptrs *, pm_id_t *, pm_id_t *);
EXT void calc_refresh_timeout(time_t, time_t, int *);
EXT void calc_refresh_timeout_sec(time_t, time_t, int *);
EXT int load_tags(char *, struct pretag_filter *, char *);
EXT int load_labels(char *, struct pretag_label_filter *, char *);
EXT int evaluate_tags(struct pretag_filter *, pm_id_t);
EXT int evaluate_labels(struct pretag_label_filter *, pt_label_t *);
EXT void load_pkt_len_distrib_bins();
EXT void evaluate_pkt_len_distrib(struct pkt_data *);
EXT char *write_sep(char *, int *);
EXT void version_daemon(char *);
EXT void set_truefalse_nonzero(int *);

EXT char *compose_json_str(void *);
EXT void write_and_free_json(FILE *, void *);
EXT void add_writer_name_and_pid_json(void *, char *, pid_t);

#ifdef WITH_AVRO
EXT void write_avro_schema_to_file(char *, avro_schema_t);
EXT char *compose_avro_purge_schema(avro_schema_t, char *);
#endif

EXT void compose_timestamp(char *, int, struct timeval *, int, int);

EXT void print_primitives(int, char *);
EXT int mkdir_multilevel(const char *, int, uid_t, gid_t);
EXT char bin_to_hex(int);
EXT int print_hex(const u_char *, u_char *, int);

EXT primptrs_func primptrs_funcs[PRIMPTRS_FUNCS_N];
EXT void set_primptrs_funcs(struct extra_primitives *);
EXT void primptrs_set_bgp(u_char *, struct extra_primitives *, struct primitives_ptrs *);
EXT void primptrs_set_lbgp(u_char *, struct extra_primitives *, struct primitives_ptrs *);
EXT void primptrs_set_nat(u_char *, struct extra_primitives *, struct primitives_ptrs *);
EXT void primptrs_set_mpls(u_char *, struct extra_primitives *, struct primitives_ptrs *);
EXT void primptrs_set_tun(u_char *, struct extra_primitives *, struct primitives_ptrs *);
EXT void primptrs_set_custom(u_char *, struct extra_primitives *, struct primitives_ptrs *);
EXT void primptrs_set_extras(u_char *, struct extra_primitives *, struct primitives_ptrs *);
EXT void primptrs_set_vlen_hdr(u_char *, struct extra_primitives *, struct primitives_ptrs *);

EXT int custom_primitives_vlen(struct custom_primitives_ptrs *);
EXT void custom_primitives_reconcile(struct custom_primitives_ptrs *, struct custom_primitives *);
EXT void custom_primitive_header_print(char *, int, struct custom_primitive_ptrs *, int);
EXT void custom_primitive_value_print(char *, int, char *, struct custom_primitive_ptrs *, int);

EXT unsigned char *vlen_prims_copy(struct pkt_vlen_hdr_primitives *);
EXT void vlen_prims_init(struct pkt_vlen_hdr_primitives *, int);
EXT void vlen_prims_free(struct pkt_vlen_hdr_primitives *);
EXT int vlen_prims_cmp(struct pkt_vlen_hdr_primitives *, struct pkt_vlen_hdr_primitives *);
EXT void vlen_prims_get(struct pkt_vlen_hdr_primitives *, pm_cfgreg_t, char **);
EXT void vlen_prims_debug(struct pkt_vlen_hdr_primitives *);
EXT void vlen_prims_insert(struct pkt_vlen_hdr_primitives *, pm_cfgreg_t, int, char *, int);
EXT int vlen_prims_delete(struct pkt_vlen_hdr_primitives *, pm_cfgreg_t);

EXT void hash_init_key(pm_hash_key_t *);
EXT int hash_init_serial(pm_hash_serial_t *, u_int16_t);
EXT int hash_alloc_key(pm_hash_key_t *, u_int16_t);
EXT int hash_dup_key(pm_hash_key_t *, pm_hash_key_t *);
EXT void hash_destroy_key(pm_hash_key_t *);
EXT void hash_destroy_serial(pm_hash_serial_t *);
EXT void hash_serial_set_off(pm_hash_serial_t *, u_int16_t);
EXT void hash_serial_append(pm_hash_serial_t *, char *, u_int16_t, int);
EXT pm_hash_key_t *hash_serial_get_key(pm_hash_serial_t *);
EXT u_int16_t hash_serial_get_off(pm_hash_serial_t *);
EXT u_int16_t hash_key_get_len(pm_hash_key_t *);
EXT char *hash_key_get_val(pm_hash_key_t *);
EXT int hash_key_cmp(pm_hash_key_t *, pm_hash_key_t *);
EXT char *hash_key_get_val(pm_hash_key_t *);

EXT void dump_writers_init();
EXT void dump_writers_count();
EXT u_int32_t dump_writers_get_flags();
EXT u_int16_t dump_writers_get_active();
EXT u_int16_t dump_writers_get_max();
EXT int dump_writers_add(pid_t);

EXT int pm_scandir(const char *, struct dirent ***, int (*select)(const struct dirent *), int (*compar)(const void *, const void *));
EXT void pm_scandir_free(struct dirent ***, int);
EXT int pm_alphasort(const void *, const void *);

EXT void *pm_tsearch(const void *, void **, int (*compar)(const void *, const void *), size_t);
EXT void pm_tdestroy(void **, void (*free_node)(void *));

EXT void replace_string(char *, int, char *, char *);
EXT int delete_line_from_file(int, char *);

EXT void generate_random_string(char *, const int);
#undef EXT

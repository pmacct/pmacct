/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2021 by Paolo Lucente
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

#ifndef UTIL_H
#define UTIL_H

/* defines */
#define ADD 0
#define SUB 1

struct p_broker_timers {
  time_t last_fail;
  int retry_interval;
};

/* prototypes */
extern void setnonblocking(int);
extern void setblocking(int);
extern int daemonize();
extern char *copy_argv(register char **);
extern char *extract_token(char **, int);
extern char *extract_plugin_name(char **);
extern void trim_spaces(char *);
extern void trim_all_spaces(char *);
extern void strip_quotes(char *);
extern void string_add_newline(char *);
extern int isblankline(char *);
extern int iscomment(char *);
extern int check_not_valid_char(char *, char *, int);
extern time_t roundoff_time(time_t, char *);
extern time_t calc_monthly_timeslot(time_t, int, int);
extern void write_pid_file(char *);
extern void write_pid_file_plugin(char *, char *, char *);
extern void remove_pid_file(char *);
extern int sanitize_buf_net(char *, char *, int);
extern int sanitize_buf(char *);
extern void mark_columns(char *);
extern int Setsocksize(int, int, int, void *, socklen_t);
extern void *map_shared(void *, size_t, int, int, int, off_t);
extern void lower_string(char *);
extern void evaluate_sums(u_int64_t *, u_int64_t *, char *, char *);
extern void stop_all_childs();
extern int file_lock(int);
extern int file_unlock(int);
extern void pm_strftime(char *, int, char *, const time_t *, int);
extern void pm_strftime_same(char *, int, char *, const time_t *, int);
extern void insert_rfc3339_timezone(char *, int, const struct tm *);
extern void append_rfc3339_timezone(char *, int, const struct tm *);
extern int read_SQLquery_from_file(char *, char *, int);
extern void stick_bosbit(u_char *);
extern int check_bosbit(u_char *);
extern u_int32_t decode_mpls_label(u_char *);
extern void encode_mpls_label(char *, u_int32_t);
extern int timeval_cmp(struct timeval *, struct timeval *);
extern void signal_kittens(int, int);
extern void exit_all(int);
extern void exit_plugin(int);
extern void exit_gracefully(int);
extern void reset_tag_label_status(struct packet_ptrs_vector *);
extern void reset_net_status(struct packet_ptrs *);
extern void reset_net_status_v(struct packet_ptrs_vector *);
extern void reset_shadow_status(struct packet_ptrs_vector *);
extern void reset_fallback_status(struct packet_ptrs *);
extern void set_sampling_table(struct packet_ptrs_vector *, u_char *);
extern void set_shadow_status(struct packet_ptrs *);
extern void set_default_preferences(struct configuration *);
extern FILE *open_output_file(char *, char *, int);
extern void open_pcap_savefile(struct pm_pcap_device *, char *);
extern void pm_pcap_device_initialize(struct pm_pcap_devices *);
extern void link_latest_output_file(char *, char *);
extern void close_output_file(FILE *);
extern int handle_dynname_internal_strings(char *, int, char *, struct primitives_ptrs *, int);
extern int handle_dynname_internal_strings_same(char *, int, char *, struct primitives_ptrs *, int);
extern int have_dynname_nontime(char *);
extern void escape_ip_uscores(char *);
extern int sql_history_to_secs(int, int);
extern void *pm_malloc(size_t);
extern void load_allow_file(char *, struct hosts_table *);
extern int check_allow(struct hosts_table *, struct sockaddr *);
extern int BTA_find_id(struct id_table *, struct packet_ptrs *, pm_id_t *, pm_id_t *);
extern void calc_refresh_timeout(time_t, time_t, int *);
extern void calc_refresh_timeout_sec(time_t, time_t, int *);
extern int load_tags(char *, struct pretag_filter *, char *);
extern int load_labels(char *, struct pretag_label_filter *, char *);
extern int evaluate_tags(struct pretag_filter *, pm_id_t);
extern int evaluate_labels(struct pretag_label_filter *, pt_label_t *);
extern char *write_sep(char *, int *);
extern void version_daemon(int, char *);
extern void set_truefalse_nonzero(int *);
extern char *ip_proto_print(u_int8_t, char *, int);
extern void parse_hostport(const char *, struct sockaddr *, socklen_t *);
extern bool is_prime(u_int32_t);
extern u_int32_t next_prime(u_int32_t);
extern char *null_terminate(char *, int);
extern char *uint_print(void *, int, int);
extern void reload_logs();
extern int is_empty_256b(void *, int);
extern ssize_t pm_recv(int, void *, size_t, int, unsigned int);
extern int ft2af(u_int8_t);

extern char *compose_json_str(void *);
extern void write_and_free_json(FILE *, void *);
extern void add_writer_name_and_pid_json(void *, char *, pid_t);
extern void write_file_binary(FILE *, void *, size_t);

extern void compose_timestamp(char *, int, struct timeval *, int, int, int, int);

extern void print_primitives(int, char *);
extern int mkdir_multilevel(const char *, int, uid_t, gid_t);
extern char bin_to_hex(int);
extern int hex_to_bin(int);
extern int serialize_hex(const u_char *, u_char *, int);
extern int serialize_bin(const u_char *, u_char *, int);

extern void set_primptrs_funcs(struct extra_primitives *);
extern void primptrs_set_bgp(u_char *, struct extra_primitives *, struct primitives_ptrs *);
extern void primptrs_set_lbgp(u_char *, struct extra_primitives *, struct primitives_ptrs *);
extern void primptrs_set_nat(u_char *, struct extra_primitives *, struct primitives_ptrs *);
extern void primptrs_set_mpls(u_char *, struct extra_primitives *, struct primitives_ptrs *);
extern void primptrs_set_tun(u_char *, struct extra_primitives *, struct primitives_ptrs *);
extern void primptrs_set_custom(u_char *, struct extra_primitives *, struct primitives_ptrs *);
extern void primptrs_set_extras(u_char *, struct extra_primitives *, struct primitives_ptrs *);
extern void primptrs_set_vlen_hdr(u_char *, struct extra_primitives *, struct primitives_ptrs *);

extern int custom_primitives_vlen(struct custom_primitives_ptrs *);
extern void custom_primitives_reconcile(struct custom_primitives_ptrs *, struct custom_primitives *);
extern void custom_primitive_header_print(char *, int, struct custom_primitive_ptrs *, int);
extern void custom_primitive_value_print(char *, int, u_char *, struct custom_primitive_ptrs *, int);
extern void custom_primitives_debug(void *, void *);

extern unsigned char *vlen_prims_copy(struct pkt_vlen_hdr_primitives *);
extern void vlen_prims_init(struct pkt_vlen_hdr_primitives *, int);
extern void vlen_prims_free(struct pkt_vlen_hdr_primitives *);
extern int vlen_prims_cmp(struct pkt_vlen_hdr_primitives *, struct pkt_vlen_hdr_primitives *);
extern void vlen_prims_get(struct pkt_vlen_hdr_primitives *, pm_cfgreg_t, char **);
extern void vlen_prims_debug(struct pkt_vlen_hdr_primitives *);
extern void vlen_prims_insert(struct pkt_vlen_hdr_primitives *, pm_cfgreg_t, int, u_char *, int);
extern int vlen_prims_delete(struct pkt_vlen_hdr_primitives *, pm_cfgreg_t);

extern void hash_init_key(pm_hash_key_t *);
extern int hash_init_serial(pm_hash_serial_t *, u_int16_t);
extern int hash_alloc_key(pm_hash_key_t *, u_int16_t);
extern int hash_dup_key(pm_hash_key_t *, pm_hash_key_t *);
extern void hash_destroy_key(pm_hash_key_t *);
extern void hash_destroy_serial(pm_hash_serial_t *);
extern void hash_serial_set_off(pm_hash_serial_t *, u_int16_t);
extern void hash_serial_append(pm_hash_serial_t *, char *, u_int16_t, int);
extern pm_hash_key_t *hash_serial_get_key(pm_hash_serial_t *);
extern u_int16_t hash_serial_get_off(pm_hash_serial_t *);
extern u_int16_t hash_key_get_len(pm_hash_key_t *);
extern u_char *hash_key_get_val(pm_hash_key_t *);
extern int hash_key_cmp(pm_hash_key_t *, pm_hash_key_t *);

extern void dump_writers_init();
extern void dump_writers_count();
extern u_int32_t dump_writers_get_flags();
extern u_int16_t dump_writers_get_active();
extern u_int16_t dump_writers_get_max();
extern int dump_writers_add(pid_t);

extern int pm_scandir(const char *, struct dirent ***, int (*select)(const struct dirent *), int (*compar)(const void *, const void *));
extern void pm_scandir_free(struct dirent ***, int);
extern int pm_alphasort(const void *, const void *);

extern void *pm_tsearch(const void *, void **, int (*compar)(const void *, const void *), size_t);
extern void pm_tdestroy(void **, void (*free_node)(void *));

extern int delete_line_from_file(int, char *);

extern void generate_random_string(char *, const int);

extern void P_broker_timers_set_last_fail(struct p_broker_timers *, time_t);
extern void P_broker_timers_set_retry_interval(struct p_broker_timers *, int);
extern void P_broker_timers_unset_last_fail(struct p_broker_timers *);
extern time_t P_broker_timers_get_last_fail(struct p_broker_timers *);
extern int P_broker_timers_get_retry_interval(struct p_broker_timers *);
extern time_t P_broker_timers_get_last_fail(struct p_broker_timers *);

extern primptrs_func primptrs_funcs[PRIMPTRS_FUNCS_N];

extern void distribute_work(struct pm_dump_runner *, u_int64_t, int, u_int64_t);
#endif //UTIL_H

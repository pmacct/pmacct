/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2013 by Paolo Lucente
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

#define DEBUG_TIMING 0

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
EXT void evaluate_sums(u_int64_t *, char *, char *);
EXT int file_archive(const char *, int);
EXT void stop_all_childs();
EXT int file_lock(int);
EXT int file_unlock(int);
EXT void strftime_same(char *, int, char *, const time_t *);
EXT int read_SQLquery_from_file(char *, char *, int);
EXT void stick_bosbit(u_char *);
EXT int timeval_cmp(struct timeval *, struct timeval *);
EXT void exit_all(int);
EXT void exit_plugin(int);
EXT void reset_tag_status(struct packet_ptrs_vector *);
EXT void reset_net_status(struct packet_ptrs *);
EXT void reset_net_status_v(struct packet_ptrs_vector *);
EXT void reset_shadow_status(struct packet_ptrs_vector *);
EXT void reset_fallback_status(struct packet_ptrs *);
EXT void set_sampling_table(struct packet_ptrs_vector *, u_char *);
EXT void set_shadow_status(struct packet_ptrs *);
EXT void set_default_preferences(struct configuration *);
EXT FILE *open_logfile(char *);
EXT FILE *open_print_output_file(char *, time_t);
EXT void handle_dynname_internal_strings(char *, int, char *);
EXT void handle_dynname_internal_strings_same(char *, int, char *);
EXT int sql_history_to_secs(int, int);
EXT void close_print_output_file(FILE *, char *, time_t);
EXT void evaluate_bgp_aspath_radius(char *, int, int);
EXT void copy_stdcomm_to_asn(char *, as_t *, int);
EXT void *Malloc(unsigned int);
EXT void load_allow_file(char *, struct hosts_table *);
EXT int check_allow(struct hosts_table *, struct sockaddr *);
EXT void load_bgp_md5_file(char *, struct bgp_md5_table *);
EXT void unload_bgp_md5_file(struct bgp_md5_table *);
EXT int BTA_find_id(struct id_table *, struct packet_ptrs *, pm_id_t *, pm_id_t *);
EXT void calc_refresh_timeout(time_t, time_t, int *);
EXT int load_tags(char *, struct pretag_filter *, char *);
EXT int evaluate_tags(struct pretag_filter *, pm_id_t);
EXT void load_pkt_len_distrib_bins();
EXT void evaluate_pkt_len_distrib(struct pkt_data *);
EXT char *write_sep(char *, int *);

EXT struct packet_ptrs *copy_packet_ptrs(struct packet_ptrs *);
EXT void free_packet_ptrs(struct packet_ptrs *);
#undef EXT

/* Timing Stuff */
#if DEBUG_TIMING
struct mytimer {
  struct timeval t0;
	struct timeval t1;
};

void start_timer(struct mytimer *);
void stop_timer(struct mytimer *, const char *, ...);
#endif

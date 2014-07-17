/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2014 by Paolo Lucente
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

#define __PMACCT_PLAYER_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "sql_common.h"
#include "mysql_plugin.h"
#include "ip_flow.h"
#include "classifier.h"

#define ARGS "df:o:n:thieP:T:U:D:H:"

struct DBdesc db;
struct logfile_header lh;
int re = 0, we = 0;
int debug = 0;
int sql_dont_try_update = 0;
int sql_history_since_epoch = 0;
char timebuf[SRVBUFLEN];
char *sql_table;
struct configuration config;

void usage(char *prog)
{
  printf("%s\n", PMMYPLAY_USAGE_HEADER);
  printf("Usage: %s -f [ filename ]\n\n", prog);
  printf("Available options:\n");
  printf("  -d\tEnable debug\n");
  printf("  -f\t[ filename ]\n\tPlay specified file\n");
  printf("  -o\t[ element ]\n\tPlay file starting at specified offset element\n");
  printf("  -n\t[ num ]\n\tNumbers of elements to play\n");
  printf("  -t\tTest only; don't actually write to the DB\n");
  printf("  -P\t[ password ]\n\tConnect to SQL server using the specified password\n");
  printf("  -U\t[ user ]\n\tUse the specified user when connecting to SQL server\n");
  printf("  -H\t[ host ]\n\tConnect to SQL server listening at specified hostname\n");
  printf("  -D\t[ DB ]\n\tUse the specified SQL database\n");
  printf("  -T\t[ table ]\n\tUse the specified SQL table\n");
  printf("  -i\tDon't try update, use insert only.\n");
  printf("  -e\tUse seconds since the Epoch timestamps.\n");
  printf("\n");
  printf("For suggestions, critics, bugs, contact me: %s.\n", MANTAINER);
}

void print_header()
{
  printf("NUM       ");
  printf("ID     ");
#if defined (HAVE_L2)
  printf("SRC_MAC            ");
  printf("DST_MAC            ");
  printf("VLAN   ");
#endif
  printf("SRC_AS  ");
  printf("DST_AS  ");
#if defined ENABLE_IPV6
  printf("SRC_IP                                         ");
  printf("DST_IP                                         ");
#else
  printf("SRC_IP           ");
  printf("DST_IP           ");
#endif
  printf("SRC_PORT  ");
  printf("DST_PORT  ");
  printf("PROTOCOL    ");
  printf("TOS    ");
#if defined HAVE_64BIT_COUNTERS
  printf("PACKETS               ");
  printf("FLOWS                 ");
  printf("BYTES                 ");
#else
  printf("PACKETS     ");
  printf("FLOWS       ");
  printf("BYTES       ");
#endif
  printf("BASETIME\n");
}

void print_data(struct db_cache *cache_elem, u_int32_t wtc, int num)
{
  struct tm *lt;
  struct pkt_primitives *data = &cache_elem->primitives;
  char src_mac[18], dst_mac[18], src_host[INET6_ADDRSTRLEN], dst_host[INET6_ADDRSTRLEN];

  printf("%-8d  ", num);
  printf("%-5d  ", data->tag);
#if defined (HAVE_L2)
  etheraddr_string(data->eth_shost, src_mac);
  printf("%-17s  ", src_mac);
  etheraddr_string(data->eth_dhost, dst_mac);
  printf("%-17s  ", dst_mac);
  printf("%-5d  ", data->vlan_id);
#endif
  printf("%-5d   ", data->src_as);
  printf("%-5d   ", data->dst_as);
#if defined ENABLE_IPV6
  addr_to_str(src_host, &data->src_ip);
  printf("%-45s  ", src_host);
  addr_to_str(dst_host, &data->dst_ip);
  printf("%-45s  ", dst_host);
#else
  addr_to_str(src_host, &data->src_ip);
  printf("%-15s  ", src_host);
  addr_to_str(dst_host, &data->dst_ip);
  printf("%-15s  ", dst_host);
#endif
  printf("%-5d     ", data->src_port);
  printf("%-5d     ", data->dst_port);
  printf("%-10s  ", _protocols[data->proto].name);
  printf("%-3d    ", data->tos);
#if defined HAVE_64BIT_COUNTERS
  printf("%-20llu  ", cache_elem->packet_counter);
  printf("%-20llu  ", cache_elem->flows_counter);
  printf("%-20llu  ", cache_elem->bytes_counter);
#else
  printf("%-10lu  ", cache_elem->packet_counter);
  printf("%-10lu  ", cache_elem->flows_counter);
  printf("%-10lu  ", cache_elem->bytes_counter);
#endif
  if (lh.sql_history) {
    if (!sql_history_since_epoch) {
      lt = localtime(&cache_elem->basetime); 
      strftime(timebuf, SRVBUFLEN, "%Y-%m-%d %H:%M:%S" , lt); 
      printf("%s\n", timebuf);
    }
    else printf("%u\n", cache_elem->basetime);
  }
  else printf("0\n"); 
}

int main(int argc, char **argv)
{
  struct insert_data idata;
  FILE *f;
  unsigned char fbuf[SRVBUFLEN];
  char logfile[SRVBUFLEN];
  char default_pwd[] = "arealsmartpwd";
  int have_pwd = 0, have_logfile = 0, n;
  int result = 0, position = 0, howmany = 0; 
  int do_nothing = 0, ret; 
  char *cl_sql_host = NULL, *cl_sql_user = NULL, *cl_sql_db = NULL, *cl_sql_table = NULL;

  char sql_pwd[SRVBUFLEN];
  char *sql_host, *sql_user, *sql_db;
  
  struct template_entry *teptr;
  int tot_size = 0, cnt = 0;
  u_char *te;

  struct template_header th;
  struct db_cache data;

  /* getopt() stuff */
  extern char *optarg;
  extern int optind, opterr, optopt;
  int errflag = 0, cp;

  memset(&idata, 0, sizeof(idata));
  memset(sql_data, 0, sizeof(sql_data));
  memset(lock_clause, 0, sizeof(lock_clause));
  memset(unlock_clause, 0, sizeof(unlock_clause));
  memset(update_clause, 0, sizeof(update_clause));
  memset(insert_clause, 0, sizeof(insert_clause));
  memset(where, 0, sizeof(where));
  memset(values, 0, sizeof(values));
  memset(&data, 0, sizeof(data));
  memset(timebuf, 0, sizeof(timebuf));

  db.desc = malloc(sizeof(MYSQL));
  memset(db.desc, 0, sizeof(MYSQL));

  pp_size = sizeof(struct db_cache);

  while (!errflag && ((cp = getopt(argc, argv, ARGS)) != -1)) {
    switch (cp) {
    case 'd':
      debug = TRUE;
      break;
    case 'f':
      strlcpy(logfile, optarg, sizeof(logfile));
      have_logfile = TRUE;
      break;
    case 'o':
      position = atoi(optarg);
      if (!position) {
	printf("ERROR: invalid offset. Exiting.\n");
	exit(1);
      }
      break;
    case 'n':
      howmany = atoi(optarg);
      if (!howmany) {
	printf("ERROR: invalid number of elements. Exiting.\n");
	exit(1);
      }
      break;
    case 't':
      do_nothing = TRUE;
      break;
    case 'i':
      sql_dont_try_update = TRUE;
      break;
    case 'e':
      sql_history_since_epoch = TRUE;
      break;
    case 'P':
      strlcpy(sql_pwd, optarg, sizeof(sql_pwd));
      have_pwd = TRUE;
      break;
    case 'U':
      cl_sql_user = malloc(SRVBUFLEN);
      memset(cl_sql_user, 0, SRVBUFLEN);
      strlcpy(cl_sql_user, optarg, SRVBUFLEN);
      break;
    case 'D':
      cl_sql_db = malloc(SRVBUFLEN);
      memset(cl_sql_db, 0, SRVBUFLEN);
      strlcpy(cl_sql_db, optarg, SRVBUFLEN);
      break;
    case 'H':
      cl_sql_host = malloc(SRVBUFLEN);
      memset(cl_sql_host, 0, SRVBUFLEN);
      strlcpy(cl_sql_host, optarg, SRVBUFLEN);
      break;
    case 'T':
      cl_sql_table = malloc(SRVBUFLEN);
      memset(cl_sql_table, 0, SRVBUFLEN);
      strlcpy(cl_sql_table, optarg, SRVBUFLEN);
      break;
    case 'h':
      usage(argv[0]);
      exit(0);
      break;
    default:
      usage(argv[0]);
      exit(1);
    }
  }

  /* searching for user supplied values */ 
  if (!howmany) howmany = -1; 
  if (!have_pwd) memcpy(sql_pwd, default_pwd, sizeof(default_pwd));
  if (!have_logfile) {
    usage(argv[0]);
    printf("\nERROR: missing logfile (-f)\nExiting...\n");
    exit(1);
  }

  f = fopen(logfile, "r");
  if (!f) {
    printf("ERROR: %s does not exists\nExiting...\n", logfile);
    exit(1);
  }

  if ((ret = fread(&lh, sizeof(lh), 1, f)) != 1) {
    printf("ERROR: Short read from %s\nExiting...\n", logfile);
    exit(1);
  }
  lh.sql_table_version = ntohs(lh.sql_table_version);
  lh.sql_optimize_clauses = ntohs(lh.sql_optimize_clauses);
  lh.sql_history = ntohs(lh.sql_history);
  lh.what_to_count = ntohl(lh.what_to_count);
  lh.magic = ntohl(lh.magic);

  if (lh.magic == MAGIC) {
    if (debug) printf("OK: Valid logfile header read.\n");
    printf("sql_db: %s\n", lh.sql_db); 
    printf("sql_table: %s\n", lh.sql_table);
    printf("sql_user: %s\n", lh.sql_user);
    printf("sql_host: %s\n", lh.sql_host);
    if (cl_sql_db||cl_sql_table||cl_sql_user||cl_sql_host)
      printf("OK: Overrided by commandline options:\n"); 
    if (cl_sql_db) printf("sql_db: %s\n", cl_sql_db);
    if (cl_sql_table) printf("sql_table: %s\n", cl_sql_table);
    if (cl_sql_user) printf("sql_user: %s\n", cl_sql_user);
    if (cl_sql_host) printf("sql_host: %s\n", cl_sql_host);
  }
  else {
    printf("ERROR: Invalid magic number. Exiting.\n");
    exit(1);
  }

  /* binding SQL stuff */
  if (cl_sql_db) sql_db = cl_sql_db;
  else sql_db = lh.sql_db;
  if (cl_sql_table) sql_table = cl_sql_table;
  else sql_table = lh.sql_table;
  if (cl_sql_user) sql_user = cl_sql_user;
  else sql_user = lh.sql_user;
  if (cl_sql_host) sql_host = cl_sql_host;
  else sql_host = lh.sql_host;
  
  if ((ret = fread(&th, sizeof(th), 1, f)) != 1) {
    printf("ERROR: Short read from %s\nExiting...\n", logfile);
    exit(1);
  }
  th.magic = ntohl(th.magic);
  th.num = ntohs(th.num);
  th.sz = ntohs(th.sz);

  if (th.magic == TH_MAGIC) {
    if (debug) printf("OK: Valid template header read.\n");
    if (th.num > N_PRIMITIVES) {
      printf("ERROR: maximum number of primitives exceeded. Exiting.\n");
      exit(1);
    }
    te = malloc(th.num*sizeof(struct template_entry));
    memset(te, 0, th.num*sizeof(struct template_entry));
    if ((ret = fread(te, th.num*sizeof(struct template_entry), 1, f)) != 1) {
      printf("ERROR: Short read from %s\nExiting...\n", logfile);
      exit(1);
    }
  }
  else {
    if (debug) printf("ERROR: no template header found.\n");
    exit(1);
  }

  /* checking template */
  if (th.sz >= sizeof(fbuf)) { 
    printf("ERROR: Objects are too big. Exiting.\n");
    exit(1); 
  }
  teptr = (struct template_entry *) te; 
  for (tot_size = 0, cnt = 0; cnt < th.num; cnt++, teptr++)
    tot_size += teptr->size;
  if (tot_size != th.sz) {
    printf("ERROR: malformed template header. Size mismatch. Exiting.\n");
    exit(1);
  }
  TPL_check_sizes(&th, &data, te); 

  if (!do_nothing) {
    mysql_init(db.desc); 
    if (mysql_real_connect(db.desc, sql_host, sql_user, sql_pwd, sql_db, 0, NULL, 0) == NULL) {
      printf("%s\n", mysql_error(db.desc));
      exit(1);
    }
  }
  else {
    if (debug) print_header();
  }

  /* setting number of entries in _protocols structure */
  while (_protocols[protocols_number].number != -1) protocols_number++;

  /* composing the proper (filled with primitives used during
     the current execution) SQL strings */
  idata.num_primitives = MY_compose_static_queries();
  idata.now = time(NULL);

  /* handling offset */ 
  if (position) n = fseek(f, (th.sz*position), SEEK_CUR);

  /* handling single or iterative request */
  if (!do_nothing) mysql_query(db.desc, lock_clause);
  while(!feof(f)) {
    if (!howmany) break;
    else if (howmany > 0) howmany--;

    memset(fbuf, 0, th.sz);
    n = fread(fbuf, th.sz, 1, f); 
    if (n) {
      re++;
      TPL_pop(fbuf, &data, &th, te);

      if (!do_nothing) result = MY_cache_dbop(&db, &data, &idata);
      else {
	if (debug) print_data(&data, lh.what_to_count, (position+re));
      }

      if (!result) we++;
      if (re != we) printf("WARN: unable to write element %u.\n", re);
    }
  }

  if (!do_nothing) {
    mysql_query(db.desc, unlock_clause);
    printf("\nOK: written [%u/%u] elements.\n", we, re);
  }
  else printf("OK: read [%u] elements.\n", re);
  mysql_close(db.desc);
  fclose(f);

  return 0;
}

int MY_cache_dbop(struct DBdesc *db, struct db_cache *cache_elem, struct insert_data *idata)
{
  char *ptr_values, *ptr_where;
  int num=0, ret=0, have_flows=0;

  if (lh.what_to_count & COUNT_FLOWS) have_flows = TRUE;

  /* constructing sql query */
  ptr_where = where_clause;
  ptr_values = values_clause; 
  while (num < idata->num_primitives) {
    (*where[num].handler)(cache_elem, idata, num, &ptr_values, &ptr_where);
    num++;
  }
  
  if (have_flows) snprintf(sql_data, sizeof(sql_data), update_clause, cache_elem->packet_counter, cache_elem->bytes_counter, cache_elem->flows_counter);
  else snprintf(sql_data, sizeof(sql_data), update_clause, cache_elem->packet_counter, cache_elem->bytes_counter);
  strncat(sql_data, where_clause, SPACELEFT(sql_data));
  if (!sql_dont_try_update) {
    ret = mysql_query(db->desc, sql_data);
    if (ret) return ret; 
  }

  if (sql_dont_try_update || (mysql_affected_rows(db->desc) == 0)) {
    /* UPDATE failed, trying with an INSERT query */ 
    strncpy(sql_data, insert_clause, sizeof(sql_data));
#if defined HAVE_64BIT_COUNTERS
    if (have_flows) snprintf(ptr_values, SPACELEFT(values_clause), ", %llu, %llu, %llu)", cache_elem->packet_counter, cache_elem->bytes_counter, cache_elem->flows_counter);
    else snprintf(ptr_values, SPACELEFT(values_clause), ", %llu, %llu)", cache_elem->packet_counter, cache_elem->bytes_counter);
#else
    if (have_flows) snprintf(ptr_values, SPACELEFT(values_clause), ", %lu, %lu, %lu)", cache_elem->packet_counter, cache_elem->bytes_counter, cache_elem->flows_counter);
    else snprintf(ptr_values, SPACELEFT(values_clause), ", %lu, %lu)", cache_elem->packet_counter, cache_elem->bytes_counter);
#endif
    strncat(sql_data, values_clause, SPACELEFT(sql_data));
    ret = mysql_query(db->desc, sql_data);
    if (ret) return ret;
  }

  if (debug) {
    printf("**********\n");
    printf("%s\n", sql_data);
  }

  return ret;
}

int MY_evaluate_history(int primitive)
{
  if (lh.sql_history) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    if (!sql_history_since_epoch)
      strncat(where[primitive].string, "FROM_UNIXTIME(%u) = ", SPACELEFT(where[primitive].string));
    else
      strncat(where[primitive].string, "%u = ", SPACELEFT(where[primitive].string));
	 
    strncat(where[primitive].string, "stamp_inserted", SPACELEFT(where[primitive].string));

    strncat(insert_clause, "stamp_updated, stamp_inserted", SPACELEFT(insert_clause));
    if (!sql_history_since_epoch)
      strncat(values[primitive].string, "FROM_UNIXTIME(%u), FROM_UNIXTIME(%u)", SPACELEFT(values[primitive].string));
    else
      strncat(values[primitive].string, "%u, %u", SPACELEFT(values[primitive].string));

    where[primitive].type = values[primitive].type = TIMESTAMP;
    values[primitive].handler = where[primitive].handler = count_timestamp_handler;
    primitive++;
  }

  return primitive;
}

int MY_evaluate_primitives(int primitive)
{
  pm_cfgreg_t what_to_count = 0;
  short int assume_custom_table = FALSE;

  if (lh.sql_optimize_clauses) {
    what_to_count = lh.what_to_count;
    assume_custom_table = TRUE;
  }
  else {
    /* we are requested to avoid optimization;
       then we'll construct an all-true "what
       to count" bitmap */ 
    if (lh.what_to_count & COUNT_SRC_AS) what_to_count |= COUNT_SRC_AS;
    else if (lh.what_to_count & COUNT_SUM_HOST) what_to_count |= COUNT_SUM_HOST;
    else if (lh.what_to_count & COUNT_SUM_NET) what_to_count |= COUNT_SUM_NET;
    else if (lh.what_to_count & COUNT_SUM_AS) what_to_count |= COUNT_SUM_AS;
    else what_to_count |= COUNT_SRC_HOST;

    if (lh.what_to_count & COUNT_DST_AS) what_to_count |= COUNT_DST_AS;
    else what_to_count |= COUNT_DST_HOST;
    what_to_count |= COUNT_SRC_MAC;
    what_to_count |= COUNT_DST_MAC;
    what_to_count |= COUNT_SRC_PORT;
    what_to_count |= COUNT_DST_PORT;
    what_to_count |= COUNT_IP_TOS;
    what_to_count |= COUNT_IP_PROTO;
    what_to_count |= COUNT_TAG;
    what_to_count |= COUNT_VLAN;
    if (lh.what_to_count & COUNT_SUM_PORT) what_to_count |= COUNT_SUM_PORT; 
    if (lh.what_to_count & COUNT_SUM_MAC) what_to_count |= COUNT_SUM_MAC; 
  }

  /* 1st part: arranging pointers to an opaque structure and 
     composing the static selection (WHERE) string */

#if defined (HAVE_L2)
  if (what_to_count & (COUNT_SRC_MAC|COUNT_SUM_MAC)) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "mac_src", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "mac_src=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_SRC_MAC;
    values[primitive].handler = where[primitive].handler = count_src_mac_handler;
    primitive++;
  }

  if (what_to_count & COUNT_DST_MAC) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "mac_dst", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "mac_dst=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_DST_MAC;
    values[primitive].handler = where[primitive].handler = count_dst_mac_handler;
    primitive++;
  }

  if (what_to_count & COUNT_VLAN) {
    int count_it = FALSE;

    if ((lh.sql_table_version < 2) && !assume_custom_table) {
      if (lh.what_to_count & COUNT_VLAN) {
        printf("ERROR: The use of VLAN accounting requires SQL table v2. Exiting.\n");
        exit(1);
      }
      else what_to_count ^= COUNT_VLAN;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
        strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
      }
      strncat(insert_clause, "vlan", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "vlan=%u", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_VLAN;
      values[primitive].handler = where[primitive].handler = count_vlan_handler;
      primitive++;
    }
  }
#endif

  if (what_to_count & (COUNT_SRC_HOST|COUNT_SRC_NET|COUNT_SUM_HOST|COUNT_SUM_NET)) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "ip_src", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "ip_src=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_SRC_HOST;
    values[primitive].handler = where[primitive].handler = count_src_host_handler;
    primitive++;
  }

  if (what_to_count & (COUNT_DST_HOST|COUNT_DST_NET)) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "ip_dst", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "ip_dst=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_DST_HOST;
    values[primitive].handler = where[primitive].handler = count_dst_host_handler;
    primitive++;
  }

  if (what_to_count & (COUNT_SRC_AS|COUNT_SUM_AS)) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }

    if (lh.sql_table_version >= 6) {
      strncat(insert_clause, "as_src", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "as_src=%u", SPACELEFT(where[primitive].string));
    }
    else {
      strncat(insert_clause, "ip_src", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "\'%u\'", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "ip_src=\'%u\'", SPACELEFT(where[primitive].string));
    }
    values[primitive].type = where[primitive].type = COUNT_SRC_AS;
    values[primitive].handler = where[primitive].handler = count_src_as_handler;
    primitive++;
  }

  if (what_to_count & COUNT_DST_AS) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }

    if (lh.sql_table_version >= 6) {
      strncat(insert_clause, "as_dst", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "as_dst=%u", SPACELEFT(where[primitive].string));
    }
    else {
      strncat(insert_clause, "ip_dst", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "\'%u\'", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "ip_dst=\'%u\'", SPACELEFT(where[primitive].string));
    }
    values[primitive].type = where[primitive].type = COUNT_DST_AS;
    values[primitive].handler = where[primitive].handler = count_dst_as_handler;
    primitive++;
  }

  if (what_to_count & (COUNT_SRC_PORT|COUNT_SUM_PORT)) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "src_port", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "src_port=%u", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_SRC_PORT;
    values[primitive].handler = where[primitive].handler = count_src_port_handler;
    primitive++;
  }

  if (what_to_count & COUNT_DST_PORT) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "dst_port", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "dst_port=%u", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_DST_PORT;
    values[primitive].handler = where[primitive].handler = count_dst_port_handler;
    primitive++;
  }

  if (what_to_count & COUNT_IP_TOS) {
    int count_it = FALSE;

    if ((lh.sql_table_version < 3) && !assume_custom_table) {
      if (lh.what_to_count & COUNT_IP_TOS) {
        printf("ERROR: The use of ToS/DSCP accounting requires SQL table v3. Exiting.\n");
	exit(1);
      }
      else what_to_count ^= COUNT_IP_TOS;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
	strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
	strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
      }
      strncat(insert_clause, "tos", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "tos=%u", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_IP_TOS;
      values[primitive].handler = where[primitive].handler = count_ip_tos_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_IP_PROTO) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "ip_proto", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "ip_proto=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_IP_PROTO;
    values[primitive].handler = where[primitive].handler = MY_count_ip_proto_handler;
    primitive++;
  }

  if (what_to_count & COUNT_TAG) {
    int count_it = FALSE;
                                                                                            
    if ((lh.sql_table_version < 2) && !assume_custom_table) {
      if (lh.what_to_count & COUNT_TAG) {
        printf("ERROR: The use of IDs requires SQL table version 2. Exiting.\n");
        exit(1);
      }
      else what_to_count ^= COUNT_TAG;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
        strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
      }
      strncat(insert_clause, "agent_id", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "agent_id=%u", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_TAG;
      values[primitive].handler = where[primitive].handler = count_tag_handler;
      primitive++;
    }
  }

  return primitive;
}

int MY_compose_static_queries()
{
  int primitives=0, have_flows=0;

  if (lh.what_to_count & COUNT_FLOWS || (lh.sql_table_version >= 4 && !lh.sql_optimize_clauses)) {
    lh.what_to_count |= COUNT_FLOWS;
    have_flows = TRUE;

    if (lh.sql_table_version < 4 && !lh.sql_optimize_clauses) {
      printf("ERROR: The accounting of flows requires SQL table v4. Exiting.\n");
      exit(1);
    }
  }

  /* "INSERT INTO ... VALUES ... " and "... WHERE ..." stuff */
  strncpy(where[primitives].string, " WHERE ", sizeof(where[primitives].string));
  snprintf(insert_clause, sizeof(insert_clause), "INSERT INTO %s (", sql_table);
  strncpy(values[primitives].string, " VALUES (", sizeof(values[primitives].string));
  primitives = MY_evaluate_history(primitives);
  primitives = MY_evaluate_primitives(primitives);
  strncat(insert_clause, ", packets, bytes", SPACELEFT(insert_clause));
  if (have_flows) strncat(insert_clause, ", flows", SPACELEFT(insert_clause));
  strncat(insert_clause, ")", SPACELEFT(insert_clause));

  /* "LOCK ..." stuff */
  snprintf(lock_clause, sizeof(lock_clause), "LOCK TABLES %s WRITE", sql_table);
  strncpy(unlock_clause, "UNLOCK TABLES", sizeof(unlock_clause));

  /* "UPDATE ... SET ..." stuff */
  snprintf(update_clause, sizeof(update_clause), "UPDATE %s ", sql_table);
#if defined HAVE_64BIT_COUNTERS
  strncat(update_clause, "SET packets=packets+%llu, bytes=bytes+%llu", SPACELEFT(update_clause));
  if (have_flows) strncat(update_clause, ", flows=flows+%llu", SPACELEFT(update_clause));
#else
  strncat(update_clause, "SET packets=packets+%lu, bytes=bytes+%lu", SPACELEFT(update_clause));
  if (have_flows) strncat(update_clause, ", flows=flows+%lu", SPACELEFT(update_clause));
#endif
  if (lh.sql_history) {
    if (!sql_history_since_epoch)
      strncat(update_clause, ", stamp_updated=NOW()", SPACELEFT(update_clause));
    else
      strncat(update_clause, ", stamp_updated=UNIX_TIMESTAMP(NOW())", SPACELEFT(update_clause));
  }

  return primitives;
}

void MY_exit_gracefully(int signum)
{
  printf("\nOK: written [%u/%u] elements.\n", we, re);
  exit(0);
}

/* Dummy version of unsupported functions for the purpose of resolving code dependencies */
int bgp_rd2str(u_char *str, rd_t *rd)
{
  return TRUE;
}

void custom_primitive_value_print(char *out, int outlen, char *in, struct custom_primitive_ptrs *cp_entry, int formatted)
{
}

void vlen_prims_get(struct pkt_vlen_hdr_primitives *pvlen, pm_cfgreg_t wtc, char **label_ptr)
{
}

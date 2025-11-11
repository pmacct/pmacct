/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2025 by Paolo Lucente
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

const struct dynname_token_dict_registry_line dynname_token_dict_registry[] = {
  {DYN_STR_KAFKA_TOPIC, "kafka_topic", NULL},
  {DYN_STR_KAFKA_PART, "kafka_parttion", NULL},
  {DYN_STR_RABBITMQ_RK, "amqp_routing_key", NULL},
  {DYN_STR_SQL_TABLE, "sql_table", NULL},
  {DYN_STR_PRINT_FILE, "print_output_file", NULL},
  {DYN_STR_WRITER_ID, "writer_id", dtdr_writer_id},
  {DYN_STR_UNKNOWN, "unknown", dtdr_unknown}
};

const struct dynname_type_dictionary_line dynname_writer_id_dictionary[] = {
  {"proc_name", dwi_proc_name_handler},
  {"writer_pid", dwi_writer_pid_handler},
  {"pmacct_build", dwi_pmacct_build_handler},
  {"", NULL}
};

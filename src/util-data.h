/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2022 by Paolo Lucente
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
  {DYN_STR_KAFKA_TOPIC, NULL},
  {DYN_STR_KAFKA_PART, NULL},
  {DYN_STR_RABBITMQ_RK, NULL},
  {DYN_STR_MONGODB_TABLE, NULL},
  {DYN_STR_SQL_TABLE, NULL},
  {DYN_STR_PRINT_FILE, NULL},
  {DYN_STR_WRITER_ID, dtdr_writer_id},
  {DYN_STR_UNKNOWN, dtdr_unknown}
};

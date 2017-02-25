Build pmacct with pgsql support:

export PGSQL_CFLAGS="-I/usr/pgsql-9.4/include/"
export PGSQL_LIBS="-L/usr/pgsql-9.4/lib/ -lpq"
./autogen.sh
./configure --enable-pgsql
make

To create the database and grant default permission to the daemon you have to execute
the two scripts below, in the same order; which user has to execute them and how to
autenticate with the PostgreSQL server depends upon your current configuration.
Keep in mind that both scripts need postgres superuser permissions to execute commands 
successfully:

shell> cp -p *.pgsql /tmp
shell> su - postgres

- To create v1 tables:
  * psql -d template1 -f /tmp/pmacct-create-db.pgsql
  * psql -d pmacct -f /tmp/pmacct-create-table_v1.pgsql

- To use v1 tables:
  * data will be available in 'acct' table of 'pmacct' DB.
  * Add 'sql_table_version: 1' line to your configuration.

- To create v2 tables:
  * psql -d template1 -f /tmp/pmacct-create-db.pgsql
  * psql -d pmacct -f /tmp/pmacct-create-table_v2.pgsql

- To use v2 tables:
  * data will be available in 'acct_v2' table of 'pmacct' DB.
  * Add 'sql_table_version: 2' line to your configuration.

[ ... ]

- To create v7 tables:
  * psql -d template1 -f /tmp/pmacct-create-db.pgsql
  * psql -d pmacct -f /tmp/pmacct-create-table_v7.pgsql

- To use v7 tables:
  * data will be available in 'acct_v7' table of 'pmacct' DB.
  * Add 'sql_table_version: 7' line to your configuration.

Similarly, BGP tables:

- To create BGP v1 tables:
  * psql -d template1 -f /tmp/pmacct-create-db.pgsql
  * psql -d pmacct -f /tmp/pmacct-create-table_bgp_v1.pgsql

- To use BGP v1 tables:
  * data will be available in 'acct_bgp' table of 'pmacct' DB.
  * Add 'sql_table_version: 1' line to your configuration.
  * Add 'sql_table_type: bgp' line to your configuration.

Until SQL table schemas v5 a few tables are created in the 'pmacct' database:
'acct' (or 'acct_vN') table is the default table where data will be written
when in 'typed' mode (see 'sql_data' option in CONFIG-KEYS text file; default
value is 'typed'); 'acct_uni' (or 'acct_uni_vN') is the default table where
data will be written when in 'unified' mode. Starting with v6 unified schemas
are no longer supplied as part of the PostgreSQL table creation script: the
'typed' schema instead can still be customized, ie. to write IP addresses in
CHAR fields because making use of IP prefix labels, transparently to pmacct.

- To understand difference between the various table versions: 
  * Do you need any of the BGP primitives ? Then look the next section.
  * Do you need TCP flags ? Then you have to use v7.
  * Do you need both IP addresses and AS numbers in the same table ? Then you have to use v6.
  * Do you need packet classification ? Then you have to use v5.
  * Do you need flows (other than packets) accounting ? Then you have to use v4.
  * Do you need ToS/DSCP field (QoS) accounting ? Then you have to use v3.
  * Do you need agent ID for distributed accounting and packet tagging ? Then you have to use v2. 
  * Do you need VLAN traffic accounting ? Then you have to use v2.
  * If all of the above point sound useless, then use v1.

- To understand difference between the various BGP table versions:
  * Only BGP table v1 is currently available.

- Aggregation primitives to SQL schema mapping:
  Aggregation primitive => SQL table field
  * tag => agent_id (BIGINT NOT NULL DEFAULT 0)
    - or tag => tag (BIGINT NOT NULL DEFAULT 0, if sql_table_version >= 9)
  * tag2 => tag2 (BIGINT NOT NULL DEFAULT 0, see README.tag2)
  * label => label (VARCHAR(255) NOT NULL DEFAULT ' ', see README.label)
  * src_as => as_src (BIGINT NOT NULL DEFAULT 0)
    - or src_as => ip_src (BIGINT NOT NULL DEFAULT 0, if sql_table_version < 6)
  * dst_as => as_dst (BIGINT NOT NULL DEFAULT 0)
    - or dst_as => ip_dst (BIGINT NOT NULL DEFAULT 0, if sql_table_version < 6)
  * peer_src_as => peer_as_src (BIGINT NOT NULL DEFAULT 0)
  * peer_dst_as => peer_as_dst (BIGINT NOT NULL DEFAULT 0)
  * peer_src_ip => peer_ip_src (inet NOT NULL DEFAULT '0.0.0.0', see README.IPv6)
  * peer_dst_ip => peer_ip_dst (inet NOT NULL DEFAULT '0.0.0.0', see README.IPv6)
  * mpls_vpn_rd => mpls_vpn_rd (CHAR(18) NOT NULL DEFAULT ' ')
  * std_comm => comms (CHAR(24) NOT NULL DEFAULT ' ')
  * ext_comm => ecomms (CHAR(24) NOT NULL DEFAULT ' ')
  * lrg_comm => lcomms (CHAR(24) NOT NULL DEFAULT ' ')
  * as_path => as_path (CHAR(21) NOT NULL DEFAULT ' ')
  * local_pref => local_pref (BIGINT NOT NULL DEFAULT 0)
  * med => med (BIGINT NOT NULL DEFAULT 0)
  * src_std_comm => comms_src (CHAR(24) NOT NULL DEFAULT ' ')
  * src_ext_comm => ecomms_src (CHAR(24) NOT NULL DEFAULT ' ')
  * src_lrg_comm => lcomms_src (CHAR(24) NOT NULL DEFAULT ' ')
  * src_as_path => as_path_src (CHAR(21) NOT NULL DEFAULT ' ')
  * src_local_pref => local_pref_src (BIGINT NOT NULL DEFAULT 0)
  * src_med => med_src (BIGINT NOT NULL DEFAULT 0)
  * in_iface => iface_in (BIGINT NOT NULL DEFAULT 0, see README.iface)
  * out_iface => iface_out (BIGINT NOT NULL DEFAULT 0, see README.iface)
  * src_mask => mask_src (SMALLINT NOT NULL DEFAULT 0, see README.mask)
  * dst_mask => mask_dst (SMALLINT NOT NULL DEFAULT 0, see README.mask)
  * cos => cos (SMALLINT NOT NULL DEFAULT 0, see README.cos)
  * etype => etype (CHAR(5) NOT NULL DEFAULT ' ', see README.etype)
  * src_host_country => country_ip_src (CHAR (2) NOT NULL DEFAULT '--', see README.GeoIP)
  * dst_host_country => country_ip_dst (CHAR (2) NOT NULL DEFAULT '--', see README.GeoIP)
  * src_host_pocode => pocode_ip_src (CHAR (12) NOT NULL DEFAULT ' ', see README.GeoIP)
  * dst_host_pocode => pocode_ip_dst (CHAR (12) NOT NULL DEFAULT ' ', see README.GeoIP)
  * sampling_rate => sampling_rate (BIGINT NOT NULL DEFAULT 0, see README.sampling_rate)
  * pkt_len_distrib => pkt_len_distrib (CHAR(10) NOT NULL DEFAULT ' ', see README.pkt_len_distrib)
  * class => class_id (CHAR(16) NOT NOT NULL DEFAULT ' ')
  * src_mac => mac_src (macaddr NOT NULL DEFAULT '0:0:0:0:0:0')
  * dst_mac => mac_dst (macaddr NOT NULL DEFAULT '0:0:0:0:0:0')
  * vlan => vlan (INT NOT NULL DEFAULT 0)
  * src_as => as_src (BIGINT NOT NULL DEFAULT 0)
  * dst_as => as_dst (BIGINT NOT NULL DEFAULT 0)
  * src_host => ip_src (inet NOT NULL DEFAULT '0.0.0.0', see README.IPv6)
  * dst_host => ip_dst (inet NOT NULL DEFAULT '0.0.0.0', see README.IPv6)
  * src_net => ip_src (inet NOT NULL DEFAULT '0.0.0.0', see README.IPv6)
    - or src_net => net_src (same definition, if tmp_net_own_field: true)
  * dst_net => ip_dst (inet NOT NULL DEFAULT '0.0.0.0', see README.IPv6)
    - or dst_net => net_dst (same definition, if tmp_net_own_field: true)
  * src_port => port_src (INT NOT NULL DEFAULT 0)
  * dst_port => port_dst (INT NOT NULL DEFAULT 0)
  * tcpflags => tcp_flags (SMALLINT NOT NULL DEFAULT 0)
  * proto => ip_proto (SMALLINT NOT NULL DEFAULT 0)
  * tos => tos (INT NOT NULL DEFAULT 0)
  * post_nat_src_host => post_nat_ip_src (inet NOT NULL DEFAULT '0.0.0.0', see README.IPv6)
  * post_nat_dst_host => post_nat_ip_dst (inet NOT NULL DEFAULT '0.0.0.0', see README.IPv6)
  * post_nat_src_port => post_nat_port_src (INT NOT NULL DEFAULT 0)
  * post_nat_dst_port => post_nat_port_dst (INT NOT NULL DEFAULT 0)
  * nat_event => nat_event (INT NOT NULL DEFAULT 0)
  * mpls_label_top => mpls_label_top (INT NOT NULL DEFAULT 0)
  * mpls_label_bottom => mpls_label_bottom (INT NOT NULL DEFAULT 0)
  * mpls_stack_depth => mpls_stack_depth (INT NOT NULL DEFAULT 0)
  * timestamp_start => timestamp_start, timestamp_start_residual:
    - timestamp_start timestamp without time zone NOT NULL DEFAULT '0000-01-01 00:00:00', see README.timestamp)
    - timestamp_start_residual INT NOT NULL DEFAULT 0, see README.timestamp)
  * timestamp_end => timestamp_end, timestamp_end_residual:
    - timestamp_end timestamp without time zone NOT NULL DEFAULT '0000-01-01 00:00:00', see README.timestamp)
    - timestamp_end_residual INT NOT NULL DEFAULT 0, see README.timestamp)
  * timestamp_arrival => timestamp_arrival, timestamp_arrival_residual:
    - timestamp_arrival timestamp without time zone NOT NULL DEFAULT '0000-01-01 00:00:00', see README.timestamp)
    - timestamp_arrival_residual INT NOT NULL DEFAULT 0, see README.timestamp)
  * timestamp_min => timestamp_min, timestamp_min_residual:
    - timestamp_min timestamp without time zone NOT NULL DEFAULT '0000-01-01 00:00:00', see README.timestamp)
    - timestamp_min_residual INT NOT NULL DEFAULT 0, see README.timestamp)
  * timestamp_max => timestamp_max, timestamp_max_residual:
    - timestamp_max timestamp without time zone NOT NULL DEFAULT '0000-01-01 00:00:00', see README.timestamp)
    - timestamp_max_residual INT NOT NULL DEFAULT 0, see README.timestamp)

- If not using COPY statements (sql_use_copy, sql_dont_try_update both enabled)
  'packets' and 'bytes' counters need to be defined as part of the SQL schema
  whenever traffic flows are being accounted for; they are not required, and
  are zeroed, if accounting for events, ie. using Cisco NEL; if instead COPY
  is in use, 'packets' and 'bytes' counters are mandatory. 'stamp_inserted' and
  'stamp_updated' time references are mandatory only if temporal aggregation
  (sql_history) is enabled:
  * packets (INT NOT NULL)
  * bytes (BIGINT NOT NULL)
  * stamp_inserted (timestamp without time zone NOT NULL DEFAULT '0000-01-01 00:00:00')
  * stamp_updated (timestamp without time zone)

- For custom-defined primitives refer to the README.custom_primitives doc.

- What is the difference between 'typed' and 'unified' modes ? 
Read this section only if using a table schema v5 or below and does not apply to BGP table
schemas. The 'unified' table has IP addresses and MAC addresses specified as standard CHAR
strings, slower but flexible; 'typed' tables sport PostgreSQL own types (inet, mac, etc.),
faster but rigid. When not specifying your own 'sql_table', this switch instructs the plugin
which tables has to use, default being 'typed'. Since v6 this is all deprecated but default
typed schemas, the only still supplied as part of the PostgreSQL table creation script, can
still be customized transparently to pmacct.

- What is the 'proto' table ?
The auxiliar 'proto' table will be created by default. Its tuples are simply number-string
pairs: the protocol field of both typed and unified tables is numerical. This table helps 
in looking up protocol names by their number and viceversa. Because joins are expensive,
'proto' table has been created *only* for your personal reference. 

NOTE: mind to specify EVERYTIME which SQL table version you
intend to adhere to by using either of the following rules:

When using commandline options:
  * -v [ 1 | 2 | 3 | 4 | 5 | 6 | 7 ]

When using configuration directives:
  * sql_table_version: [ 1 | 2 | 3 | 4 | 5 | 6 | 7 ]
  * sql_table_type: [ bgp ]

NOTE: specifying a non-documented SQL table profile will result
in an non-determined behaviour. Unless this will create crashes
to the application, such situations will not be supported.

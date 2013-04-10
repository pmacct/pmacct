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

Until v5 a few tables are created in the 'pmacct' database. 'acct' (or 'acct_vN')
table is the default table where data will be written when in 'typed' mode (see
'sql_data' option in CONFIG-KEYS text file; default value is 'typed'); 'acct_uni'
(or 'acct_uni_vN') is the default table where data will be written when in 'unified'
mode. Since v6 unified mode is no longer supported.

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
  * tag2 => agent_id2 (BIGINT NOT NULL DEFAULT 0, see README.agent_id2)
  * src_as => as_src (BIGINT NOT NULL DEFAULT 0)
  * dst_as => as_dst (BIGINT NOT NULL DEFAULT 0)
  * peer_src_as => peer_as_src (BIGINT NOT NULL DEFAULT 0)
  * peer_dst_as => peer_as_dst (BIGINT NOT NULL DEFAULT 0)
  * peer_src_ip => peer_ip_src (inet NOT NULL DEFAULT '0.0.0.0', see README.IPv6)
  * peer_dst_ip => peer_ip_dst (inet NOT NULL DEFAULT '0.0.0.0', see README.IPv6)
  * mpls_vpn_rd => mpls_vpn_rd (CHAR(18) NOT NULL DEFAULT ' ')
  * std_comm => comms (CHAR(24) NOT NULL DEFAULT ' ')
  * ext_comm => comms (CHAR(24) NOT NULL DEFAULT ' ')
  * as_path => as_path (CHAR(21) NOT NULL DEFAULT ' ')
  * local_pref => local_pref (BIGINT NOT NULL DEFAULT 0)
  * med => med (BIGINT NOT NULL DEFAULT 0)
  * src_std_comm => comms_src (CHAR(24) NOT NULL DEFAULT ' ')
  * src_ext_comm => comms_src (CHAR(24) NOT NULL DEFAULT ' ')
  * src_as_path => as_path_src (CHAR(21) NOT NULL DEFAULT ' ')
  * src_local_pref => local_pref_src (BIGINT NOT NULL DEFAULT 0)
  * src_med => med_src (BIGINT NOT NULL DEFAULT 0)
  * in_iface => iface_in (BIGINT NOT NULL DEFAULT 0, see README.iface)
  * out_iface => iface_out (BIGINT NOT NULL DEFAULT 0, see README.iface)
  * src_mask => mask_src (SMALLINT NOT NULL DEFAULT 0, see README.mask)
  * dst_mask => mask_dst (SMALLINT NOT NULL DEFAULT 0, see README.mask)
  * cos => cos (SMALLINT NOT NULL DEFAULT 0, see README.cos)
  * etype => etype (CHAR(5) NOT NULL DEFAULT ' ', see README.etype)
  * src_host_country => country_ip_src (CHAR (2) NOT NULL DEFAULT '--', see README.country)
  * dst_host_country => country_ip_dst (CHAR (2) NOT NULL DEFAULT '--', see README.country)
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
  * dst_net => ip_dst (inet NOT NULL DEFAULT '0.0.0.0', see README.IPv6)
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
  * timestamp_start => timestamp_start, timestamp_start_residual:
    - timestamp_start timestamp without time zone NOT NULL DEFAULT '0000-01-01 00:00:00', see README.timestamp)
    - timestamp_start_residual INT NOT NULL DEFAULT 0, see README.timestamp)
  * timestamp_end => timestamp_end, timestamp_end_residual:
    - timestamp_end timestamp without time zone NOT NULL DEFAULT '0000-01-01 00:00:00', see README.timestamp)
    - timestamp_end_residual INT NOT NULL DEFAULT 0, see README.timestamp)

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

- What is the difference between 'typed' and 'unified' modes ? 
It applies to IP tables only (ie. not to BGP ones). The 'unified' table has IP addresses
and MAC addresses specified as standard CHAR strings, slower but flexible (in the sense it
may store each kind of strings); 'typed' tables sport PostgreSQL own types (inet, mac, etc.),
faster but rigid. When not specifying your own 'sql_table', this switch instructs the plugin
which tables has to use. (default: 'typed'). Since v6 unified mode is not supported anymore.

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

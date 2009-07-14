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

- What is the difference between 'typed' and 'unified' modes ? 
The 'unified' table has IP addresses and MAC addresses specified as standard CHAR strings,
slower but flexible (in the sense it may store each kind of strings); 'typed' tables sport
PostgreSQL own types (inet, mac, etc.), faster but rigid. When not specifying your own
'sql_table', this switch instructs the plugin which tables has to use. (default: 'typed').
Since v6 unified mode is not supported anymore.

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

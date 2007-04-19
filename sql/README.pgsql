To create the database and grant default permission to the daemon you have to execute
the two scripts below, in the same order; which user has to execute them and how to
autenticate with the PostgreSQL server depends upon your current configuration.
Keep in mind that both scripts need postgres superuser permissions to execute commands 
successfully:

shell> cp -p *.pgsql /tmp
shell> su - postgres

To create v1 tables:
shell> psql -d template1 -f /tmp/pmacct-create-db.pgsql
shell> psql -d pmacct -f /tmp/pmacct-create-table_v1.pgsql

To create v2 tables:
shell> psql -d template1 -f /tmp/pmacct-create-db.pgsql
shell> psql -d pmacct -f /tmp/pmacct-create-table_v2.pgsql

To create v3 tables:
shell> psql -d template1 -f /tmp/pmacct-create-db.pgsql
shell> psql -d pmacct -f /tmp/pmacct-create-table_v3.pgsql

To create v4 tables:
shell> psql -d template1 -f /tmp/pmacct-create-db.pgsql
shell> psql -d pmacct -f /tmp/pmacct-create-table_v4.pgsql

To create v5 tables:
shell> psql -d template1 -f /tmp/pmacct-create-db.pgsql
shell> psql -d pmacct -f /tmp/pmacct-create-table_v5.pgsql

To create v6 tables:
shell> psql -d template1 -f /tmp/pmacct-create-db.pgsql
shell> psql -d pmacct -f /tmp/pmacct-create-table_v6.pgsql

To create v7 tables:
shell> psql -d template1 -f /tmp/pmacct-create-db.pgsql
shell> psql -d pmacct -f /tmp/pmacct-create-table_v7.pgsql

Until v5 a few tables are created in the 'pmacct' database. 'acct' (or 'acct_vN')
table is the default table where data will be written when in 'typed' mode (see
'sql_data' option in CONFIG-KEYS text file; default value is 'typed'); 'acct_uni'
(or 'acct_uni_vN') is the default table where data will be written when in 'unified'
mode. Since v6 unified mode will be no longer supported: an unique table ('acct_vN')
is used instead. A pair of brief explanations: 

- To understand difference between v1, v2, v3, v4, v5, v6 and v7 tables:
  - Do you need TCP flags ? Then you have to use v7.
  - Do you need both IP addresses and AS numbers in the same table ? Then you have to use v6.
  - Do you need packet classification ? Then you have to use v5.
  - Do you need flows (other than packets) accounting ? Then you have to use v4.
  - Do you need ToS/DSCP field (QoS) accounting ? Then you have to use v3.
  - Do you need agent ID for distributed accounting and packet tagging ? Then you have to use v2. 
  - Do you need VLAN traffic accounting ? Then you have to use v2.
  - If all of the above point sound useless, then use v1.

- What is the difference between 'typed' and 'unified' modes ? 
The 'unified' table has IP addresses and MAC addresses specified as standard CHAR strings,
slower but flexible (in the sense it may store each kind of strings); 'typed' tables sport
PostgreSQL own types (inet, mac, etc.), faster but rigid. When not specifying your own
'sql_table', this switch instructs the plugin which tables has to use. (default: 'typed').
Since v6 unified mode is no more supported. 

- What is the 'proto' table ?
The auxiliar 'proto' table will be created by default. Its tuples are simply number-string
pairs: the protocol field of both typed and unified tables is numerical. This table helps 
in looking up protocol names by their number and viceversa. Because joins are expensive,
'proto' table has been created *only* for your personal reference. 

NOTE: mind to specify EVERYTIME which SQL table version you
intend to adhere to by using either of the following rules:

commandline:    -v [ 1 | 2 | 3 | 4 | 5 | 6 | 7 ]
configuration:  sql_table_version: [ 1 | 2 | 3 | 4 | 5 | 6 | 7 ]

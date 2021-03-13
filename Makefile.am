SUBDIRS = src examples/custom
if USING_BGP_BINS
SUBDIRS += examples/lg
endif
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = include sql examples docs CONFIG-KEYS FAQS QUICKSTART UPGRADE
if USING_SQL
EXTRA_DIST += src/sql_common_m.c
endif

pmacct_data_dir = $(datarootdir)/pmacct
pmacct_libs_dir = $(libdir)/pmacct
pmacct_docs_dir = $(pmacct_data_dir)/docs
pmacct_examples_dir = $(pmacct_data_dir)/examples
pmacct_examples_arch_dir = $(pmacct_libs_dir)/examples
pmacct_examples_kafka_dir = $(pmacct_examples_dir)/kafka
pmacct_examples_amqp_dir = $(pmacct_examples_dir)/amqp
pmacct_examples_avro_dir = $(pmacct_examples_dir)/avro
if USING_BGP_BINS
pmacct_examples_lg_dir = $(pmacct_examples_dir)/lg
pmacct_examples_lg_arch_dir = $(pmacct_examples_arch_dir)/lg
endif
pmacct_examples_custom_dir = $(pmacct_examples_arch_dir)/custom
if USING_SQL
pmacct_sql_dir = $(pmacct_data_dir)/sql
endif

pmacct_data__DATA = CONFIG-KEYS FAQS QUICKSTART UPGRADE
pmacct_docs__DATA = docs/IPFIX docs/LOOKING_GLASS_FORMAT docs/SIGNALS \
	docs/MSGLOG_DUMP_FORMATS docs/TRIGGER_VARS
pmacct_examples__DATA = examples/allow.lst.example examples/bgp_agent.map.example \
	examples/bgp_md5.lst.example examples/bgp_xconnects.map.example \
	examples/flow_to_rd.map.example examples/networks.lst.example \
	examples/peers.map.example examples/pcap_interfaces.map.example \
	examples/pmacctd-imt.conf.example examples/pmacctd-multiple-plugins.conf.example \
	examples/ports.lst.example examples/pretag.map.example \
	examples/primitives.lst.example examples/probe_netflow.conf.example \
	examples/probe_sflow.conf.example examples/sampling.map.example \
	examples/tee_receivers.lst.example examples/nfacctd-sql.conf.example \
	examples/pmacctd-sql.conf.example examples/pmacctd-sqlite3.conf.example 
pmacct_examples_kafka__DATA = examples/kafka/kafka_consumer.py
pmacct_examples_amqp__DATA = examples/amqp/amqp_receiver.py
pmacct_examples_avro__DATA = examples/avro/avro_file_decoder.py
if USING_BGP_BINS
pmacct_examples_lg__DATA = examples/lg/pmbgp.py
pmacct_examples_lg_arch__DATA = examples/lg/pmbgp
endif
pmacct_examples_custom__DATA = examples/custom/libcustom.la
if USING_SQL
pmacct_sql__DATA = sql/pmacct-create-db_bgp_v1.mysql sql/pmacct-create-db.pgsql \
	sql/pmacct-create-db_v1.mysql sql/pmacct-create-db_v2.mysql \
	sql/pmacct-create-db_v3.mysql sql/pmacct-create-db_v4.mysql \
	sql/pmacct-create-db_v5.mysql sql/pmacct-create-db_v6.mysql \
	sql/pmacct-create-db_v7.mysql sql/pmacct-create-db_v8.mysql \
	sql/pmacct-create-db_v9.mysql sql/pmacct-create-table_bgp_v1.pgsql \
	sql/pmacct-create-table_bgp_v1.sqlite3 sql/pmacct-grant-db.mysql \
	sql/pmacct-create-table_v1.pgsql sql/pmacct-create-table_v1.sqlite3 \
	sql/pmacct-create-table_v2.pgsql sql/pmacct-create-table_v2.sqlite3 \
	sql/pmacct-create-table_v3.pgsql sql/pmacct-create-table_v3.sqlite3 \
	sql/pmacct-create-table_v4.pgsql sql/pmacct-create-table_v4.sqlite3 \
	sql/pmacct-create-table_v5.pgsql sql/pmacct-create-table_v5.sqlite3 \
	sql/pmacct-create-table_v6.pgsql sql/pmacct-create-table_v6.sqlite3 \
	sql/pmacct-create-table_v7_v8.pgsql sql/pmacct-create-table_v7.sqlite3 \
	sql/pmacct-create-table_v8.sqlite3 sql/pmacct-create-table_v9.pgsql \
	sql/pmacct-create-table_v9.sqlite3 sql/README.64bit sql/README.cos \
	sql/README.custom_primitives sql/README.etype sql/README.export_proto \
	sql/README.GeoIP sql/README.iface sql/README.IPv6 sql/README.label \
	sql/README.mask sql/README.mpls sql/README.mysql sql/README.nat \
	sql/README.pgsql sql/README.sampling sql/README.sqlite3 \
	sql/README.tag2 sql/README.tunnel sql/README.timestamp
endif

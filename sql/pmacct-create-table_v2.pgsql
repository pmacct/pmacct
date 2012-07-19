--
-- # su - postgres  (or whatever your database runs as ... usually postgres)
-- $ psql -d pmacct -f pmacct-create-table_v2.pgsql 
--

-- Tables 
DROP TABLE acct_uni_v2;
CREATE TABLE acct_uni_v2 (
        agent_id BIGINT NOT NULL DEFAULT 0,
        mac_src CHAR(17) NOT NULL DEFAULT '0:0:0:0:0:0',
        mac_dst CHAR(17) NOT NULL DEFAULT '0:0:0:0:0:0',
        vlan INT NOT NULL DEFAULT 0,
        ip_src CHAR(15) NOT NULL DEFAULT '0.0.0.0',
        ip_dst CHAR(15) NOT NULL DEFAULT '0.0.0.0',
        port_src INT NOT NULL DEFAULT 0,
        port_dst INT NOT NULL DEFAULT 0,
        ip_proto SMALLINT NOT NULL DEFAULT 0,
        packets INT NOT NULL,
        bytes BIGINT NOT NULL,
        stamp_inserted timestamp without time zone NOT NULL DEFAULT '0001-01-01 00:00:00', 
        stamp_updated timestamp without time zone,
        CONSTRAINT acct_uni_v2_pk PRIMARY KEY (agent_id, mac_src, mac_dst, vlan, ip_src, ip_dst, port_src, port_dst, ip_proto, stamp_inserted)
);

DROP TABLE acct_v2;
CREATE TABLE acct_v2 (
	agent_id BIGINT NOT NULL DEFAULT 0,
        mac_src macaddr NOT NULL DEFAULT '0:0:0:0:0:0',
        mac_dst macaddr NOT NULL DEFAULT '0:0:0:0:0:0',
	vlan INT NOT NULL DEFAULT 0,
        ip_src inet NOT NULL DEFAULT '0.0.0.0',
        ip_dst inet NOT NULL DEFAULT '0.0.0.0',
        port_src INT NOT NULL DEFAULT 0,
        port_dst INT NOT NULL DEFAULT 0,
        ip_proto SMALLINT NOT NULL DEFAULT 0,
        packets INT NOT NULL,
        bytes BIGINT NOT NULL,
        stamp_inserted timestamp without time zone NOT NULL DEFAULT '0001-01-01 00:00:00', 
        stamp_updated timestamp without time zone,
        CONSTRAINT acct_v2_pk PRIMARY KEY (agent_id, mac_src, mac_dst, vlan, ip_src, ip_dst, port_src, port_dst, ip_proto, stamp_inserted)
);

DROP TABLE acct_as_v2;
CREATE TABLE acct_as_v2 (
        agent_id BIGINT NOT NULL DEFAULT 0,
        mac_src macaddr NOT NULL DEFAULT '0:0:0:0:0:0',
        mac_dst macaddr NOT NULL DEFAULT '0:0:0:0:0:0',
        vlan INT NOT NULL DEFAULT 0,
        ip_src INT NOT NULL DEFAULT 0,
        ip_dst INT NOT NULL DEFAULT 0,
        port_src INT NOT NULL DEFAULT 0,
        port_dst INT NOT NULL DEFAULT 0,
        ip_proto SMALLINT NOT NULL DEFAULT 0,
        packets INT NOT NULL,
        bytes BIGINT NOT NULL,
        stamp_inserted timestamp without time zone NOT NULL DEFAULT '0001-01-01 00:00:00', 
        stamp_updated timestamp without time zone,
        CONSTRAINT acct_as_v2_pk PRIMARY KEY (agent_id, mac_src, mac_dst, vlan, ip_src, ip_dst, port_src, port_dst, ip_proto, stamp_inserted)
);

DROP TABLE proto;
CREATE TABLE proto (
	num SMALLINT NOT NULL,
	description CHAR(20),
	CONSTRAINT proto_pk PRIMARY KEY (num)
);

COPY proto FROM stdin USING DELIMITERS ',';
0,ip
1,icmp
2,igmp
3,ggp
4,ipencap
5,st
6,tcp
8,egp
9,igp
17,udp
18,mux
27,rdp
29,iso-tp4
30,netblt
37,ddp
39,idpr-cmtp
41,ipv6
43,ipv6-route
44,ipv6-frag
46,rsvp
47,gre
50,ipv6-crypt
51,ipv6-auth
55,mobile
56,tlsp
58,ipv6-icmp
59,ipv6-nonxt
60,ipv6-opts
80,iso-ip
83,vines
88,eigrp
89,ospf
90,sprite-rpc
93,ax-25
94,ipip
98,encap
102,pnni
108,IPcomp
111,ipx-in-ip
112,vrrp
115,l2tp
124,isis
132,sctp
133,fc
\.

-- Perms
GRANT SELECT, INSERT, UPDATE, DELETE ON acct_uni_v2 TO pmacct;
GRANT SELECT, INSERT, UPDATE, DELETE ON acct_v2 TO pmacct;
GRANT SELECT, INSERT, UPDATE, DELETE ON acct_as_v2 TO pmacct;
GRANT SELECT, INSERT, UPDATE, DELETE ON proto TO pmacct;


--
-- # su - postgres  (or whatever your database runs as ... usually postgres)
-- $ psql -d pmacct -f pmacct-create-table_bgp_v1.pgsql 
--

-- Tables 
DROP TABLE acct_bgp;
CREATE TABLE acct_bgp (
	agent_id BIGINT NOT NULL DEFAULT 0,
        as_src BIGINT NOT NULL DEFAULT 0,
        as_dst BIGINT NOT NULL DEFAULT 0,
        peer_as_src BIGINT NOT NULL DEFAULT 0,
        peer_as_dst BIGINT NOT NULL DEFAULT 0,
        peer_ip_src inet NOT NULL DEFAULT '0.0.0.0',
        peer_ip_dst inet NOT NULL DEFAULT '0.0.0.0',
	comms CHAR(24) NOT NULL DEFAULT ' ',
	as_path CHAR(21) NOT NULL DEFAULT ' ',
        local_pref BIGINT NOT NULL DEFAULT 0,
        med BIGINT NOT NULL DEFAULT 0,
        packets INT NOT NULL,
        bytes BIGINT NOT NULL,
        stamp_inserted timestamp without time zone NOT NULL DEFAULT '0001-01-01 00:00:00', 
        stamp_updated timestamp without time zone,
        CONSTRAINT acct_bgp_pk PRIMARY KEY (agent_id, as_src, as_dst, peer_as_src, peer_as_dst, peer_ip_src, peer_ip_dst, comms, as_path, local_pref, med, stamp_inserted) 
);

-- Perms
GRANT SELECT, INSERT, UPDATE, DELETE ON acct_bgp TO pmacct;


--
-- # su - postgres  (or whatever your database runs as ... usually postgres)
-- $ psql -d template1 -f pmacct-create-db.pgsql 
--
-- NOTE: you should have a line like "local  all password" in your pg_hba.conf
--       to authenticate local users against Postgres userbase passwords.
--

DROP DATABASE pmacct;
CREATE DATABASE pmacct;

CREATE USER pmacct;
ALTER USER pmacct WITH PASSWORD 'arealsmartpwd';


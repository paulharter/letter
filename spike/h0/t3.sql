\i prelude.sql
\set VERBOSITY terse
\echo == 11'. spike_reader: SELECT on t, none on "allowed" (referenced only inside the subquery)
SET ROLE spike_reader;
SELECT count(*) AS reader_sees FROM t;
SELECT count(*) FROM allowed;
RESET ROLE;
\echo == 12'. spike_nobody: still refused on t
SET ROLE spike_nobody;
SELECT count(*) FROM t;
RESET ROLE;
\echo == 13'. spike_colreader: SELECT(a) only
SET ROLE spike_colreader;
SELECT a FROM t WHERE a = 2;
SELECT b FROM t WHERE a = 2;
RESET ROLE;
\echo == 6'. nested: subquery in FROM, CTE, sublink, set operation, view over t, SQL function
SELECT count(*) AS in_subquery FROM (SELECT * FROM t) s;
WITH w AS (SELECT * FROM t) SELECT count(*) AS in_cte, count(b) AS b_visible FROM w;
SELECT count(*) AS in_sublink FROM other o WHERE o.t_a IN (SELECT a FROM t);
SELECT count(*) AS in_union FROM (SELECT a FROM t UNION ALL SELECT a FROM t) u;
CREATE TEMP VIEW plain_v AS SELECT a, b FROM t;
SELECT count(*) AS via_plain_view, count(b) AS b_visible FROM plain_v;
CREATE FUNCTION pg_temp.f() RETURNS bigint LANGUAGE sql AS 'SELECT count(*) FROM public.t';
SELECT pg_temp.f() AS via_sql_function;
\echo == 7'. INSERT ... SELECT reading t
BEGIN;
INSERT INTO other SELECT a + 100, a, b FROM t;
SELECT count(*) AS inserted_rows, count(note) AS with_b FROM other WHERE id > 100;
ROLLBACK;

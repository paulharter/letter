-- bench/barrier/run_e.sql — form E against forms B/C at both scales.
SET search_path = lx;
SET max_parallel_workers_per_gather = 0;
\set ea 'EXPLAIN (ANALYZE, COSTS, SUMMARY)'
SET lx.uid = 'alice';
\echo ---- E v_hashed as alice
:ea SELECT count(*), count(body), count(author) FROM v_hashed;
\echo ---- E v_hashed as alice, non-leakproof qual
:ea SELECT * FROM v_hashed WHERE body LIKE 'body 16%';
SET lx.uid = 'bigshot';
\echo ---- E v_hashed as bigshot
:ea SELECT count(*), count(body), count(author) FROM v_hashed;
\echo ---- E v_hashed as bigshot, row filter only (no protected columns read)
:ea SELECT count(*) FROM v_hashed;
\echo ---- B v_initplan as bigshot, row filter only
:ea SELECT count(*) FROM v_initplan;
SET lx.uid = 'nobody';
\echo ---- E v_hashed as nobody
:ea SELECT count(*), count(body) FROM v_hashed;

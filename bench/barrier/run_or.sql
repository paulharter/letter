-- bench/barrier/run_or.sql — see views_or.sql
SET search_path = lx;
SET max_parallel_workers_per_gather = 0;
\set ea 'EXPLAIN (ANALYZE, COSTS, SUMMARY)'
SET lx.uid = 'alice';
\echo ---- v_or_union as alice
:ea SELECT count(*), count(body) FROM v_or_union;
\echo ---- v_2chain_or as alice
:ea SELECT count(*), count(body) FROM v_2chain_or;
\echo ---- v_2chain_union as alice
:ea SELECT count(*), count(body) FROM v_2chain_union;
\echo ---- v_2chain_union as alice, leakproof PK qual
:ea SELECT * FROM v_2chain_union WHERE id = 165;
SET lx.uid = 'root';
\echo ---- v_or_union as root
:ea SELECT count(*), count(body) FROM v_or_union;
SET lx.uid = 'bigshot';
\echo ---- D v_exists_case as bigshot (EXISTS per column at 200k rows)
:ea SELECT count(*), count(body), count(author) FROM v_exists_case;
\echo ---- C v_semi as bigshot (same aggregate, for comparison)
:ea SELECT count(*), count(body), count(author) FROM v_semi;

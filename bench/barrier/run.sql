-- bench/barrier/run.sql — EXPLAIN (ANALYZE) each barrier form. See RESULTS.md.
--   psql -d letter_bench -f bench/barrier/run.sql > bench/barrier/run.out 2>&1
SET search_path = lx;
SET max_parallel_workers_per_gather = 0;      -- keep plans comparable and readable
\set ea 'EXPLAIN (ANALYZE, BUFFERS, COSTS, SUMMARY)'

\echo ==== Q1 full visible set, alice (7 projects -> 698 of 1M rows) ====
SET lx.uid = 'alice';
\echo ---- A v_from
:ea SELECT count(*), count(body), count(author) FROM v_from;
\echo ---- B v_initplan
:ea SELECT count(*), count(body), count(author) FROM v_initplan;
\echo ---- C v_semi
:ea SELECT count(*), count(body), count(author) FROM v_semi;
\echo ---- D v_exists_case (anti-pattern)
:ea SELECT count(*), count(body), count(author) FROM v_exists_case;
\echo ---- wrong-side cast
:ea SELECT count(*), count(body) FROM v_wrongcast;
\echo ---- B1 per-row function
:ea SELECT count(*), count(body), count(author) FROM v_b1;

\echo ==== Q2 leakproof user qual on the PK (can be pushed below the barrier) ====
\echo ---- B v_initplan
:ea SELECT * FROM v_initplan WHERE id = 165;
\echo ---- C v_semi
:ea SELECT * FROM v_semi WHERE id = 165;

\echo ==== Q3 non-leakproof user qual (must stay above the barrier) ====
\echo ---- B v_initplan
:ea SELECT * FROM v_initplan WHERE body LIKE 'body 16%';
\echo ---- C v_semi
:ea SELECT * FROM v_semi WHERE body LIKE 'body 16%';

\echo ==== Q4 protected view joined to another table ====
\echo ---- B v_initplan
:ea SELECT p.name, count(*) FROM v_initplan v JOIN comments c ON c.id = v.id
      JOIN tasks t ON t.id = c.task_id JOIN projects p ON p.id = t.project_id GROUP BY 1;

\echo ==== Q5 large scope set: bigshot (2000 projects -> ~200k rows) ====
SET lx.uid = 'bigshot';
\echo ---- A v_from
:ea SELECT count(*), count(body) FROM v_from;
\echo ---- B v_initplan
:ea SELECT count(*), count(body) FROM v_initplan;
\echo ---- C v_semi
:ea SELECT count(*), count(body) FROM v_semi;

\echo ==== Q6 user with no roles ====
SET lx.uid = 'nobody';
\echo ---- B v_initplan
:ea SELECT count(*) FROM v_initplan;
\echo ---- C v_semi
:ea SELECT count(*) FROM v_semi;

\echo ==== Q7 OR-shaped visibility (unscoped grant resolved at run time) ====
SET lx.uid = 'alice';
\echo ---- v_or as alice (not admin)
:ea SELECT count(*), count(body) FROM v_or;
SET lx.uid = 'root';
\echo ---- v_or as root (admin)
:ea SELECT count(*), count(body) FROM v_or;

\echo ==== Q8 without the referencing-side FK indexes (plan/16 §3.4) ====
SET lx.uid = 'alice';
BEGIN;
DROP INDEX tasks_project_id_idx, comments_task_id_idx;
\echo ---- B v_initplan, no FK indexes
:ea SELECT count(*), count(body), count(author) FROM v_initplan;
\echo ---- C v_semi, no FK indexes
:ea SELECT count(*), count(body), count(author) FROM v_semi;
ROLLBACK;

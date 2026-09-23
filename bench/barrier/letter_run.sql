-- bench/barrier/letter_run.sql — the hook, for real, on the bench data.
-- Compare with run_e.out (hand-written form E view v_hashed).
LOAD 'letter';
SET search_path = lx;
SET max_parallel_workers_per_gather = 0;
SET letter.enforce_reads = on;
SET letter.bypass = off;
\set ea 'EXPLAIN (ANALYZE, COSTS, SUMMARY)'

SET letter.user_id = 'alice';
\echo ==== Q1 hook, comments as alice (7 projects -> 698 of 1M rows)
:ea SELECT count(*), count(body), count(author) FROM comments;
\echo ==== Q2 leakproof user qual on the PK, alice
:ea SELECT * FROM comments WHERE id = 1650;
\echo ==== Q3 non-leakproof user qual, alice
:ea SELECT * FROM comments WHERE body LIKE 'body 16%';
\echo ==== Q4 three protected tables joined, alice
:ea SELECT p.name, count(*) FROM comments c JOIN tasks t ON t.id = c.task_id JOIN projects p ON p.id = t.project_id GROUP BY p.name ORDER BY p.name;

SET letter.user_id = 'bigshot';
\echo ==== Q5 hook, comments as bigshot (2000 projects -> 200k rows)
:ea SELECT count(*), count(body), count(author) FROM comments;
\echo ==== Q5b bigshot, row filter only
:ea SELECT count(*) FROM comments;

SET letter.user_id = 'nobody';
\echo ==== Q6 hook, nobody
:ea SELECT count(*), count(body) FROM comments;

SET letter.user_id = 'root';
\echo ==== Q7 hook, root (unscoped admin: the OR-shaped case)
:ea SELECT count(*), count(body) FROM comments;

SET letter.user_id = 'alice';
\echo ==== W3 UPDATE by PK, alice (row in her scope)
BEGIN;
:ea UPDATE comments SET body = body WHERE id = 1650;
ROLLBACK;
\echo ==== W3b UPDATE by PK, alice (row outside her scope: skipped)
BEGIN;
:ea UPDATE comments SET body = body WHERE id = 165;
ROLLBACK;

-- bench/barrier/letter_run_if.sql — the same Q1/Q5 with an `if` on the editor
-- rule (plan/20 §3): body readable where author <> 'author 0' (all but 200 rows).
LOAD 'letter';
SET search_path = lx;
SET max_parallel_workers_per_gather = 0;
\set ea 'EXPLAIN (ANALYZE, COSTS, SUMMARY)'
SET letter.bypass = on;
SELECT letter.revoke_scoped('select', 'lx.comments', 'editor', ARRAY['body'], 'lx.projects');
SELECT letter.grant_scoped('select', 'lx.comments', 'editor', ARRAY['body'], 'lx.projects', ARRAY['task_id'],
                           if := 'author <> ''author 0''');
SET letter.bypass = off;
SET letter.user_id = 'alice';
\echo ==== Q1-if alice
:ea SELECT count(*), count(body), count(author) FROM comments;
:ea SELECT count(*), count(body), count(author) FROM comments;
SET letter.user_id = 'bigshot';
\echo ==== Q5-if bigshot
:ea SELECT count(*), count(body), count(author) FROM comments;
:ea SELECT count(*), count(body), count(author) FROM comments;
SET letter.bypass = on;
SELECT letter.revoke_scoped('select', 'lx.comments', 'editor', ARRAY['body'], 'lx.projects');
SELECT letter.grant_scoped('select', 'lx.comments', 'editor', ARRAY['body'], 'lx.projects', ARRAY['task_id']);

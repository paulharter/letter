\i prelude.sql
\set VERBOSITY terse
-- 8. system columns: run separately — `SELECT ctid FROM t` crashes the backend (see plan/17 §7)
\echo == 9. row marks
SELECT a FROM t WHERE a = 2 FOR UPDATE;
SELECT a FROM t WHERE a = 2 FOR SHARE;
\echo == 10. TABLESAMPLE
SELECT count(*) FROM t TABLESAMPLE BERNOULLI (100);
\echo == 11. privileges — spike_reader has SELECT on t and other, NOT on allowed
SET ROLE spike_reader;
SELECT count(*) AS reader_sees FROM t;
SELECT count(*) FROM allowed;
RESET ROLE;
\echo == 12. privileges — spike_nobody has nothing: must still be refused on t
SET ROLE spike_nobody;
SELECT count(*) FROM t;
RESET ROLE;
\echo == 13. column privileges — spike_colreader has SELECT(a) only
SET ROLE spike_colreader;
SELECT a FROM t WHERE a = 2;
SELECT b FROM t WHERE a = 2;
SELECT * FROM t WHERE a = 2;
RESET ROLE;
\echo == 14. plan equality with the hand-written security_barrier view
EXPLAIN (COSTS OFF) SELECT a, b FROM t WHERE d LIKE 'd1%';
EXPLAIN (COSTS OFF) SELECT a, b FROM t_view WHERE d LIKE 'd1%';
EXPLAIN (COSTS OFF) SELECT o.note FROM other o JOIN t ON t.a = o.t_a WHERE t.a = 4;
EXPLAIN (COSTS OFF) SELECT o.note FROM other o JOIN t_view t ON t.a = o.t_a WHERE t.a = 4;
\echo == 15. prepared statement, generic plan, then the subquery SQL changes under it
SET plan_cache_mode = force_generic_plan;
PREPARE p(int) AS SELECT a, b FROM t WHERE a = $1;
EXECUTE p(2);
EXECUTE p(12);
SET letter_spike.sql = 'SELECT x.a, x.b, NULL::int, x.d FROM public.t x';
EXECUTE p(12);

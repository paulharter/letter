\i prelude.sql
\echo == 1. plain columns, no Var fix-up (expect a<=10, b NULL on odd a)
SELECT a, b, d FROM t WHERE a IN (1,2,3,11,12) ORDER BY a;
\echo == 2. SELECT * (parser expanded to attnos 1,2,4 before the hook ran)
SELECT * FROM t WHERE a <= 3 ORDER BY a;
\echo == 3. alias + join + qual on a redacted column
SELECT o.note, tt.a, tt.b FROM other o JOIN t tt ON tt.a = o.t_a WHERE tt.b IS NOT NULL ORDER BY 2;
\echo == 4. aggregate over redacted column / predicate leak check (b = 'b1' must find nothing: a=1 is odd)
SELECT count(*), count(b), max(b) FROM t;
SELECT count(*) FROM t WHERE b = 'b1';
\echo == 5. whole-row Var with a dropped column present
SELECT t FROM t WHERE a <= 2 ORDER BY a;
SELECT row_to_json(t) FROM t WHERE a <= 2 ORDER BY a;
SELECT (t).d, (t).b FROM t WHERE a = 2;
\echo == 6. t.* inside a subquery and a CTE (top-level-only spike: NOT expected to be rewritten)
SELECT count(*) AS in_subquery FROM (SELECT * FROM t) s;
\echo == 7. result relation is skipped; other RTEs of a write are substituted
BEGIN;
UPDATE other o SET note = 'seen' FROM t WHERE t.a = o.t_a;
SELECT count(*) AS updated_rows FROM other WHERE note = 'seen';
INSERT INTO other SELECT a + 100, a, b FROM t;
SELECT count(*) AS inserted_rows, count(note) AS with_b FROM other WHERE id > 100;
UPDATE t SET d = 'w' WHERE a = 15 RETURNING a, b, d;
ROLLBACK;

-- Test: planner hook — infrastructure, substitution and the universal gate
-- (plan/17-planner-hook-implementation.md H1, H3, D14)
--
-- Semantics under test:
--   1. letter.enforce_reads exists, defaults to on, and is superuser-only.
--   2. D14: with the hook on, a table with no grants cannot be read (an
--      error, not zero rows); catalogues, information_schema, the session's
--      own temporary tables and letter's own tables are exempt.
--   3. Every reference to a protected table is substituted, at every
--      nesting level (reported at DEBUG1); a table with grants but no
--      select grant is closed to reads.
--   4. Switch off / letter.bypass on = untouched, and flipping either one
--      replans cached statements (ResetPlanCache assign hooks).
--   5. Tables are identified by OID (plan/18 D1); the set follows grants:
--      revoke, and a grant rolled back by a transaction or savepoint, all
--      take effect.
--   6. letter's own SPI runs under the internal guard, invisible to the
--      hook — and letter.read() resets the plan cache as it leaves the
--      guard, so a function first run inside read()'s condition is
--      replanned afterwards (D9).
--   7. The substituted subquery redacts: rows and columns follow the
--      user's roles, and a predicate on a hidden column cannot tell "no
--      match" from "can't see".
--   8. Shapes that cannot be redacted faithfully fail closed (§4).
--   9. D14 on writes: the result relation needs a grant of the statement's
--      privilege, checked at plan time; other tables in a write statement
--      are substituted like any read.
--  10. COPY table TO is refused, COPY (SELECT …) TO enforced, COPY FROM
--      gated, TRUNCATE needs bypass — the ProcessUtility hook (H6).

CREATE EXTENSION letter;
SET letter.bypass = on;   -- fixture: the hook is on by default

CREATE TABLE projects (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    secret TEXT
);

CREATE TABLE notes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid NOT NULL REFERENCES projects(id),
    body TEXT
);
CREATE INDEX notes_project_id_idx ON notes (project_id);

CREATE TABLE widgets (
    id int PRIMARY KEY,
    label TEXT
);

INSERT INTO projects (id, name, secret) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'Alpha', 's1'),
    ('a0000000-0000-0000-0000-000000000002', 'Beta',  's2');
INSERT INTO notes (id, project_id, body) VALUES
    ('b0000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001', 'n1'),
    ('b0000000-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000002', 'n2');
INSERT INTO widgets VALUES (1, 'w1');

INSERT INTO letter.roles (role, user_id, scope_table, scope_id) VALUES
    ('editor', 'alice', 'public.projects', 'a0000000-0000-0000-0000-000000000001'),
    ('editor', 'bob',   'public.projects', 'a0000000-0000-0000-0000-000000000002');

CREATE FUNCTION count_notes() RETURNS bigint LANGUAGE plpgsql AS $$
BEGIN
    RETURN (SELECT count(*) FROM notes);
END $$;

SET letter.bypass = off;
\set VERBOSITY terse

-- ============================================================
-- Test 1: the switch defaults to on and is superuser-only.
-- ============================================================
SHOW letter.enforce_reads;

CREATE ROLE letter_test_nosuper NOSUPERUSER;
SET ROLE letter_test_nosuper;
SET letter.enforce_reads = off;
RESET ROLE;
DROP ROLE letter_test_nosuper;

-- ============================================================
-- Test 2: D14 — no grants at all: user tables are closed, the
-- exempt namespaces are not.
-- ============================================================
SET letter.enforce_reads = on;
SET letter.current_user_id = 'alice';

SELECT count(*) FROM notes;
SELECT count(*) FROM widgets;
SELECT count(*) FROM pg_class WHERE relname = 'notes';
SELECT count(*) FROM information_schema.tables WHERE table_name = 'notes';
CREATE TEMP TABLE scratch (x int);
INSERT INTO scratch VALUES (1);
SELECT count(*) FROM scratch;
SELECT count(*) FROM letter.grants;
SELECT count(*) FROM letter.read('public.widgets');

-- ============================================================
-- Test 3: references to protected tables are substituted wherever
-- they sit in the tree. projects gets only an update grant: closed
-- to reads, open to the gate for updates (Test 9).
-- ============================================================
SELECT letter.grant('select', 'public.notes', 'editor', ARRAY['body'],
    'public.projects', NULL, NULL);
SELECT letter.grant('update', 'public.projects', 'editor', ARRAY['name'],
    'public.projects', NULL, NULL);

SET client_min_messages = debug1;
-- top level
SELECT count(*) FROM notes;
-- joined, twice
SELECT count(*) FROM notes a JOIN notes b USING (id);
-- subquery in FROM
SELECT count(*) FROM (SELECT body FROM notes OFFSET 0) s;
-- CTE
WITH c AS MATERIALIZED (SELECT body FROM notes) SELECT count(*) FROM c;
-- sublink
SELECT count(*) FROM notes WHERE EXISTS (SELECT 1 FROM notes);
-- set-operation arm
SELECT body FROM notes UNION ALL SELECT body FROM notes ORDER BY 1;
-- a function body
SELECT count_notes();
RESET client_min_messages;
-- no grants / no select grant
SELECT count(*) FROM widgets;
SELECT count(*) FROM projects;

-- ============================================================
-- Test 4: the switches. A parameterless prepared statement is
-- planned once; flipping letter.bypass or letter.enforce_reads
-- must force a replan under the new value.
-- ============================================================
PREPARE count_p AS SELECT count(*) FROM notes;

SET client_min_messages = debug1;
-- planned: substituted
EXECUTE count_p;
-- cached plan: silent
EXECUTE count_p;

SET letter.bypass = on;
-- replanned under bypass: silent, and every row
EXECUTE count_p;
SET letter.bypass = off;
-- replanned again: substituted
EXECUTE count_p;

SET letter.enforce_reads = off;
-- replanned with the hook off: silent
EXECUTE count_p;
SET letter.enforce_reads = on;
-- substituted
EXECUTE count_p;
RESET client_min_messages;

DEALLOCATE count_p;

-- ============================================================
-- Test 5: the protected set is keyed by OID and follows grants.
-- ============================================================

-- 5a: drop and recreate. The grant rows go with the table (plan/18);
-- the recreated table is a new table with no grants — closed —
-- until it is granted on again, as a migration would.
SET letter.bypass = on;
DROP TABLE notes;
CREATE TABLE notes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid NOT NULL REFERENCES projects(id),
    body TEXT
);
CREATE INDEX notes_project_id_idx ON notes (project_id);
INSERT INTO notes (id, project_id, body) VALUES
    ('b0000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001', 'n1'),
    ('b0000000-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000002', 'n2');
SET letter.bypass = off;

SELECT count(*) FROM notes;
SELECT letter.grant('select', 'public.notes', 'editor', ARRAY['body'],
    'public.projects', NULL, NULL);
SELECT count(*) FROM notes;

-- 5b: a grant rolled back with its transaction protects nothing:
-- readable inside the transaction, closed again after ROLLBACK.
BEGIN;
SELECT letter.grant('select', 'public.widgets', 'editor', ARRAY['*'], NULL, NULL, NULL);
SELECT count(*) FROM widgets;
ROLLBACK;
SELECT count(*) FROM widgets;

-- 5c: likewise for a savepoint.
BEGIN;
SAVEPOINT s;
SELECT letter.grant('select', 'public.widgets', 'editor', ARRAY['*'], NULL, NULL, NULL);
SELECT count(*) FROM widgets;
ROLLBACK TO s;
SELECT count(*) FROM widgets;
ROLLBACK;

-- 5d: revoking the last select grant closes the table.
SELECT letter.grant('select', 'public.widgets', 'editor', ARRAY['*'], NULL, NULL, NULL);
SELECT count(*) FROM widgets;
SELECT letter.revoke('select', 'public.widgets', 'editor', ARRAY['*'], NULL);
SELECT count(*) FROM widgets;

-- ============================================================
-- Test 6: the internal guard, and letter.read()'s plan-cache
-- reset. count_notes() is first planned inside read()'s guarded
-- scan — unrewritten, and invisible to the hook — so its plan must
-- be discarded when read() leaves the guard (D9).
-- ============================================================
DISCARD PLANS;
SET client_min_messages = debug1;
-- silent: read()'s scan and everything under it is letter's own
SELECT count(*) FROM letter.read('public.notes', 'count_notes() > 0');
-- substituted: the plan cached inside the guard was discarded
SELECT count_notes();
RESET client_min_messages;

-- An error inside a guarded region must not leave the guard set.
SELECT count(*) FROM letter.read('public.notes', '1/0 > 0');
SET client_min_messages = debug1;
SELECT count(*) FROM notes;
RESET client_min_messages;

-- ============================================================
-- Test 7: the substituted subquery redacts.
-- ============================================================
SET letter.current_user_id = 'alice';
SELECT body FROM notes ORDER BY body;
SELECT n.body, n.project_id IS NULL AS project_id_hidden FROM notes n ORDER BY 1;
-- the leak is closed: a predicate on a hidden column finds nothing
SELECT count(*) FROM notes WHERE project_id = 'a0000000-0000-0000-0000-000000000001';
SET letter.current_user_id = 'bob';
SELECT body FROM notes ORDER BY body;
SET letter.current_user_id = 'nobody';
SELECT body FROM notes ORDER BY body;
RESET letter.current_user_id;
-- unset user id: zero rows, no error (D2)
SELECT count(*) FROM notes;
SET letter.current_user_id = 'alice';

-- ============================================================
-- Test 8: shapes that cannot be redacted faithfully fail closed.
-- ============================================================
SELECT ctid FROM notes;
SELECT xmin FROM notes;
SELECT tableoid FROM notes;
SELECT count(*) FROM notes WHERE ctid IS NOT NULL;
SELECT count(*) FROM (SELECT 1 FROM notes n WHERE n.ctid IS NOT NULL) s;
SELECT body FROM notes TABLESAMPLE SYSTEM (100);
SELECT body FROM notes FOR UPDATE;
SELECT body FROM notes FOR SHARE;
-- whole-row references are fine
SELECT (n).body FROM notes n ORDER BY 1;

-- ============================================================
-- Test 9: D14 on writes — the gate at plan time, the triggers after.
-- ============================================================
-- no grants at all
INSERT INTO widgets VALUES (2, 'w2');
-- grants, but not this privilege
DELETE FROM projects WHERE name = 'Beta';
UPDATE notes SET body = 'x';
-- the privilege is granted: the gate passes. projects has no select grant,
-- so no row is visible to a write either (plan/19 D1): both touch nothing
UPDATE projects SET name = 'Alpha!' WHERE id = 'a0000000-0000-0000-0000-000000000001';
UPDATE projects SET name = 'Beta!'  WHERE id = 'a0000000-0000-0000-0000-000000000002';
-- other tables in a write statement are substituted like any read
INSERT INTO widgets SELECT 3, body FROM notes;
UPDATE projects SET name = name WHERE id IN (SELECT project_id FROM notes);
-- the result relation is redacted too (plan/19): with no select grant,
-- RETURNING has no row to show
UPDATE projects SET name = name WHERE id = 'a0000000-0000-0000-0000-000000000001' RETURNING secret;

-- ============================================================
-- Test 10: the ways round the planner (H6). COPY table TO would
-- emit true values: refused (COPY (SELECT …) TO is enforced). COPY
-- FROM needs an insert grant; TRUNCATE needs bypass.
-- ============================================================
COPY notes TO STDOUT;
COPY widgets TO STDOUT;
COPY (SELECT body FROM notes) TO STDOUT;
COPY widgets FROM '/dev/null';
TRUNCATE widgets;
TRUNCATE notes;
COPY scratch TO STDOUT;
SET letter.bypass = on;
COPY notes (body) TO STDOUT;
SET letter.bypass = off;

\set VERBOSITY default

-- Cleanup
RESET letter.current_user_id;
RESET letter.enforce_reads;
DROP FUNCTION count_notes();
DROP TABLE scratch;
DROP TABLE widgets CASCADE;
DROP TABLE notes CASCADE;
DROP TABLE projects CASCADE;
DROP EXTENSION letter CASCADE;

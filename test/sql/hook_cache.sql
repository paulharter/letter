-- Test: plan and cache invalidation across backends
-- (plan/17-planner-hook-implementation.md H4)
--
-- A rewritten plan lists letter.grants in its relationOids; the grants
-- trigger raises a relcache invalidation on letter.grants, which reaches
-- every backend at commit and makes the plancache drop those plans. The
-- roles trigger invalidates the empty signal table letter._membership_signal
-- instead, so role churn refreshes every backend's session cache without
-- touching the plans, which do not depend on role rows.
--
-- The "other backend" is a dblink connection to this database.

CREATE EXTENSION letter;
CREATE EXTENSION dblink;
SET letter.bypass = on;   -- fixture: the hook is on by default

CREATE TABLE projects (id uuid PRIMARY KEY, name TEXT);
CREATE TABLE notes (
    id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(id),
    body TEXT,
    extra TEXT
);
CREATE INDEX ON notes (project_id);
INSERT INTO projects VALUES ('a0000000-0000-0000-0000-000000000001', 'Alpha');
INSERT INTO notes VALUES
    ('b0000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001', 'n1', 'x1');
INSERT INTO letter.memberships (role, user_id, scope_table, scope_id) VALUES
    ('editor', 'alice', 'public.projects', 'a0000000-0000-0000-0000-000000000001');
SELECT letter.grant_scoped('select', 'public.notes', 'editor', ARRAY['body'], 'public.projects');

CREATE FUNCTION other(sql text) RETURNS text LANGUAGE sql AS $$
    SELECT x FROM dblink('dbname=' || current_database() || ' port=' || current_setting('port'), sql) AS t(x text);
$$;

SET letter.bypass = off;
SET letter.enforce_reads = on;
SET letter.user_id = 'alice';
\set VERBOSITY terse

-- ============================================================
-- 1. Same backend: a grant change replans a prepared statement.
-- ============================================================
PREPARE p AS SELECT body, extra FROM notes;
SET client_min_messages = debug1;
EXECUTE p;
EXECUTE p;
RESET client_min_messages;

SELECT letter.grant_scoped('select', 'public.notes', 'editor', ARRAY['extra'], 'public.projects');
SET client_min_messages = debug1;
-- replanned: extra is now visible
EXECUTE p;
RESET client_min_messages;

-- ============================================================
-- 2. Another backend changes the grants: this backend's cached
--    plan is dropped at its next use, and the protected set too.
-- ============================================================
SELECT other($$SELECT letter.revoke_scoped('select', 'public.notes', 'editor', ARRAY['extra'], 'public.projects')$$);
SET client_min_messages = debug1;
-- replanned: extra hidden again
EXECUTE p;
RESET client_min_messages;

SELECT other($$SELECT letter.revoke_scoped('select', 'public.notes', 'editor', ARRAY['*'], 'public.projects')$$);
-- replanned: the table has no grants now (D14)
EXECUTE p;

SELECT other($$SELECT letter.grant_scoped('select', 'public.notes', 'editor', ARRAY['body'], 'public.projects')$$);
EXECUTE p;

-- ============================================================
-- 3. Another backend changes the memberships: this backend's session
--    cache follows (write path), and the plan is NOT dropped — the
--    memberships are read at execution time.
-- ============================================================
SELECT letter.grant_scoped('update', 'public.notes', 'editor', ARRAY['body'], 'public.projects');
SELECT letter.grant_scoped('insert', 'public.notes', 'editor', NULL, 'public.projects');
SELECT letter.grant_scoped('select', 'public.notes', 'viewer', ARRAY['body'], 'public.projects');
-- (those grants invalidated p; plan it again, as bob)
SET letter.user_id = 'bob';
EXECUTE p;
-- bob has no membership yet: the row is not there for him (plan/19 D1) —
-- nothing happens, no error
UPDATE notes SET body = 'by bob' WHERE id = 'b0000000-0000-0000-0000-000000000001';
-- an insert reaches the trigger and is refused — and, having been checked,
-- bob's (empty) membership set is now in this backend's session cache. The
-- remote changes below must reach a WARM cache, not an empty one (plan/24 A2).
INSERT INTO notes (id, project_id, body) VALUES
    ('b0000000-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000001', 'bob''s');

SELECT other($$INSERT INTO letter.memberships (role, user_id, scope_table, scope_id)
    VALUES ('editor', 'bob', 'public.projects', 'a0000000-0000-0000-0000-000000000001'),
           ('viewer', 'bob', 'public.projects', 'a0000000-0000-0000-0000-000000000001')
    RETURNING role$$);

SET client_min_messages = debug1;
-- the read plan is reused (no "substituting"), and bob now sees the row
EXECUTE p;
RESET client_min_messages;
-- and the write path sees bob's new membership without any local memberships write
UPDATE notes SET body = 'by bob' WHERE id = 'b0000000-0000-0000-0000-000000000001';
SELECT body FROM notes;
-- the other way too: the editor membership revoked elsewhere is gone here at
-- once — bob still sees the row as a viewer, and may no longer change it
SELECT other($$DELETE FROM letter.memberships WHERE user_id = 'bob' AND role = 'editor' RETURNING 'deleted'$$);
UPDATE notes SET body = 'by bob again' WHERE id = 'b0000000-0000-0000-0000-000000000001';
SELECT body FROM notes;

-- ============================================================
-- 4. The signal table is just that.
-- ============================================================
SELECT count(*) FROM letter._membership_signal;

\set VERBOSITY default
DEALLOCATE p;
RESET letter.user_id;
RESET letter.enforce_reads;
DROP FUNCTION other(text);
DROP TABLE notes, projects CASCADE;
DROP EXTENSION dblink;
DROP EXTENSION letter CASCADE;

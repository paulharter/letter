-- Test: letter.check_health() (plan/18 I4)
--
-- Reports, as (severity, object, message) rows, the states the lifecycle
-- contract cannot prevent: deployment settings, letter state edited by hand,
-- disabled triggers, missing indexes. In this test the library is not
-- preloaded and read enforcement is off, so those two rows are always
-- present.

CREATE EXTENSION letter;
SET letter.enforce_reads = off;   -- this test is not about the read hook

CREATE TABLE users (id uuid PRIMARY KEY);
CREATE TABLE projects (id uuid PRIMARY KEY, name TEXT);
CREATE TABLE tasks (
    id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(id),   -- no index: reported
    title TEXT
);
CREATE TABLE team_members (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id),
    project_id uuid NOT NULL REFERENCES projects(id),
    role TEXT NOT NULL
);
CREATE TABLE stale (id int PRIMARY KEY, x TEXT);
CREATE TABLE unguarded (id int PRIMARY KEY, x TEXT);

SET letter.bypass = on;
SELECT letter.assign('public.team_members', 'user_id', 'public.projects',
    role_name := NULL, role_column := 'role', if_fn := NULL);
RESET letter.bypass;

SELECT letter.grant('select', 'public.tasks', 'editor', ARRAY['title'],
    'public.projects', NULL, NULL);
SELECT letter.grant('update', 'public.tasks', 'editor', ARRAY['title'],
    'public.projects', NULL, NULL);

-- assignment ids are random: normalise them away
CREATE VIEW health AS
    SELECT severity, object,
           regexp_replace(message, '[0-9a-f]{8}(_[0-9a-f]{4}){3}_[0-9a-f]{12}', '<id>') AS message
    FROM letter.check_health();

-- ============================================================
-- 1. A healthy installation: only the two environmental rows and
--    the missing index.
-- ============================================================
SELECT * FROM health ORDER BY 1, 2, 3;

-- ============================================================
-- 2. Things the lifecycle contract cannot catch.
-- ============================================================
-- a disabled enforcement trigger
ALTER TABLE tasks DISABLE TRIGGER letter_enforce_update;
-- grants edited by hand: a dead table OID, and a table with no triggers
INSERT INTO letter.grants (privilege, on_table, role, column_name, scope)
    VALUES ('select', 99999999, 'ghost', '*', 0);
INSERT INTO letter.grants (privilege, on_table, role, column_name, scope)
    VALUES ('select', 'public.unguarded'::regclass, 'r', '*', 0);
-- enforcement triggers left behind by a hand-deleted grant
SELECT letter.grant('select', 'public.stale', 'r', ARRAY['x'], NULL);
DELETE FROM letter.grants WHERE on_table = 'public.stale'::regclass;
-- a role row managed directly, and one scoped to a dead table
INSERT INTO letter.roles (role, user_id) VALUES ('auditor', 'u1');
INSERT INTO letter.roles (role, user_id, scope_table, scope_id) VALUES ('editor', 'u2', 99999999, '1');
-- an assignment whose trigger function was dropped by hand
SELECT 'letter.source_delete_' || replace(id::text, '-', '_') || '()' AS fn
    FROM letter.assignments \gset
SET client_min_messages = warning;
DROP FUNCTION :fn CASCADE;
RESET client_min_messages;
-- a role with a bypass default
CREATE ROLE letter_test_admin;
ALTER ROLE letter_test_admin SET letter.bypass = on;

SELECT * FROM health ORDER BY 1, 2, 3;

-- Cleanup
SET client_min_messages = warning;
DROP VIEW health;
DROP ROLE letter_test_admin;
DROP TABLE team_members, tasks, projects, users, stale, unguarded CASCADE;
DROP EXTENSION letter CASCADE;

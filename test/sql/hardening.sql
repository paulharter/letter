-- Test: enforcement hardening (plan/14-enforcement-gaps.md §2, §4.2)
--
-- Semantics under test:
--   1. letter.bypass is PGC_SUSET — a non-superuser cannot switch
--      enforcement off.
--   2. UPDATE scope migration: changing a scope-contributing column
--      requires rights in BOTH the old and the new scope. Rights in
--      the destination scope alone are not enough to pull a row in.
--   3. Role changes invalidate the session cache immediately — a role
--      gained or lost mid-session takes effect on the next check.
--   4. Role names are handled as data, never interpolated into SQL —
--      a role name containing quotes/SQL must not break enforcement.
--   5. letter._read() quotes identifiers — a table name cannot smuggle SQL.

CREATE EXTENSION letter;
SET letter.enforce_reads = off;   -- this test is not about the read hook

CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL
);

CREATE TABLE projects (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL
);

CREATE TABLE tasks (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid NOT NULL REFERENCES projects(id),
    title TEXT NOT NULL
);

CREATE TABLE comments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id uuid REFERENCES tasks(id),
    body TEXT NOT NULL
);

CREATE TABLE team_members (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    role TEXT NOT NULL
);

INSERT INTO users (id, name) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'Alice'),
    ('a0000000-0000-0000-0000-000000000003', 'Mallory');

INSERT INTO projects (id, name) VALUES
    ('b0000000-0000-0000-0000-000000000001', 'Alpha'),
    ('b0000000-0000-0000-0000-000000000002', 'Beta');

INSERT INTO tasks (id, project_id, title) VALUES
    ('d0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 'Alpha task'),
    ('d0000000-0000-0000-0000-000000000011', 'b0000000-0000-0000-0000-000000000001', 'Alpha task 2'),
    ('d0000000-0000-0000-0000-000000000002', 'b0000000-0000-0000-0000-000000000002', 'Beta task');

INSERT INTO comments (id, task_id, body) VALUES
    ('e0000000-0000-0000-0000-000000000001', 'd0000000-0000-0000-0000-000000000001', 'alpha comment'),
    ('e0000000-0000-0000-0000-000000000002', 'd0000000-0000-0000-0000-000000000002', 'beta comment');

SET letter.bypass = on;
SELECT letter.assign('public.team_members', 'user_id', role_column := 'role', scope := 'public.projects');
RESET letter.bypass;

-- Alice: editor on Alpha only.
INSERT INTO team_members (user_id, project_id, role) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 'editor');

SELECT letter.grant_scoped('select', 'public.comments', 'editor', ARRAY['body'], 'public.projects', ARRAY['task_id']);
SELECT letter.grant_scoped('update', 'public.comments', 'editor', ARRAY['body', 'task_id'], 'public.projects', ARRAY['task_id']);

-- ============================================================
-- Test 1: letter.bypass is superuser-only.
-- ============================================================
CREATE ROLE letter_test_nosuper NOSUPERUSER;
SET ROLE letter_test_nosuper;

\set VERBOSITY terse
SET letter.bypass = true;
\set VERBOSITY default

RESET ROLE;
DROP ROLE letter_test_nosuper;

-- ============================================================
-- Test 2a: scope migration within the same scope is allowed
-- (Alice moves an Alpha comment between two Alpha tasks).
-- ============================================================
SET letter.user_id = 'a0000000-0000-0000-0000-000000000001';

UPDATE comments SET task_id = 'd0000000-0000-0000-0000-000000000011'
    WHERE id = 'e0000000-0000-0000-0000-000000000001';

SELECT body FROM comments WHERE id = 'e0000000-0000-0000-0000-000000000001';

-- ============================================================
-- Test 2b: moving a row OUT of the user's scope is denied
-- (destination is Beta, where Alice has no role).
-- ============================================================
\set VERBOSITY terse
UPDATE comments SET task_id = 'd0000000-0000-0000-0000-000000000002'
    WHERE id = 'e0000000-0000-0000-0000-000000000001';

-- ============================================================
-- Test 2c: pulling a row INTO the user's scope is denied — the
-- user has rights in the destination (Alpha) but not the origin
-- (Beta). Before the OLD-scope check this succeeded.
-- ============================================================
UPDATE comments SET task_id = 'd0000000-0000-0000-0000-000000000001'
    WHERE id = 'e0000000-0000-0000-0000-000000000002';
\set VERBOSITY default

-- ============================================================
-- Test 3: role changes take effect mid-session. Alice cannot see
-- the Beta comment; granting her editor on Beta (same session,
-- same user id) makes it visible on the next read; removing the
-- role hides it again.
-- ============================================================
SELECT row_data->>'body' AS body FROM letter._read('public.comments') t(row_data)
    ORDER BY 1;

INSERT INTO team_members (id, user_id, project_id, role) VALUES
    ('c0000000-0000-0000-0000-000000000099',
     'a0000000-0000-0000-0000-000000000001',
     'b0000000-0000-0000-0000-000000000002', 'editor');

SELECT row_data->>'body' AS body FROM letter._read('public.comments') t(row_data)
    ORDER BY 1;

DELETE FROM team_members WHERE id = 'c0000000-0000-0000-0000-000000000099';

SELECT row_data->>'body' AS body FROM letter._read('public.comments') t(row_data)
    ORDER BY 1;

-- ============================================================
-- Test 4: a role name containing quote characters and SQL is
-- handled as data. Enforcement queries must not break, and the
-- role works like any other once granted to.
-- ============================================================
INSERT INTO team_members (user_id, project_id, role) VALUES
    ('a0000000-0000-0000-0000-000000000003',
     'b0000000-0000-0000-0000-000000000001',
     'ev''il; DROP TABLE users;--');

SET letter.user_id = 'a0000000-0000-0000-0000-000000000003';

-- No grants for the role yet: zero rows, no syntax error.
SELECT row_data->>'body' AS body FROM letter._read('public.comments') t(row_data)
    ORDER BY 1;

SELECT letter.grant_scoped('select', 'public.comments', 'ev''il; DROP TABLE users;--', ARRAY['body'], 'public.projects', ARRAY['task_id']);

SELECT row_data->>'body' AS body FROM letter._read('public.comments') t(row_data)
    ORDER BY 1;

-- users table is still there.
SELECT count(*) AS users_intact FROM users;

-- ============================================================
-- Test 5: letter._read() cannot be used to smuggle SQL through
-- the table name — identifiers are quoted.
-- ============================================================
\set VERBOSITY terse
SELECT * FROM letter._read('public.comments"; DROP TABLE users;--') t(row_data);
\set VERBOSITY default

SELECT count(*) AS users_still_intact FROM users;

-- Clean up
RESET letter.user_id;
SET letter.bypass = true;
DROP TABLE team_members CASCADE;
DROP TABLE comments CASCADE;
DROP TABLE tasks CASCADE;
DROP TABLE projects CASCADE;
DROP TABLE users CASCADE;
DROP EXTENSION letter CASCADE;

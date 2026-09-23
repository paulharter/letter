-- Test: write enforcement triggers

CREATE EXTENSION letter;
SET letter.enforce_reads = off;   -- this test is not about the read hook

-- Set up application tables
CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL
);

CREATE TABLE projects (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    budget INTEGER
);

CREATE TABLE team_members (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    role TEXT NOT NULL
);

-- Create users
INSERT INTO users (id, name) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'Alice'),
    ('a0000000-0000-0000-0000-000000000002', 'Bob');

-- Create projects
INSERT INTO projects (id, name) VALUES
    ('b0000000-0000-0000-0000-000000000001', 'Project Alpha'),
    ('b0000000-0000-0000-0000-000000000002', 'Project Beta');

-- Set up assignments so users get roles
SET letter.bypass = on;
SELECT letter.assign('public.team_members', 'user_id', role_column := 'role', scope := 'public.projects');
RESET letter.bypass;

INSERT INTO team_members (user_id, project_id, role) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 'editor'),
    ('a0000000-0000-0000-0000-000000000002', 'b0000000-0000-0000-0000-000000000001', 'viewer');

-- Set up grants on projects table
-- editor can update name and status, scoped to projects
SELECT letter.grant_scoped('update', 'public.projects', 'editor', ARRAY['name', 'status'], 'public.projects');
-- editor can set budget (only when NULL), scoped to projects
SELECT letter.grant_scoped('fill', 'public.projects', 'editor', ARRAY['budget'], 'public.projects');
-- editor can insert projects (unscoped)
SELECT letter.grant_global('insert', 'public.projects', 'editor');
-- editor can delete projects (unscoped — applies to any project)
SELECT letter.grant_global('delete', 'public.projects', 'editor');
-- viewer can only select (no write grants)

-- Verify GUC works
SET letter.user_id = 'alice_test';
SELECT current_setting('letter.user_id');
RESET letter.user_id;

-- ============================================================
-- Test 1: Fail closed - no user ID set
-- ============================================================
\set VERBOSITY terse

UPDATE projects SET name = 'New Name' WHERE id = 'b0000000-0000-0000-0000-000000000001';

-- ============================================================
-- Test 2: UPDATE allowed with update grant
-- ============================================================
SET letter.user_id = 'a0000000-0000-0000-0000-000000000001';

UPDATE projects SET name = 'Alpha Updated' WHERE id = 'b0000000-0000-0000-0000-000000000001';

SELECT name FROM projects WHERE id = 'b0000000-0000-0000-0000-000000000001';

-- ============================================================
-- Test 3: UPDATE denied - viewer has no update grant
-- ============================================================
SET letter.user_id = 'a0000000-0000-0000-0000-000000000002';

UPDATE projects SET name = 'Viewer Attempt' WHERE id = 'b0000000-0000-0000-0000-000000000001';

-- ============================================================
-- Test 4: SET allowed - budget is NULL, editor has set grant
-- ============================================================
SET letter.user_id = 'a0000000-0000-0000-0000-000000000001';

UPDATE projects SET budget = 50000 WHERE id = 'b0000000-0000-0000-0000-000000000001';

SELECT budget FROM projects WHERE id = 'b0000000-0000-0000-0000-000000000001';

-- ============================================================
-- Test 5: SET denied - budget is no longer NULL, set grant insufficient
-- ============================================================

UPDATE projects SET budget = 99999 WHERE id = 'b0000000-0000-0000-0000-000000000001';

-- ============================================================
-- Test 6: Scoped - editor can't update project they're not scoped to
-- ============================================================

UPDATE projects SET name = 'Beta Hacked' WHERE id = 'b0000000-0000-0000-0000-000000000002';

-- Verify Beta was not modified
SELECT name FROM projects WHERE id = 'b0000000-0000-0000-0000-000000000002';

-- ============================================================
-- Test 7: INSERT allowed with insert grant (row-level check)
-- ============================================================

-- The insert grant is unscoped, and Alice holds 'editor' only in
-- project Alpha's scope. An unscoped grant needs the role in the global
-- scope (plan/17 D11): denied.
INSERT INTO projects (id, name) VALUES ('b0000000-0000-0000-0000-000000000003', 'Project Gamma');

-- Give Alice the global 'editor' role: allowed.
INSERT INTO letter.memberships (role, user_id)
    VALUES ('editor', 'a0000000-0000-0000-0000-000000000001');

INSERT INTO projects (id, name) VALUES ('b0000000-0000-0000-0000-000000000003', 'Project Gamma');

SELECT name FROM projects WHERE id = 'b0000000-0000-0000-0000-000000000003';

-- ============================================================
-- Test 8: INSERT denied - viewer has no insert grant
-- ============================================================
SET letter.user_id = 'a0000000-0000-0000-0000-000000000002';

INSERT INTO projects (id, name) VALUES ('b0000000-0000-0000-0000-000000000004', 'Viewer Project');

-- ============================================================
-- Test 9: DELETE allowed with delete grant
-- ============================================================
SET letter.user_id = 'a0000000-0000-0000-0000-000000000001';

DELETE FROM projects WHERE id = 'b0000000-0000-0000-0000-000000000003';

SELECT count(*) AS remaining FROM projects WHERE id = 'b0000000-0000-0000-0000-000000000003';

-- ============================================================
-- Test 10: DELETE denied - viewer has no delete grant
-- ============================================================
SET letter.user_id = 'a0000000-0000-0000-0000-000000000002';

DELETE FROM projects WHERE id = 'b0000000-0000-0000-0000-000000000001';

-- ============================================================
-- Test 11: Triggers auto-installed on first grant, auto-removed on last revoke
-- ============================================================
\set VERBOSITY default

SELECT count(*) AS trigger_count FROM pg_trigger
    WHERE tgname LIKE 'letter_enforce_%'
    AND tgrelid = 'projects'::regclass;

SELECT letter.revoke_scoped('update', 'public.projects', 'editor', ARRAY['*'], 'public.projects');
SELECT letter.revoke_scoped('fill', 'public.projects', 'editor', ARRAY['*'], 'public.projects');
SELECT letter.revoke_global('insert', 'public.projects', 'editor');
SELECT letter.revoke_global('delete', 'public.projects', 'editor');

SELECT count(*) AS trigger_count_after FROM pg_trigger
    WHERE tgname LIKE 'letter_enforce_%'
    AND tgrelid = 'projects'::regclass;

-- ============================================================
-- Test 12: `if` on write grants (plan/20 §3). Alice is editor@Alpha
-- and a global editor; the projects' write triggers are re-installed
-- by the first grant below.
-- ============================================================
CREATE TABLE notes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid NOT NULL REFERENCES projects(id),
    author uuid,
    body TEXT,
    reviewed_by uuid
);
CREATE INDEX ON notes (project_id);

-- Single-row form on update: evaluated on OLD and on NEW, both must pass.
-- Editors may change the status of a project that is not archived — and
-- may not archive one, since the NEW row would fail.
SELECT letter.grant_scoped('update', 'public.projects', 'editor', ARRAY['status'], 'public.projects',
                           if := 'status <> ''archived''');
SET letter.user_id = 'a0000000-0000-0000-0000-000000000001';
UPDATE projects SET status = 'paused' WHERE id = 'b0000000-0000-0000-0000-000000000001';
UPDATE projects SET status = 'archived' WHERE id = 'b0000000-0000-0000-0000-000000000001';
SET letter.bypass = on;
UPDATE projects SET status = 'archived' WHERE id = 'b0000000-0000-0000-0000-000000000001';
RESET letter.bypass;
UPDATE projects SET status = 'active' WHERE id = 'b0000000-0000-0000-0000-000000000001';   -- OLD fails
SELECT status FROM projects WHERE id = 'b0000000-0000-0000-0000-000000000001';

-- Transition form: names old and new, evaluated once. Editors may archive
-- an active project, and nothing else under this rule.
SELECT letter.grant_scoped('update', 'public.projects', 'editor', ARRAY['status'], 'public.projects',
                           if := 'old.status = ''active'' AND new.status = ''archived''');
SET letter.bypass = on;
UPDATE projects SET status = 'active' WHERE id = 'b0000000-0000-0000-0000-000000000001';
RESET letter.bypass;
UPDATE projects SET status = 'archived' WHERE id = 'b0000000-0000-0000-0000-000000000001';   -- transition rule
UPDATE projects SET status = 'active' WHERE id = 'b0000000-0000-0000-0000-000000000001';     -- neither rule
SELECT status FROM projects WHERE id = 'b0000000-0000-0000-0000-000000000001';

-- Authorship: insert and delete only your own notes; fill reviewed_by only
-- on notes that are not yours.
SELECT letter.grant_scoped('insert', 'public.notes', 'editor', NULL, 'public.projects',
                           if := 'author = letter.user_id()::uuid');
SELECT letter.grant_scoped('delete', 'public.notes', 'editor', NULL, 'public.projects',
                           if := 'author = letter.user_id()::uuid');
SELECT letter.grant_scoped('fill', 'public.notes', 'editor', ARRAY['reviewed_by'], 'public.projects',
                           if := 'author <> letter.user_id()::uuid');
INSERT INTO notes (id, project_id, author, body) VALUES
    ('c0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001',
     'a0000000-0000-0000-0000-000000000001', 'mine');
INSERT INTO notes (id, project_id, author, body) VALUES
    ('c0000000-0000-0000-0000-000000000002', 'b0000000-0000-0000-0000-000000000001',
     'a0000000-0000-0000-0000-000000000002', 'as bob');
SET letter.bypass = on;
INSERT INTO notes (id, project_id, author, body) VALUES
    ('c0000000-0000-0000-0000-000000000002', 'b0000000-0000-0000-0000-000000000001',
     'a0000000-0000-0000-0000-000000000002', 'bobs');
RESET letter.bypass;
UPDATE notes SET reviewed_by = 'a0000000-0000-0000-0000-000000000001' WHERE body = 'mine';   -- own: refused
UPDATE notes SET reviewed_by = 'a0000000-0000-0000-0000-000000000001' WHERE body = 'bobs';   -- not own: allowed
DELETE FROM notes WHERE body = 'bobs';
DELETE FROM notes WHERE body = 'mine';
SELECT body, reviewed_by FROM notes ORDER BY body;

-- A NULL if is a failed if: a note without an author cannot be inserted.
INSERT INTO notes (project_id, author, body) VALUES ('b0000000-0000-0000-0000-000000000001', NULL, 'anon');

-- The transition form is refused on a rule with one row.
SELECT letter.grant_scoped('insert', 'public.notes', 'editor', NULL, 'public.projects',
                           if := 'old.body = new.body');
-- And on update, an unqualified name is ambiguous in the transition form:
-- the row form is tried first, so a plain expression is the row form.
SELECT letter.grant_scoped('update', 'public.notes', 'editor', ARRAY['body'], 'public.projects',
                           if := 'body <> new.body');

RESET letter.user_id;
DROP TABLE notes;

-- Clean up
DROP TABLE team_members CASCADE;
DROP TABLE projects CASCADE;
DROP TABLE users CASCADE;
DROP EXTENSION letter CASCADE;

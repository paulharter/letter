-- Test: write enforcement triggers

CREATE EXTENSION letter;

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
SELECT letter.assign('public.team_members', 'user_id', 'public.projects',
    role_name := NULL, role_column := 'role', if_fn := NULL);

INSERT INTO team_members (user_id, project_id, role) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 'editor'),
    ('a0000000-0000-0000-0000-000000000002', 'b0000000-0000-0000-0000-000000000001', 'viewer');

-- Set up grants on projects table
-- editor can update name and status, scoped to projects
SELECT letter.grant('update', 'public.projects', 'editor', ARRAY['name', 'status'], 'public.projects', NULL, NULL);
-- editor can set budget (only when NULL), scoped to projects
SELECT letter.grant('set', 'public.projects', 'editor', ARRAY['budget'], 'public.projects', NULL, NULL);
-- editor can insert projects (unscoped)
SELECT letter.grant('insert', 'public.projects', 'editor', ARRAY['*'], '', NULL, NULL);
-- editor can delete projects (unscoped — applies to any project)
SELECT letter.grant('delete', 'public.projects', 'editor', ARRAY['*'], '', NULL, NULL);
-- viewer can only select (no write grants)

-- Verify GUC works
SET letter.current_user_id = 'alice_test';
SELECT current_setting('letter.current_user_id');
RESET letter.current_user_id;

-- ============================================================
-- Test 1: Fail closed - no user ID set
-- ============================================================
\set VERBOSITY terse

UPDATE projects SET name = 'New Name' WHERE id = 'b0000000-0000-0000-0000-000000000001';

-- ============================================================
-- Test 2: UPDATE allowed with update grant
-- ============================================================
SET letter.current_user_id = 'a0000000-0000-0000-0000-000000000001';

UPDATE projects SET name = 'Alpha Updated' WHERE id = 'b0000000-0000-0000-0000-000000000001';

SELECT name FROM projects WHERE id = 'b0000000-0000-0000-0000-000000000001';

-- ============================================================
-- Test 3: UPDATE denied - viewer has no update grant
-- ============================================================
SET letter.current_user_id = 'a0000000-0000-0000-0000-000000000002';

UPDATE projects SET name = 'Viewer Attempt' WHERE id = 'b0000000-0000-0000-0000-000000000001';

-- ============================================================
-- Test 4: SET allowed - budget is NULL, editor has set grant
-- ============================================================
SET letter.current_user_id = 'a0000000-0000-0000-0000-000000000001';

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

INSERT INTO projects (id, name) VALUES ('b0000000-0000-0000-0000-000000000003', 'Project Gamma');

SELECT name FROM projects WHERE id = 'b0000000-0000-0000-0000-000000000003';

-- ============================================================
-- Test 8: INSERT denied - viewer has no insert grant
-- ============================================================
SET letter.current_user_id = 'a0000000-0000-0000-0000-000000000002';

INSERT INTO projects (id, name) VALUES ('b0000000-0000-0000-0000-000000000004', 'Viewer Project');

-- ============================================================
-- Test 9: DELETE allowed with delete grant
-- ============================================================
SET letter.current_user_id = 'a0000000-0000-0000-0000-000000000001';

DELETE FROM projects WHERE id = 'b0000000-0000-0000-0000-000000000003';

SELECT count(*) AS remaining FROM projects WHERE id = 'b0000000-0000-0000-0000-000000000003';

-- ============================================================
-- Test 10: DELETE denied - viewer has no delete grant
-- ============================================================
SET letter.current_user_id = 'a0000000-0000-0000-0000-000000000002';

DELETE FROM projects WHERE id = 'b0000000-0000-0000-0000-000000000001';

-- ============================================================
-- Test 11: Triggers auto-installed on first grant, auto-removed on last revoke
-- ============================================================
\set VERBOSITY default

SELECT count(*) AS trigger_count FROM pg_trigger
    WHERE tgname LIKE 'letter_enforce_%'
    AND tgrelid = 'projects'::regclass;

SELECT letter.revoke('update', 'public.projects', 'editor', ARRAY['*'], 'public.projects');
SELECT letter.revoke('set', 'public.projects', 'editor', ARRAY['*'], 'public.projects');
SELECT letter.revoke('insert', 'public.projects', 'editor', ARRAY['*'], '');
SELECT letter.revoke('delete', 'public.projects', 'editor', ARRAY['*'], '');

SELECT count(*) AS trigger_count_after FROM pg_trigger
    WHERE tgname LIKE 'letter_enforce_%'
    AND tgrelid = 'projects'::regclass;

-- Clean up
DROP TABLE team_members CASCADE;
DROP TABLE projects CASCADE;
DROP TABLE users CASCADE;
DROP EXTENSION letter CASCADE;

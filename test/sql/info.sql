-- Test: info/debug functions

CREATE EXTENSION letter;
SET letter.enforce_reads = off;   -- this test is not about the read hook

-- Bypass enforcement for this test (we're testing info functions, not enforcement)
SET letter.bypass = true;

-- Set up application tables and data
CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL
);

CREATE TABLE projects (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL
);

CREATE TABLE team_members (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    role TEXT NOT NULL
);

INSERT INTO users (id, name) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'Alice'),
    ('a0000000-0000-0000-0000-000000000002', 'Bob');

INSERT INTO projects (id, name) VALUES
    ('b0000000-0000-0000-0000-000000000001', 'Project Alpha'),
    ('b0000000-0000-0000-0000-000000000002', 'Project Beta');

-- Set up grants
SELECT letter.grant_global('select', 'public.projects', 'viewer', ARRAY['*']);
SELECT letter.grant_global('select', 'public.projects', 'editor', ARRAY['*']);
SELECT letter.grant_scoped('update', 'public.projects', 'editor', ARRAY['name', 'status'], 'public.projects');
SELECT letter.grant_global('delete', 'public.projects', 'admin');
SELECT letter.grant_global('insert', 'public.projects', 'admin');
SELECT letter.grant_scoped('select', 'public.team_members', 'editor', ARRAY['*'], 'public.projects');

-- Set up assignments
SELECT letter.assign('public.team_members', 'user_id', role_column := 'role', scope := 'public.projects');

-- Create some roles via assignment
INSERT INTO team_members (user_id, project_id, role) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 'editor'),
    ('a0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000002', 'viewer'),
    ('a0000000-0000-0000-0000-000000000002', 'b0000000-0000-0000-0000-000000000001', 'admin');

-- ============================================================
-- Test 1: list_grants() - all grants grouped by role
-- ============================================================

SELECT * FROM letter.list_grants() ORDER BY role, on_table, privilege, column_name;

-- ============================================================
-- Test 2: list_grants(role) - grants for a specific role
-- ============================================================

SELECT * FROM letter.list_grants('editor') ORDER BY on_table, privilege, column_name;

-- ============================================================
-- Test 3: user_permissions(user_id) - all permissions for a user
-- ============================================================

SELECT * FROM letter.user_permissions('a0000000-0000-0000-0000-000000000001')
    ORDER BY on_table, privilege, column_name, scope_table, scope_id;

-- ============================================================
-- Test 4: user_permissions for Bob (admin on Alpha only)
-- ============================================================

SELECT * FROM letter.user_permissions('a0000000-0000-0000-0000-000000000002')
    ORDER BY on_table, privilege, column_name, scope_table, scope_id;

-- ============================================================
-- Test 5: user with no roles
-- ============================================================

SELECT count(*) AS no_perms FROM letter.user_permissions('a0000000-0000-0000-0000-000000000099');

-- ============================================================
-- Test 6: letter.user_id() — the user id, NULL when unset
-- ============================================================
RESET letter.user_id;
SELECT letter.user_id() IS NULL AS unset;
SET letter.user_id = 'a0000000-0000-0000-0000-000000000001';
SELECT letter.user_id(), letter.user_id()::uuid = 'a0000000-0000-0000-0000-000000000001' AS castable;
RESET letter.user_id;

-- Clean up
DROP TABLE team_members CASCADE;
DROP TABLE projects CASCADE;
DROP TABLE users CASCADE;
DROP EXTENSION letter CASCADE;

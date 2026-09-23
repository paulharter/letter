-- Test: assign() creates rules that denormalize roles

CREATE EXTENSION letter;
SET letter.enforce_reads = off;   -- this test is not about the read hook

-- Set up application tables
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

-- ============================================================
-- Test 1: Scoped assignment with role from a column
-- "rows in team_members assign the role in the 'role' column, scoped to projects"
-- ============================================================

SET letter.bypass = on;
SELECT letter.assign('public.team_members', 'user_id', role_column := 'role', scope := 'public.projects');
RESET letter.bypass;

-- Verify the assignment rule was created
SELECT table_name, scope_table, user_column, role, role_column
    FROM letter.membership_rules;

-- Insert test data
INSERT INTO users (id, name) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'Alice'),
    ('a0000000-0000-0000-0000-000000000002', 'Bob');

INSERT INTO projects (id, name) VALUES
    ('b0000000-0000-0000-0000-000000000001', 'Project Alpha'),
    ('b0000000-0000-0000-0000-000000000002', 'Project Beta');

-- Adding a team member should create a role
INSERT INTO team_members (user_id, project_id, role) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 'editor');

SELECT role, user_id, scope_table, scope_id FROM letter.memberships ORDER BY role;
SELECT count(*) AS role_assignment_count FROM letter.membership_sources;

-- Adding another team member
INSERT INTO team_members (user_id, project_id, role) VALUES
    ('a0000000-0000-0000-0000-000000000002', 'b0000000-0000-0000-0000-000000000001', 'viewer');

SELECT role, user_id, scope_table, scope_id FROM letter.memberships ORDER BY role, user_id;

-- Updating the role column should update the role
UPDATE team_members SET role = 'admin'
    WHERE user_id = 'a0000000-0000-0000-0000-000000000001'
    AND project_id = 'b0000000-0000-0000-0000-000000000001';

SELECT role, user_id, scope_table, scope_id FROM letter.memberships ORDER BY role, user_id;

-- ============================================================
-- Test 2: Cleanup - deleting source row removes the role
-- ============================================================

DELETE FROM team_members
    WHERE user_id = 'a0000000-0000-0000-0000-000000000002'
    AND project_id = 'b0000000-0000-0000-0000-000000000001';

SELECT role, user_id FROM letter.memberships ORDER BY role;
SELECT count(*) AS remaining FROM letter.membership_sources;

-- ============================================================
-- Test 3: Cleanup - deleting scope row removes scoped roles
-- ============================================================

-- Give Alice a role on Beta too
INSERT INTO team_members (user_id, project_id, role) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000002', 'viewer');

SELECT count(*) AS roles_before FROM letter.memberships;

-- Delete Project Alpha - should remove Alice's admin role on Alpha but keep her viewer on Beta
DELETE FROM projects WHERE id = 'b0000000-0000-0000-0000-000000000001';

SELECT role, user_id, scope_id FROM letter.memberships ORDER BY role;

-- ============================================================
-- Test 4: Cleanup - deleting user cascades through and removes roles
-- ============================================================

DELETE FROM users WHERE id = 'a0000000-0000-0000-0000-000000000001';

SELECT count(*) AS roles_after_user_delete FROM letter.memberships;
SELECT count(*) AS assignments_after FROM letter.membership_sources;

-- ============================================================
-- Test 5: Unscoped assignment with a fixed role name
-- ============================================================

CREATE TABLE admins (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE
);

SET letter.bypass = on;
SELECT letter.assign('public.admins', 'user_id', role := 'superadmin');
RESET letter.bypass;

INSERT INTO users (id, name) VALUES ('a0000000-0000-0000-0000-000000000003', 'Charlie');
INSERT INTO admins (user_id) VALUES ('a0000000-0000-0000-0000-000000000003');

SELECT role, user_id, scope_table, scope_id FROM letter.memberships;

-- Removing from admins removes the role
DELETE FROM admins WHERE user_id = 'a0000000-0000-0000-0000-000000000003';

SELECT count(*) AS roles_after_admin_delete FROM letter.memberships;

-- ============================================================
-- Test 6: assign with an if (plan/20 §3): the source row must satisfy
-- it to confer the membership — on backfill, on insert, and as it
-- changes. Validated like a grant's if.
-- ============================================================
CREATE TABLE staff (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    active boolean NOT NULL DEFAULT true,
    title TEXT
);
INSERT INTO users (id, name) VALUES
    ('a0000000-0000-0000-0000-000000000004', 'Dora'),
    ('a0000000-0000-0000-0000-000000000005', 'Eve');
INSERT INTO staff (user_id, active, title) VALUES
    ('a0000000-0000-0000-0000-000000000004', true,  'on duty'),
    ('a0000000-0000-0000-0000-000000000005', false, 'on leave');
SET letter.bypass = on;
SELECT letter.assign('public.staff', 'user_id', role := 'staff', if := 'active AND title <> ''fired''');
\set VERBOSITY terse
SELECT letter.assign('public.staff', 'user_id', role := 'bad', if := 'title');
SELECT letter.assign('public.staff', 'user_id', role := 'bad', if := 'EXISTS (SELECT 1)');
\set VERBOSITY default
RESET letter.bypass;
SELECT role, user_id FROM letter.memberships WHERE role = 'staff' ORDER BY user_id;
UPDATE staff SET active = true WHERE title = 'on leave';                 -- Eve joins
UPDATE staff SET title = 'fired' WHERE user_id = 'a0000000-0000-0000-0000-000000000004';   -- Dora leaves
SELECT role, user_id FROM letter.memberships WHERE role = 'staff' ORDER BY user_id;
INSERT INTO users (id, name) VALUES ('a0000000-0000-0000-0000-000000000006', 'Fay');
INSERT INTO staff (user_id, active) VALUES ('a0000000-0000-0000-0000-000000000006', false);   -- no membership
SELECT count(*) AS staff_memberships FROM letter.memberships WHERE role = 'staff';
-- Dropping a column the if names removes the rule (and its memberships).
ALTER TABLE staff DROP COLUMN title;
SELECT count(*) AS rules FROM letter.membership_rules WHERE table_name = 'public.staff'::regclass;
SELECT count(*) AS staff_memberships FROM letter.memberships WHERE role = 'staff';
DROP TABLE staff CASCADE;

DROP TABLE admins CASCADE;
DROP TABLE team_members CASCADE;
DROP TABLE projects CASCADE;
DROP TABLE users CASCADE;
DROP EXTENSION letter CASCADE;

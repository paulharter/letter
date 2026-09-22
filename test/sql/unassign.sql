-- Test: unassign() removes assignment rules and cleans up

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

-- Create test data
INSERT INTO users (id, name) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'Alice');
INSERT INTO projects (id, name) VALUES
    ('b0000000-0000-0000-0000-000000000001', 'Project Alpha');

-- Create a scoped assignment
SET letter.bypass = on;
SELECT letter.assign(
    'public.team_members', 'user_id', 'public.projects',
    role_name := NULL, role_column := 'role', if_fn := NULL
);
RESET letter.bypass;

-- Add a team member to generate a role
INSERT INTO team_members (user_id, project_id, role) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 'editor');

SELECT count(*) AS roles_before FROM letter.roles;
SELECT count(*) AS assignments_before FROM letter.assignments;

-- Unassign the rule
SET letter.bypass = on;
SELECT letter.unassign(
    'public.team_members', 'user_id', 'public.projects',
    role_name := NULL, role_column := 'role'
);
RESET letter.bypass;

-- Assignment rule should be gone
SELECT count(*) AS assignments_after FROM letter.assignments;

-- Roles and role_assignments should be cleaned up
SELECT count(*) AS roles_after FROM letter.roles;
SELECT count(*) AS role_assignments_after FROM letter.role_assignments;

-- Triggers should be removed - inserting should not create roles
INSERT INTO team_members (user_id, project_id, role) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 'admin');

SELECT count(*) AS roles_no_trigger FROM letter.roles;

-- ============================================================
-- Test 2: Unscoped unassign
-- ============================================================

CREATE TABLE admins (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE
);

SET letter.bypass = on;
SELECT letter.assign(
    'public.admins', 'user_id', NULL,
    role_name := 'superadmin', role_column := NULL, if_fn := NULL
);
RESET letter.bypass;

INSERT INTO admins (user_id) VALUES ('a0000000-0000-0000-0000-000000000001');
SELECT count(*) AS roles_before_unscp FROM letter.roles;

SET letter.bypass = on;
SELECT letter.unassign(
    'public.admins', 'user_id', NULL,
    role_name := 'superadmin', role_column := NULL
);
RESET letter.bypass;

SELECT count(*) AS roles_after_unscp FROM letter.roles;
SELECT count(*) AS assignments_after_unscp FROM letter.assignments;

DROP TABLE admins CASCADE;
DROP TABLE team_members CASCADE;
DROP TABLE projects CASCADE;
DROP TABLE users CASCADE;
DROP EXTENSION letter CASCADE;

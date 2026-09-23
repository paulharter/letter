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
SELECT letter.assign('public.team_members', 'user_id', role_column := 'role', scope := 'public.projects');
RESET letter.bypass;

-- Add a team member to generate a role
INSERT INTO team_members (user_id, project_id, role) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 'editor');

SELECT count(*) AS roles_before FROM letter.memberships;
SELECT count(*) AS assignments_before FROM letter.membership_rules;

-- Unassign the rule
SET letter.bypass = on;
SELECT letter.unassign('public.team_members', 'user_id', role_column := 'role', scope := 'public.projects');
RESET letter.bypass;

-- Assignment rule should be gone
SELECT count(*) AS assignments_after FROM letter.membership_rules;

-- Memberships and membership_sources should be cleaned up
SELECT count(*) AS roles_after FROM letter.memberships;
SELECT count(*) AS membership_sources_after FROM letter.membership_sources;

-- Triggers should be removed - inserting should not create roles
INSERT INTO team_members (user_id, project_id, role) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 'admin');

SELECT count(*) AS roles_no_trigger FROM letter.memberships;

-- ============================================================
-- Test 2: Unscoped unassign
-- ============================================================

CREATE TABLE admins (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE
);

SET letter.bypass = on;
SELECT letter.assign('public.admins', 'user_id', role := 'superadmin');
RESET letter.bypass;

INSERT INTO admins (user_id) VALUES ('a0000000-0000-0000-0000-000000000001');
SELECT count(*) AS roles_before_unscp FROM letter.memberships;

SET letter.bypass = on;
SELECT letter.unassign('public.admins', 'user_id', role := 'superadmin');
RESET letter.bypass;

SELECT count(*) AS roles_after_unscp FROM letter.memberships;
SELECT count(*) AS assignments_after_unscp FROM letter.membership_rules;

DROP TABLE admins CASCADE;
DROP TABLE team_members CASCADE;
DROP TABLE projects CASCADE;
DROP TABLE users CASCADE;
DROP EXTENSION letter CASCADE;

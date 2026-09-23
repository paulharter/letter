-- Test: letter._read() enforced reads returning JSONB
--
-- Semantics under test:
--   1. letter.user_id unset → ERROR. This is a hard precondition;
--      letter fails closed loudly so the application cannot silently read
--      without identity.
--   2. Once a user id is set, no other access failure raises an error —
--      missing access is represented by absent rows:
--        a. User has no applicable select grant for the table → zero rows.
--        b. User has no applicable select grant for a specific row → that row
--           is excluded (not returned as a fully-redacted shell).
--        c. WHERE condition that filters to rows the user cannot see → zero
--           rows, no error.
--   3. For rows the user can see, the row is returned with columns lacking a
--      matching grant set to NULL and listed in _redacted. The PK is always
--      visible on any returned row.
--   4. letter.bypass = true returns everything untouched.

CREATE EXTENSION letter;
SET letter.enforce_reads = off;   -- this test is not about the read hook
SET letter.bypass = true;

CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL
);

CREATE TABLE projects (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    budget INTEGER,
    notes TEXT
);

CREATE TABLE team_members (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    role TEXT NOT NULL
);

-- A table with no grants ever, for the no-grants-on-table case.
CREATE TABLE widgets (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL
);

CREATE TABLE auditors (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE reporters (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE
);

INSERT INTO users (id, name) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'Alice'),
    ('a0000000-0000-0000-0000-000000000002', 'Bob'),
    ('a0000000-0000-0000-0000-000000000003', 'Carol'),
    ('a0000000-0000-0000-0000-000000000004', 'Dora');

INSERT INTO projects (id, name, status, budget, notes) VALUES
    ('b0000000-0000-0000-0000-000000000001', 'Alpha', 'active', 50000, 'alpha notes'),
    ('b0000000-0000-0000-0000-000000000002', 'Beta',  'draft',  NULL,  NULL),
    ('b0000000-0000-0000-0000-000000000003', 'Gamma', 'done',   10000, 'gamma notes');

INSERT INTO widgets (id, name) VALUES
    ('c0000000-0000-0000-0000-000000000001', 'Widget-1');

-- Scoped assignments: role derived from team_members.role, scoped to projects.
SELECT letter.assign('public.team_members', 'user_id', role_column := 'role', scope := 'public.projects');

-- Unscoped assignment: auditors are global 'auditor' role.
SELECT letter.assign('public.auditors', 'user_id', role := 'auditor');

-- Unscoped assignment: reporters are global 'reporter' role.
SELECT letter.assign('public.reporters', 'user_id', role := 'reporter');

-- Alice: editor on Alpha, viewer on Beta. No role on Gamma.
-- Bob:   viewer on Alpha only.
-- Carol: reporter only (select on users, not projects).
-- Dora:  auditor (unscoped role).
INSERT INTO team_members (user_id, project_id, role) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 'editor'),
    ('a0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000002', 'viewer'),
    ('a0000000-0000-0000-0000-000000000002', 'b0000000-0000-0000-0000-000000000001', 'viewer');

INSERT INTO auditors (user_id) VALUES ('a0000000-0000-0000-0000-000000000004');
INSERT INTO reporters (user_id) VALUES ('a0000000-0000-0000-0000-000000000003');

-- Grants on projects:
--   editor:  select all columns, scoped to projects
--   viewer:  select name + status only, scoped to projects
--   auditor: select name only, unscoped
SELECT letter.grant_scoped('select', 'public.projects', 'editor', ARRAY['*'], 'public.projects');
SELECT letter.grant_scoped('select', 'public.projects', 'viewer', ARRAY['name', 'status'], 'public.projects');
SELECT letter.grant_global('select', 'public.projects', 'auditor', ARRAY['name']);

-- reporter has select on users only — used to test "user has grants, but not
-- on this table".
SELECT letter.grant_global('select', 'public.users', 'reporter', ARRAY['*']);

SET letter.bypass = false;

\set VERBOSITY terse

-- ============================================================
-- Test 1: letter.user_id is unset → ERROR (fail closed loudly)
-- ============================================================
RESET letter.user_id;
SELECT * FROM letter._read('public.projects');

-- ============================================================
-- Test 2: Table with no letter grants at all → an error (plan/17 D14:
-- a missing grant is a configuration mistake, not an authorization outcome).
-- ============================================================
SET letter.user_id = 'a0000000-0000-0000-0000-000000000001';
SELECT count(*) AS row_count FROM letter._read('public.widgets');

-- ============================================================
-- Test 3: User has select grants, but none on this table → zero rows
-- Carol has 'reporter' with select on users only.
-- ============================================================
SET letter.user_id = 'a0000000-0000-0000-0000-000000000003';
SELECT count(*) AS row_count FROM letter._read('public.projects');

-- Sanity: Carol can still read users via her reporter grant.
SELECT count(*) > 0 AS carol_sees_users FROM letter._read('public.users');

-- ============================================================
-- Test 4: Unknown user id (no roles, no assignments) → zero rows
-- ============================================================
SET letter.user_id = 'a0000000-0000-0000-0000-0000000000ff';
SELECT count(*) AS row_count FROM letter._read('public.projects');

-- ============================================================
-- Test 5: Alice as editor on Alpha → full row, empty _redacted
-- ============================================================
SET letter.user_id = 'a0000000-0000-0000-0000-000000000001';
SELECT
    row_data->>'name'    AS name,
    row_data->>'status'  AS status,
    row_data->>'budget'  AS budget,
    row_data->>'notes'   AS notes,
    jsonb_array_length(row_data->'_redacted') AS redacted_len
FROM letter._read('public.projects',
    'id = ''b0000000-0000-0000-0000-000000000001''') t(row_data);

-- ============================================================
-- Test 6: Alice as viewer on Beta → name+status visible, budget+notes redacted
-- PK must still be present on the returned row.
-- ============================================================
SELECT
    row_data ? 'id'        AS has_id,
    row_data->>'name'      AS name,
    row_data->>'status'    AS status,
    row_data->>'budget'    AS budget,
    row_data->>'notes'     AS notes,
    'budget' = ANY(SELECT jsonb_array_elements_text(row_data->'_redacted')) AS budget_redacted,
    'notes'  = ANY(SELECT jsonb_array_elements_text(row_data->'_redacted')) AS notes_redacted,
    'status' = ANY(SELECT jsonb_array_elements_text(row_data->'_redacted')) AS status_redacted,
    'name'   = ANY(SELECT jsonb_array_elements_text(row_data->'_redacted')) AS name_redacted
FROM letter._read('public.projects',
    'id = ''b0000000-0000-0000-0000-000000000002''') t(row_data);

-- ============================================================
-- Test 7: Alice on Gamma (no role on that project) → row excluded
-- Previously returned a fully-redacted shell row; new semantics omit it.
-- ============================================================
SELECT count(*) AS row_count FROM letter._read('public.projects',
    'id = ''b0000000-0000-0000-0000-000000000003''');

-- ============================================================
-- Test 8: Alice reads all projects — Alpha and Beta only; Gamma excluded
-- ============================================================
SELECT
    row_data->>'name'                         AS name,
    row_data->>'budget'                       AS budget,
    jsonb_array_length(row_data->'_redacted') AS redacted_count
FROM letter._read('public.projects') t(row_data)
ORDER BY row_data->>'name';

-- ============================================================
-- Test 9: Bob reads all projects — only Alpha; Beta and Gamma excluded
-- ============================================================
SET letter.user_id = 'a0000000-0000-0000-0000-000000000002';
SELECT
    row_data->>'name'                         AS name,
    row_data->>'budget'                       AS budget,
    jsonb_array_length(row_data->'_redacted') AS redacted_count
FROM letter._read('public.projects') t(row_data)
ORDER BY row_data->>'name';

-- ============================================================
-- Test 10: WHERE condition picks an out-of-scope row → zero rows, no error
-- ============================================================
SELECT count(*) AS row_count FROM letter._read('public.projects',
    'id = ''b0000000-0000-0000-0000-000000000003''');

-- ============================================================
-- Test 11: WHERE condition matches no rows at all → zero rows, no error
-- ============================================================
SELECT count(*) AS row_count FROM letter._read('public.projects',
    'id = ''00000000-0000-0000-0000-000000000000''');

-- ============================================================
-- Test 12: Genuine NULL vs redacted NULL
-- Beta's budget is genuinely NULL; viewer also lacks select on budget. Both
-- are NULL in the row, but budget appears in _redacted while status does not.
-- ============================================================
SET letter.user_id = 'a0000000-0000-0000-0000-000000000001';
SELECT
    row_data->>'name'   AS name,
    row_data->>'status' AS status,
    row_data->>'budget' AS budget,
    'budget' = ANY(SELECT jsonb_array_elements_text(row_data->'_redacted')) AS budget_redacted,
    'status' = ANY(SELECT jsonb_array_elements_text(row_data->'_redacted')) AS status_redacted,
    'notes'  = ANY(SELECT jsonb_array_elements_text(row_data->'_redacted')) AS notes_redacted
FROM letter._read('public.projects',
    'id = ''b0000000-0000-0000-0000-000000000002''') t(row_data);

-- ============================================================
-- Test 13: Unscoped select grant applies to all rows regardless of scope
-- Dora (auditor, unscoped, select on name only) sees all 3 projects, each with
-- only name visible and the rest redacted.
-- ============================================================
SET letter.user_id = 'a0000000-0000-0000-0000-000000000004';
SELECT
    row_data->>'name'                         AS name,
    row_data->>'status'                       AS status,
    row_data->>'budget'                       AS budget,
    row_data ? 'id'                           AS has_id,
    jsonb_array_length(row_data->'_redacted') AS redacted_count
FROM letter._read('public.projects') t(row_data)
ORDER BY row_data->>'name';

-- ============================================================
-- Test 14: bypass returns everything untouched
-- ============================================================
SET letter.bypass = true;
SELECT count(*) AS row_count FROM letter._read('public.projects');
SELECT count(*) AS widgets_count FROM letter._read('public.widgets');
SET letter.bypass = false;

\set VERBOSITY default

-- Clean up
SET letter.bypass = true;
DROP TABLE reporters CASCADE;
DROP TABLE auditors CASCADE;
DROP TABLE widgets CASCADE;
DROP TABLE team_members CASCADE;
DROP TABLE projects CASCADE;
DROP TABLE users CASCADE;
DROP EXTENSION letter CASCADE;

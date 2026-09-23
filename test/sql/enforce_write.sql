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

-- ============================================================
-- Test 13: the built-in roles on the write path (plan/22). Sign-up: any
-- session with a user may insert its own users row and no other. A
-- guestbook: anyone may insert, no user set at all. With no user set, a
-- table whose write rules all need a user still errors as before.
-- ============================================================
SELECT letter.grant_global('insert', 'public.users', 'any_user', if := 'id = letter.user_id()::uuid');
SET letter.user_id = 'a0000000-0000-0000-0000-000000000009';
INSERT INTO users (id, name) VALUES ('a0000000-0000-0000-0000-000000000009', 'Ida');     -- herself
INSERT INTO users (id, name) VALUES ('a0000000-0000-0000-0000-000000000010', 'Jon');     -- somebody else
RESET letter.user_id;
INSERT INTO users (id, name) VALUES ('a0000000-0000-0000-0000-000000000010', 'Jon');     -- nobody at all
SELECT name FROM users ORDER BY name;

CREATE TABLE guestbook (id serial PRIMARY KEY, line text, approved boolean NOT NULL DEFAULT false);
SELECT letter.grant_global('insert', 'public.guestbook', 'anyone', if := 'NOT approved');
SELECT letter.grant_global('update', 'public.guestbook', 'any_user', ARRAY['line']);
INSERT INTO guestbook (line) VALUES ('hello from nobody');                 -- no user set: anyone
INSERT INTO guestbook (line, approved) VALUES ('sneaky', true);            -- the if
UPDATE guestbook SET line = 'edited';                                      -- no user: no anyone rule for update
SET letter.user_id = 'a0000000-0000-0000-0000-000000000009';
UPDATE guestbook SET line = 'edited by ida';                               -- but any user may
SELECT line, approved FROM guestbook;
RESET letter.user_id;
SELECT letter.revoke_global('insert', 'public.users', 'any_user');
DROP TABLE guestbook;

-- ============================================================
-- Test 14: no cap on a user's memberships or grants (plan/24 B4). The
-- session cache used to hold 256 memberships and 1024 grants and drop the
-- rest silently — a user past the cap was refused writes the barrier
-- permitted. Membership 300 and grant 1100 are the ones that matter.
-- ============================================================
CREATE TABLE rooms (id int PRIMARY KEY, name text);
CREATE TABLE room_notes (id serial PRIMARY KEY, room_id int NOT NULL REFERENCES rooms(id), body text);
CREATE INDEX ON room_notes (room_id);
INSERT INTO rooms SELECT g, 'room ' || g FROM generate_series(1, 300) g;
INSERT INTO letter.memberships (role, user_id, scope_table, scope_id)
    SELECT 'member', 'many', 'public.rooms', g::text FROM generate_series(1, 300) g;
SELECT letter.grant_scoped('insert', 'public.room_notes', 'member', NULL, 'public.rooms');
SET letter.user_id = 'many';
INSERT INTO room_notes (room_id, body) VALUES (300, 'in the last room');
-- 1100 global roles, only the last of which may delete; 1099 select grants first
INSERT INTO letter.memberships (role, user_id) SELECT 'r' || g, 'many' FROM generate_series(1, 1100) g;
SELECT letter.grant_global('select', 'public.room_notes', 'r1', ARRAY['body']);    -- installs the triggers
INSERT INTO letter.grants (privilege, on_table, role, column_name, scope)
    SELECT 'select', 'public.room_notes'::regclass, 'r' || g, 'body', 0 FROM generate_series(2, 1099) g;
INSERT INTO letter.grants (privilege, on_table, role, column_name, scope)
    VALUES ('delete', 'public.room_notes'::regclass, 'r1100', '*', 0);
DELETE FROM room_notes WHERE body = 'in the last room';
SELECT count(*) AS notes_left FROM room_notes;
RESET letter.user_id;
DELETE FROM letter.memberships WHERE user_id = 'many';
DROP TABLE room_notes, rooms;

-- ============================================================
-- Test 15: an if runs as the writer, not as the extension owner
-- (plan/24 A1). A function the if names sees the writer's identity;
-- before, every write evaluated it as letter's owner, a superuser.
-- ============================================================
CREATE ROLE letter_test_writer;
GRANT USAGE ON SCHEMA letter TO letter_test_writer;
GRANT SELECT, INSERT ON users TO letter_test_writer;
CREATE FUNCTION who_writes() RETURNS text LANGUAGE sql IMMUTABLE AS $$ SELECT current_user::text $$;
SELECT letter.grant_global('insert', 'public.users', 'any_user', if := 'who_writes() = ''letter_test_writer''');
SET letter.user_id = 'a0000000-0000-0000-0000-000000000011';
INSERT INTO users (id, name) VALUES ('a0000000-0000-0000-0000-000000000011', 'as superuser');   -- refused: not the writer named
SET ROLE letter_test_writer;
INSERT INTO users (id, name) VALUES ('a0000000-0000-0000-0000-000000000011', 'as the writer');  -- allowed
RESET ROLE;
SELECT name FROM users WHERE id = 'a0000000-0000-0000-0000-000000000011';
RESET letter.user_id;
SELECT letter.revoke_global('insert', 'public.users', 'any_user');
DROP FUNCTION who_writes();
REVOKE ALL ON users FROM letter_test_writer;
REVOKE USAGE ON SCHEMA letter FROM letter_test_writer;
DROP ROLE letter_test_writer;

-- Clean up
DROP TABLE team_members CASCADE;
DROP TABLE projects CASCADE;
DROP TABLE users CASCADE;
DROP EXTENSION letter CASCADE;

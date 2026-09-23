-- Test: object identity and lifecycle (plan/18-object-identity-and-lifecycle.md §3)
--
-- Tables are identified by OID, so protection follows a rename. Dropping
-- something letter depends on removes the dependent letter state with a
-- NOTICE; altering something so that letter state no longer makes sense is
-- refused. One case per row of the mutation matrix (18 §3.1) that a
-- regression test can exercise.

CREATE EXTENSION letter;
SET letter.enforce_reads = off;   -- this test is not about the read hook
CREATE SCHEMA other;

CREATE TABLE users (id uuid PRIMARY KEY, name TEXT);
CREATE TABLE projects (id uuid PRIMARY KEY, name TEXT);
CREATE TABLE tasks (
    id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(id),
    title TEXT
);
CREATE INDEX tasks_project_id_idx ON tasks (project_id);
CREATE TABLE comments (
    id uuid PRIMARY KEY,
    task_id uuid REFERENCES tasks(id),
    author TEXT,
    body TEXT
);
CREATE INDEX comments_task_id_idx ON comments (task_id);
CREATE TABLE reactions (
    id uuid PRIMARY KEY,
    comment_id uuid REFERENCES comments(id),
    emoji TEXT
);
CREATE INDEX reactions_comment_id_idx ON reactions (comment_id);
CREATE TABLE team_members (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id),
    project_id uuid NOT NULL REFERENCES projects(id),
    role TEXT NOT NULL
);
CREATE TABLE auditors (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL);

INSERT INTO users VALUES
    ('a0000000-0000-0000-0000-000000000001', 'Alice'),
    ('a0000000-0000-0000-0000-000000000002', 'Bob');
INSERT INTO projects VALUES
    ('b0000000-0000-0000-0000-000000000001', 'Alpha'),
    ('b0000000-0000-0000-0000-000000000002', 'Beta');
INSERT INTO tasks VALUES
    ('c0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 'task-Alpha');
INSERT INTO comments VALUES
    ('d0000000-0000-0000-0000-000000000001', 'c0000000-0000-0000-0000-000000000001', 'ann', 'on Alpha');
INSERT INTO reactions VALUES
    ('e0000000-0000-0000-0000-000000000001', 'd0000000-0000-0000-0000-000000000001', 'r1');

SET letter.bypass = on;
SELECT letter.assign('public.team_members', 'user_id', role_column := 'role', scope := 'public.projects');
SELECT letter.assign('public.auditors', 'user_id', role := 'auditor');
RESET letter.bypass;

INSERT INTO team_members (user_id, project_id, role) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 'editor'),
    ('a0000000-0000-0000-0000-000000000002', 'b0000000-0000-0000-0000-000000000002', 'editor');
INSERT INTO auditors (user_id) VALUES ('a0000000-0000-0000-0000-000000000002');

SELECT letter.grant_scoped('select', 'public.comments', 'editor', ARRAY['body'], 'public.projects', ARRAY['task_id']);
SELECT letter.grant_scoped('update', 'public.comments', 'editor', ARRAY['body'], 'public.projects', ARRAY['task_id']);
SELECT letter.grant_global('select', 'public.comments', 'auditor', ARRAY['author']);
SELECT letter.grant_scoped('select', 'public.reactions', 'editor', ARRAY['emoji'], 'public.projects', ARRAY['comment_id', 'task_id']);
SELECT letter.grant_scoped('select', 'public.tasks', 'editor', ARRAY['title'], 'public.projects');

-- letter's state, as text; OIDs and assignment ids are normalised away so
-- the expected output is stable.
CREATE VIEW state AS
    SELECT 'grant' AS kind, g.on_table::text AS tbl, g.role || '/' || g.privilege || '/' || g.column_name AS detail
    FROM letter.grants g
    UNION ALL
    SELECT 'assignment', a.table_name::text, COALESCE(a.scope_table::text, '-')
    FROM letter.membership_rules a
    UNION ALL
    SELECT 'role', COALESCE(r.scope_table::text, '-'), r.role || '@' || left(r.user_id, 8)
    FROM letter.memberships r
    UNION ALL
    SELECT 'trigger', t.tgrelid::regclass::text, regexp_replace(t.tgname, 'rule_[0-9a-f]{8}', 'rule_<id>')
    FROM pg_trigger t WHERE t.tgname LIKE 'letter\_%' AND NOT t.tgisinternal
    UNION ALL
    SELECT 'function', 'letter', regexp_replace(p.proname, 'rule_[0-9a-f]{8}', 'rule_<id>')
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'letter' AND p.proname LIKE '\_rule\_%';

SELECT * FROM state ORDER BY 1, 2, 3;

\set VERBOSITY terse

-- ============================================================
-- 1. Rename / set schema: protection follows the table.
-- ============================================================
ALTER TABLE comments RENAME TO remarks;
ALTER TABLE remarks SET SCHEMA other;

SELECT tbl, detail FROM state WHERE kind = 'grant' AND tbl LIKE '%remarks' ORDER BY 2;

-- write enforcement still applies under the new name
SET letter.user_id = 'a0000000-0000-0000-0000-000000000001';
UPDATE other.remarks SET body = 'edited by alice' WHERE id = 'd0000000-0000-0000-0000-000000000001';
SET letter.user_id = 'a0000000-0000-0000-0000-000000000002';
UPDATE other.remarks SET body = 'edited by bob' WHERE id = 'd0000000-0000-0000-0000-000000000001';
RESET letter.user_id;
SELECT body FROM other.remarks;

-- and the planner hook still substitutes it
SET letter.enforce_reads = on;
SET letter.user_id = 'a0000000-0000-0000-0000-000000000001';
SET client_min_messages = debug1;
SELECT count(*) FROM other.remarks;
RESET client_min_messages;
SET letter.enforce_reads = off;

ALTER TABLE other.remarks SET SCHEMA public;
ALTER TABLE remarks RENAME TO comments;

-- ============================================================
-- 2. Altering so that letter state stops making sense is refused.
-- ============================================================
-- a granted column
ALTER TABLE comments RENAME COLUMN body TO text;
-- a via column
ALTER TABLE comments RENAME COLUMN task_id TO task;
-- a rule's user column
ALTER TABLE team_members RENAME COLUMN user_id TO member_id;
-- a rule's key column and its scope column: the generated functions name
-- them (plan/24 B1)
ALTER TABLE team_members RENAME COLUMN id TO tm_id;
ALTER TABLE team_members RENAME COLUMN project_id TO proj_id;
-- an FK on a path (explicit hop, then inferred final hop)
ALTER TABLE comments DROP CONSTRAINT comments_task_id_fkey;
ALTER TABLE tasks DROP CONSTRAINT tasks_project_id_fkey;
-- a second FK that makes an inferred final hop ambiguous
ALTER TABLE tasks ADD COLUMN alt_project uuid REFERENCES projects(id);
-- a composite PK on a hop table
ALTER TABLE tasks DROP CONSTRAINT tasks_pkey CASCADE, ADD PRIMARY KEY (id, project_id);
-- no PK at all on a scope table (plan/24, 2026-09-23)
ALTER TABLE projects DROP CONSTRAINT projects_pkey CASCADE;
-- a rule's scope FK
ALTER TABLE team_members DROP CONSTRAINT team_members_project_id_fkey;

-- nothing changed
SELECT attname FROM pg_attribute WHERE attrelid = 'comments'::regclass AND attnum > 0 ORDER BY attnum;
SELECT attname FROM pg_attribute WHERE attrelid = 'team_members'::regclass AND attnum > 0 ORDER BY attnum;
SELECT conname FROM pg_constraint WHERE conrelid IN ('comments'::regclass, 'tasks'::regclass) ORDER BY 1;

-- columns can be added, and an ungranted column renamed
ALTER TABLE comments ADD COLUMN extra TEXT;
ALTER TABLE comments RENAME COLUMN extra TO spare;

-- a leaf may lose its PK (only scope and hop tables need one)
ALTER TABLE reactions DROP CONSTRAINT reactions_pkey;
ALTER TABLE reactions ADD PRIMARY KEY (id);

-- dropping an index on a path column is allowed, with the grant-time warning
DROP INDEX comments_task_id_idx;
CREATE INDEX comments_task_id_idx ON comments (task_id);

-- ============================================================
-- 2b. A function an if names (plan/24 B3): changing it so that the
--     if no longer validates is refused, dropping it removes the
--     rules that name it — grants and membership rules alike.
-- ============================================================
CREATE FUNCTION is_ok(t text) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$ SELECT t <> 'no' $$;
SELECT letter.grant_scoped('update', 'public.comments', 'editor', ARRAY['body'], 'public.projects',
                           ARRAY['task_id'], if := 'is_ok(body)');
SET letter.bypass = on;
SELECT letter.assign('public.auditors', 'user_id', role := 'checked', if := 'is_ok(user_id::text)');
RESET letter.bypass;
ALTER FUNCTION is_ok(text) STABLE;                    -- no longer allowed in an if: refused
CREATE OR REPLACE FUNCTION is_ok(t text) RETURNS boolean LANGUAGE sql STABLE AS $$ SELECT t <> 'no' $$;   -- the same by replacement: refused
CREATE OR REPLACE FUNCTION is_ok(t text) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$ SELECT t <> 'never' $$;   -- a new body, still IMMUTABLE: fine
CREATE FUNCTION unrelated() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$;   -- any other function: fine
DROP FUNCTION unrelated();
ALTER FUNCTION is_ok(text) RENAME TO is_fine;         -- the if would not resolve: refused
SELECT provolatile, proname FROM pg_proc WHERE proname IN ('is_ok', 'is_fine');
DROP FUNCTION is_ok(text);                            -- cascades, with a NOTICE each
SELECT count(*) AS grants_with_if FROM letter.grants WHERE "if" IS NOT NULL;
SELECT count(*) AS rules_with_if FROM letter.membership_rules WHERE "if" IS NOT NULL;
SELECT * FROM state ORDER BY 1, 2, 3;

-- ============================================================
-- 3. TRUNCATE on a protected table requires bypass (18 D3).
-- ============================================================
TRUNCATE reactions;
SET letter.bypass = on;
TRUNCATE reactions;
RESET letter.bypass;
SELECT count(*) FROM reactions;

-- ============================================================
-- 4. Dropping a column removes the grants on it; dropping a
--    via column removes the grants through it.
-- ============================================================
ALTER TABLE comments DROP COLUMN author;
SELECT tbl, detail FROM state WHERE kind = 'grant' ORDER BY 1, 2;

ALTER TABLE reactions DROP COLUMN comment_id;
SELECT tbl, detail FROM state WHERE kind IN ('grant', 'trigger') AND tbl = 'reactions' ORDER BY 1, 2;

-- ============================================================
-- 5. Dropping a hop table removes the grants whose paths cross it,
--    and the enforcement triggers of a table left with no grants.
-- ============================================================
DROP TABLE tasks CASCADE;
SELECT * FROM state WHERE kind IN ('grant', 'trigger') ORDER BY 1, 2, 3;

-- ============================================================
-- 6. Dropping a source table removes its assignment, functions,
--    triggers and roles.
-- ============================================================
DROP TABLE auditors;
SELECT * FROM state WHERE kind IN ('assignment', 'role', 'function') ORDER BY 1, 2, 3;

-- ============================================================
-- 7. Dropping a scope table removes the assignments scoped to it
--    (with their triggers on the surviving source table), the roles
--    scoped to it, and the grants scoped to it.
-- ============================================================
SELECT letter.grant_scoped('select', 'public.team_members', 'editor', ARRAY['role'], 'public.projects');
DROP TABLE projects CASCADE;
SELECT * FROM state ORDER BY 1, 2, 3;

-- ============================================================
-- 7b. The users table (plan/24 B8): deleting a row of it forgets that
--     user — every membership the key holds goes, the rule-derived ones
--     with their sources and the directly-managed ones — and nobody
--     else's. Changing the key forgets the old one. While declared, its
--     key column may not be renamed; a trigger dropped by hand shows in
--     check_health().
-- ============================================================
SET letter.bypass = on;
CREATE TABLE members (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL);   -- no FK: a source that outlives its user
SELECT letter.assign('public.members', 'user_id', role := 'member');
DELETE FROM team_members;                     -- the application's own FK housekeeping (no cascade in this schema)
SELECT letter.users('public.users');
SELECT letter.users('public.users');          -- again: the same declaration
SELECT letter.users('public.members');        -- a second one is allowed
SELECT letter.unusers('public.members');
ALTER TABLE users RENAME COLUMN id TO uid;    -- refused while declared
-- a user may delete themselves: the application's own route
SELECT letter.grant_global('delete', 'public.users', 'any_user', if := 'id = letter.user_id()::uuid');
RESET letter.bypass;
INSERT INTO members (user_id) VALUES
    ('a0000000-0000-0000-0000-000000000001'), ('a0000000-0000-0000-0000-000000000002');
INSERT INTO letter.memberships (role, user_id) VALUES
    ('vip', 'a0000000-0000-0000-0000-000000000001'),
    ('vip', 'a0000000-0000-0000-0000-000000000002');
SELECT role, right(user_id, 4) AS who FROM letter.memberships ORDER BY 1, 2;
-- alice deletes herself, as the application would: the trigger forgets
-- her with letter's authority, not hers
SET letter.user_id = 'a0000000-0000-0000-0000-000000000001';
DELETE FROM users WHERE id = 'a0000000-0000-0000-0000-000000000001';
RESET letter.user_id;
SELECT role, right(user_id, 4) AS who FROM letter.memberships ORDER BY 1, 2;
SELECT count(*) AS sources_left FROM letter.membership_sources
    WHERE user_id = 'a0000000-0000-0000-0000-000000000001';
-- an administrator, bypass on, gives bob a new key: the old one is
-- forgotten (the members source row, unchanged, will derive it again on its
-- next write) — bypass does not switch the hygiene off
SET letter.bypass = on;
UPDATE users SET id = 'a0000000-0000-0000-0000-000000000003' WHERE id = 'a0000000-0000-0000-0000-000000000002';
SELECT role, right(user_id, 4) AS who FROM letter.memberships ORDER BY 1, 2;
UPDATE users SET name = 'Robert' WHERE id = 'a0000000-0000-0000-0000-000000000003';   -- the key stayed: nothing happens
INSERT INTO letter.memberships (role, user_id) VALUES ('vip', 'a0000000-0000-0000-0000-000000000003');
DROP TRIGGER letter_users_forget ON users;
SELECT severity, object, message FROM letter.check_health() WHERE object LIKE 'users table%';
SELECT letter.users('public.users');          -- puts it back
SELECT count(*) AS users_triggers FROM pg_trigger WHERE tgname = 'letter_users_forget';
SELECT letter.unusers('public.users');
SELECT letter.unusers('public.users');        -- not declared: an error
SELECT count(*) AS users_triggers FROM pg_trigger WHERE tgname = 'letter_users_forget';
DELETE FROM users WHERE id = 'a0000000-0000-0000-0000-000000000003';   -- undeclared: nothing is forgotten
SELECT role, right(user_id, 4) AS who FROM letter.memberships ORDER BY 1, 2;
DELETE FROM letter.memberships WHERE role = 'vip';
-- a users table that goes: its declaration goes with it
SELECT letter.users('public.members');
DROP TABLE members;
SELECT count(*) AS users_tables FROM letter.user_tables;
-- back, for the sections below
INSERT INTO users VALUES ('a0000000-0000-0000-0000-000000000001', 'Alice'), ('a0000000-0000-0000-0000-000000000002', 'Bob');
SELECT letter.revoke_global('delete', 'public.users', 'any_user');
RESET letter.bypass;

-- ============================================================
-- 8. Hygiene: a role row with an empty user id is refused
--    (it would match sessions with no letter.user_id).
-- ============================================================
INSERT INTO letter.memberships (role, user_id) VALUES ('editor', '');

-- ============================================================
-- 9. DROP EXTENSION … CASCADE takes the assignment machinery with
--    it (18 D5): no letter trigger or function is left on user
--    tables, and writes to a former source table just work.
-- ============================================================
SELECT letter.grant_global('select', 'public.comments', 'editor', ARRAY['body']);
SET letter.bypass = on;
SELECT letter.assign('public.team_members', 'user_id', role := 'member');
RESET letter.bypass;
SELECT count(*) AS letter_triggers FROM pg_trigger WHERE tgname LIKE 'letter\_%';

-- without CASCADE: refused, as for the enforcement triggers
DROP EXTENSION letter;
DROP EXTENSION letter CASCADE;

SELECT count(*) AS letter_triggers FROM pg_trigger WHERE tgname LIKE 'letter\_%';
SELECT count(*) AS letter_functions FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'letter';
SELECT count(*) AS letter_event_triggers FROM pg_event_trigger WHERE evtname LIKE 'letter\_%';
INSERT INTO team_members (user_id, project_id, role)
    VALUES ('a0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 'x');
SELECT count(*) FROM team_members;

\set VERBOSITY default

-- Cleanup (the state view went with the extension)
DROP TABLE team_members, reactions, comments, users CASCADE;
DROP SCHEMA other;

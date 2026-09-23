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
SELECT letter.assign('public.team_members', 'user_id', 'public.projects',
    role_name := NULL, role_column := 'role', if_fn := NULL);
SELECT letter.assign('public.auditors', 'user_id', NULL,
    role_name := 'auditor', role_column := NULL, if_fn := NULL);
RESET letter.bypass;

INSERT INTO team_members (user_id, project_id, role) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 'editor'),
    ('a0000000-0000-0000-0000-000000000002', 'b0000000-0000-0000-0000-000000000002', 'editor');
INSERT INTO auditors (user_id) VALUES ('a0000000-0000-0000-0000-000000000002');

SELECT letter.grant('select', 'public.comments', 'editor', ARRAY['body'],
    'public.projects', ARRAY['task_id'], NULL);
SELECT letter.grant('update', 'public.comments', 'editor', ARRAY['body'],
    'public.projects', ARRAY['task_id'], NULL);
SELECT letter.grant('select', 'public.comments', 'auditor', ARRAY['author'], NULL);
SELECT letter.grant('select', 'public.reactions', 'editor', ARRAY['emoji'],
    'public.projects', ARRAY['comment_id', 'task_id'], NULL);
SELECT letter.grant('select', 'public.tasks', 'editor', ARRAY['title'],
    'public.projects', NULL, NULL);

-- letter's state, as text; OIDs and assignment ids are normalised away so
-- the expected output is stable.
CREATE VIEW state AS
    SELECT 'grant' AS kind, g.on_table::text AS tbl, g.role || '/' || g.privilege || '/' || g.column_name AS detail
    FROM letter.grants g
    UNION ALL
    SELECT 'assignment', a.table_name::text, COALESCE(a.scope_table::text, '-')
    FROM letter.assignments a
    UNION ALL
    SELECT 'role', COALESCE(r.scope_table::text, '-'), r.role || '@' || left(r.user_id, 8)
    FROM letter.roles r
    UNION ALL
    SELECT 'trigger', t.tgrelid::regclass::text, regexp_replace(t.tgname, '_[0-9a-f_]{36}$', '_<id>')
    FROM pg_trigger t WHERE t.tgname LIKE 'letter\_%' AND NOT t.tgisinternal
    UNION ALL
    SELECT 'function', 'letter', regexp_replace(p.proname, '_[0-9a-f_]{36}$', '_<id>')
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'letter' AND p.proname LIKE 'source\_%' OR n.nspname = 'letter' AND p.proname LIKE 'scope\_%';

SELECT * FROM state ORDER BY 1, 2, 3;

\set VERBOSITY terse

-- ============================================================
-- 1. Rename / set schema: protection follows the table.
-- ============================================================
ALTER TABLE comments RENAME TO remarks;
ALTER TABLE remarks SET SCHEMA other;

SELECT tbl, detail FROM state WHERE kind = 'grant' AND tbl LIKE '%remarks' ORDER BY 2;

-- write enforcement still applies under the new name
SET letter.current_user_id = 'a0000000-0000-0000-0000-000000000001';
UPDATE other.remarks SET body = 'edited by alice' WHERE id = 'd0000000-0000-0000-0000-000000000001';
SET letter.current_user_id = 'a0000000-0000-0000-0000-000000000002';
UPDATE other.remarks SET body = 'edited by bob' WHERE id = 'd0000000-0000-0000-0000-000000000001';
RESET letter.current_user_id;
SELECT body FROM other.remarks;

-- and the planner hook still substitutes it (no user id set: zero rows, 17 D2)
SET letter.enforce_reads = on;
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
-- a using_path column
ALTER TABLE comments RENAME COLUMN task_id TO task;
-- an assignment's user column
ALTER TABLE team_members RENAME COLUMN user_id TO member_id;
-- an FK on a path (explicit hop, then inferred final hop)
ALTER TABLE comments DROP CONSTRAINT comments_task_id_fkey;
ALTER TABLE tasks DROP CONSTRAINT tasks_project_id_fkey;
-- a second FK that makes an inferred final hop ambiguous
ALTER TABLE tasks ADD COLUMN alt_project uuid REFERENCES projects(id);
-- a composite PK on a hop table
ALTER TABLE tasks DROP CONSTRAINT tasks_pkey CASCADE, ADD PRIMARY KEY (id, project_id);
-- an assignment's scope FK
ALTER TABLE team_members DROP CONSTRAINT team_members_project_id_fkey;

-- nothing changed
SELECT attname FROM pg_attribute WHERE attrelid = 'comments'::regclass AND attnum > 0 ORDER BY attnum;
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
-- 3. TRUNCATE on a protected table requires bypass (18 D3).
-- ============================================================
TRUNCATE reactions;
SET letter.bypass = on;
TRUNCATE reactions;
RESET letter.bypass;
SELECT count(*) FROM reactions;

-- ============================================================
-- 4. Dropping a column removes the grants on it; dropping a
--    using_path column removes the grants through it.
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
SELECT letter.grant('select', 'public.team_members', 'editor', ARRAY['role'],
    'public.projects', NULL, NULL);
DROP TABLE projects CASCADE;
SELECT * FROM state ORDER BY 1, 2, 3;

-- ============================================================
-- 7b. letter.forget_user(): every role a user holds goes — the
--     assignment-derived ones with their assignment records, and the
--     directly-managed ones — and nobody else's.
-- ============================================================
SET letter.bypass = on;
CREATE TABLE members (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL);
SELECT letter.assign('public.members', 'user_id', NULL, role_name := 'member');
SET letter.bypass = off;
INSERT INTO members (user_id) VALUES
    ('a0000000-0000-0000-0000-000000000001'), ('a0000000-0000-0000-0000-000000000002');
INSERT INTO letter.roles (role, user_id) VALUES
    ('vip', 'a0000000-0000-0000-0000-000000000001'),
    ('vip', 'a0000000-0000-0000-0000-000000000002');
SELECT role, right(user_id, 4) AS who FROM letter.roles ORDER BY 1, 2;
SELECT letter.forget_user('a0000000-0000-0000-0000-000000000001') AS forgotten;
SELECT role, right(user_id, 4) AS who FROM letter.roles ORDER BY 1, 2;
SELECT count(*) AS assignment_records_left FROM letter.role_assignments
    WHERE user_id = 'a0000000-0000-0000-0000-000000000001';
SELECT letter.forget_user('nobody') AS forgotten;
DROP TABLE members;

-- ============================================================
-- 8. Hygiene: a role row with an empty user id is refused
--    (it would match sessions with no letter.current_user_id).
-- ============================================================
INSERT INTO letter.roles (role, user_id) VALUES ('editor', '');

-- ============================================================
-- 9. DROP EXTENSION … CASCADE takes the assignment machinery with
--    it (18 D5): no letter trigger or function is left on user
--    tables, and writes to a former source table just work.
-- ============================================================
SELECT letter.grant('select', 'public.comments', 'editor', ARRAY['body'], NULL);
SET letter.bypass = on;
SELECT letter.assign('public.team_members', 'user_id', NULL,
    role_name := 'member', role_column := NULL, if_fn := NULL);
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

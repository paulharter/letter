-- Test: write-path redaction of the result relation
-- (plan/19-write-path-redaction.md W2, decisions D1–D5)
--
-- The table a statement writes to stays a real relation, so it gets a
-- security qual (rows the user cannot see are not there — skipped, not
-- refused) and its hidden columns read as NULL in the qual, SET, RETURNING
-- and ON CONFLICT. Triggers still decide writability of the rows that are
-- there.
--
-- Users:  alice  editor@Alpha (sees everything of Alpha), viewer@Beta (name only)
--         bob    viewer@Alpha
-- Grants: projects  select editor * / viewer name; update editor name,status; delete editor
--         notes     select editor body (extra hidden even from editors);
--                   update/insert/delete editor

CREATE EXTENSION letter;
SET letter.bypass = on;

CREATE TABLE users (id uuid PRIMARY KEY, name TEXT);
CREATE TABLE projects (
    id uuid PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    secret TEXT
);
CREATE TABLE notes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid NOT NULL REFERENCES projects(id),
    body TEXT,
    extra TEXT
);
CREATE INDEX ON notes (project_id);
CREATE TABLE team_members (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id),
    project_id uuid NOT NULL REFERENCES projects(id),
    role TEXT NOT NULL
);

INSERT INTO users VALUES
    ('a0000000-0000-0000-0000-000000000001', 'Alice'),
    ('a0000000-0000-0000-0000-000000000002', 'Bob');
INSERT INTO projects VALUES
    ('b0000000-0000-0000-0000-000000000001', 'Alpha', 'active', 's1'),
    ('b0000000-0000-0000-0000-000000000002', 'Beta',  'draft',  's2'),
    ('b0000000-0000-0000-0000-000000000003', 'Gamma', 'done',   's3');
INSERT INTO notes (id, project_id, body, extra) VALUES
    ('c0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 'n1', 'x1'),
    ('c0000000-0000-0000-0000-000000000002', 'b0000000-0000-0000-0000-000000000002', 'n2', 'x2'),
    ('c0000000-0000-0000-0000-000000000003', 'b0000000-0000-0000-0000-000000000003', 'n3', 'x3');

SELECT letter.assign('public.team_members', 'user_id', role_column := 'role', scope := 'public.projects');
INSERT INTO team_members (user_id, project_id, role) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 'editor'),
    ('a0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000002', 'viewer'),
    ('a0000000-0000-0000-0000-000000000002', 'b0000000-0000-0000-0000-000000000001', 'viewer');

SELECT letter.grant_scoped('select', 'public.projects', 'editor', ARRAY['*'], 'public.projects');
SELECT letter.grant_scoped('select', 'public.projects', 'viewer', ARRAY['name'], 'public.projects');
SELECT letter.grant_scoped('update', 'public.projects', 'editor', ARRAY['name', 'status'], 'public.projects');
SELECT letter.grant_scoped('delete', 'public.projects', 'editor', ARRAY['*'], 'public.projects');
SELECT letter.grant_scoped('select', 'public.notes', 'editor', ARRAY['body'], 'public.projects');
SELECT letter.grant_scoped('update', 'public.notes', 'editor', ARRAY['body', 'extra'], 'public.projects');
SELECT letter.grant_scoped('insert', 'public.notes', 'editor', ARRAY['*'], 'public.projects');
SELECT letter.grant_scoped('delete', 'public.notes', 'editor', ARRAY['*'], 'public.projects');

CREATE FUNCTION truth() RETURNS TABLE (tbl text, id uuid, a text, b text) LANGUAGE plpgsql AS $$
BEGIN
    RETURN QUERY SELECT 'projects', p.id, p.name, p.status FROM projects p ORDER BY p.name;
    RETURN QUERY SELECT 'notes', n.id, n.body, n.extra FROM notes n ORDER BY n.body;
END $$ SET letter.bypass = on;

SET letter.bypass = off;
SET letter.enforce_reads = on;
SET letter.user_id = 'a0000000-0000-0000-0000-000000000001';
\set VERBOSITY terse

-- ============================================================
-- 1. The qual cannot see hidden columns: Beta's secret is hidden
--    from alice (viewer there), Gamma is invisible. No error, no
--    row count that says otherwise.
-- ============================================================
SET client_min_messages = debug1;
WITH u AS (UPDATE projects SET name = name WHERE secret = 's2' RETURNING 1) SELECT count(*) AS beta_by_secret FROM u;
RESET client_min_messages;
WITH u AS (UPDATE projects SET name = name WHERE secret = 's3' RETURNING 1) SELECT count(*) AS gamma_by_secret FROM u;
WITH u AS (UPDATE projects SET name = name WHERE secret = 's1' RETURNING 1) SELECT count(*) AS alpha_by_secret FROM u;
WITH d AS (DELETE FROM projects WHERE secret = 's2' RETURNING 1) SELECT count(*) AS beta_deleted FROM d;
SELECT * FROM truth() WHERE tbl = 'projects';

-- ============================================================
-- 2. Invisible rows are skipped (D1); visible but unwritable rows
--    still error from the trigger.
-- ============================================================
WITH u AS (UPDATE projects SET name = 'x' WHERE id = 'b0000000-0000-0000-0000-000000000003' RETURNING 1) SELECT count(*) AS gamma_updated FROM u;
WITH d AS (DELETE FROM projects WHERE id = 'b0000000-0000-0000-0000-000000000003' RETURNING 1) SELECT count(*) AS gamma_deleted FROM d;
UPDATE projects SET name = 'x' WHERE id = 'b0000000-0000-0000-0000-000000000002';
-- parity: an unqualified UPDATE touches exactly the rows SELECT shows
SELECT count(*) AS visible FROM notes;
WITH u AS (UPDATE notes SET body = body RETURNING 1) SELECT count(*) AS updated FROM u;
-- (on projects alice can see Beta but may not write it: the unqualified
-- UPDATE reaches Beta and the trigger refuses — loud, as writability is)
SELECT count(*) AS visible FROM projects;
WITH u AS (UPDATE projects SET status = status RETURNING 1) SELECT count(*) AS updated FROM u;
SELECT * FROM truth() WHERE tbl = 'projects';

-- ============================================================
-- 3. SET reads a hidden column: NULL is written (D2).
-- ============================================================
UPDATE notes SET body = extra WHERE id = 'c0000000-0000-0000-0000-000000000001';
SELECT * FROM truth() WHERE tbl = 'notes';
UPDATE notes SET body = 'n1' WHERE id = 'c0000000-0000-0000-0000-000000000001';

-- ============================================================
-- 4. RETURNING is redacted, on UPDATE, DELETE and INSERT (D4).
-- ============================================================
UPDATE notes SET body = 'n1!' WHERE id = 'c0000000-0000-0000-0000-000000000001'
    RETURNING body, extra, extra IS NULL AS extra_hidden;
INSERT INTO notes (project_id, body, extra)
    VALUES ('b0000000-0000-0000-0000-000000000001', 'new', 'x-new')
    RETURNING body, extra;
DELETE FROM notes WHERE body = 'new' RETURNING body, extra;
SELECT * FROM truth() WHERE tbl = 'notes';
-- and the value really was stored
SET letter.bypass = on;
SELECT extra FROM notes WHERE id = 'c0000000-0000-0000-0000-000000000001';
SET letter.bypass = off;

-- ============================================================
-- 5. ON CONFLICT: the WHERE cannot see hidden columns, SET cannot
--    read them.
-- ============================================================
INSERT INTO notes (id, project_id, body)
    VALUES ('c0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 'dup')
    ON CONFLICT (id) DO UPDATE SET body = EXCLUDED.body WHERE notes.extra = 'x1';
INSERT INTO notes (id, project_id, body)
    VALUES ('c0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 'dup')
    ON CONFLICT (id) DO UPDATE SET body = notes.extra
    RETURNING body;
SELECT * FROM truth() WHERE tbl = 'notes';
UPDATE notes SET body = 'n1' WHERE id = 'c0000000-0000-0000-0000-000000000001';

-- ============================================================
-- 6. UPDATE … FROM a protected table, and a sublink back to the
--    result relation. notes.project_id is the grant's path column
--    (visible, 17 D16) so the join finds alice's note; extra is
--    hidden, so the sublink on it finds nothing.
-- ============================================================
WITH u AS (UPDATE notes SET body = p.name FROM projects p WHERE p.id = notes.project_id RETURNING 1) SELECT count(*) AS updated FROM u;
WITH u AS (UPDATE notes SET body = body || '?' WHERE EXISTS (SELECT 1 FROM projects p WHERE p.secret = notes.extra) RETURNING 1) SELECT count(*) AS updated FROM u;
SELECT * FROM truth() WHERE tbl = 'notes';

-- ============================================================
-- 7. Whole-row references to the result relation are refused (D3).
-- ============================================================
UPDATE notes SET body = body RETURNING notes;
UPDATE notes SET body = body RETURNING row_to_json(notes);

-- ============================================================
-- 8. One prepared statement, two users.
-- ============================================================
PREPARE u AS UPDATE notes SET body = body RETURNING body, extra;
EXECUTE u;
SET letter.user_id = 'a0000000-0000-0000-0000-000000000002';
EXECUTE u;
DEALLOCATE u;

-- ============================================================
-- 9. A select-grant if in the write path (plan/20 §3): tickets are
--    visible to editors while open. A closed ticket is not there for
--    UPDATE or DELETE; closing one is the last thing an editor does to it.
-- ============================================================
SET letter.bypass = on;
CREATE TABLE tickets (
    id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(id),
    title TEXT,
    state TEXT
);
CREATE INDEX ON tickets (project_id);
INSERT INTO tickets VALUES
    ('e0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 't1', 'open'),
    ('e0000000-0000-0000-0000-000000000002', 'b0000000-0000-0000-0000-000000000001', 't2', 'closed');
SELECT letter.grant_scoped('select', 'public.tickets', 'editor', ARRAY['*'], 'public.projects', if := 'state = ''open''');
SELECT letter.grant_scoped('update', 'public.tickets', 'editor', ARRAY['title', 'state'], 'public.projects');
SELECT letter.grant_scoped('delete', 'public.tickets', 'editor', ARRAY['*'], 'public.projects');
SET letter.bypass = off;
SET letter.user_id = 'a0000000-0000-0000-0000-000000000001';
SELECT title, state FROM tickets ORDER BY title;
UPDATE tickets SET title = title || '!' RETURNING title;                 -- t2 is not there
DELETE FROM tickets WHERE state = 'closed';                              -- nothing to delete
UPDATE tickets SET state = 'closed' WHERE title = 't1!' RETURNING title, state;   -- allowed; the row returned is already hidden
UPDATE tickets SET title = 'again' RETURNING title;
SET letter.bypass = on;
SELECT title, state FROM tickets ORDER BY title;
DROP TABLE tickets;
SET letter.bypass = off;

\set VERBOSITY default
-- Cleanup
RESET letter.user_id;
RESET letter.enforce_reads;
DROP FUNCTION truth();
DROP TABLE team_members, notes, projects, users CASCADE;
DROP EXTENSION letter CASCADE;

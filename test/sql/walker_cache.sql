-- Test: compiled scope paths and the statement-local memo
-- (plan/16-scope-resolution-direction.md §6)
--
-- The path-walker compiles each (table, scope, using_path) once per
-- backend, keeps saved plans for its hop fetches, and memoises
-- resolved chains within a statement. None of that may change what
-- is enforced. Semantics under test:
--   1. A bulk write through a two-hop path is checked per row: rows
--      in the user's scope pass, one out-of-scope row fails the
--      whole statement.
--   2. The memo is statement-local: re-parenting an intermediate row
--      between two statements of one transaction is seen by the
--      second statement.
--   3. An error inside a savepoint leaves the walker usable after
--      ROLLBACK TO.
--   4. Compiled paths are invalidated by DDL: dropping an FK on the
--      path fails loudly at enforcement time (never enforces as
--      unscoped); restoring it restores enforcement.

CREATE EXTENSION letter;

CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL
);

CREATE TABLE projects (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL
);

CREATE TABLE tasks (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid NOT NULL REFERENCES projects(id),
    title TEXT NOT NULL
);

CREATE TABLE comments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id uuid REFERENCES tasks(id),
    body TEXT NOT NULL
);

CREATE TABLE reactions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    comment_id uuid NOT NULL CONSTRAINT reactions_comment_fk REFERENCES comments(id),
    emoji TEXT NOT NULL
);

CREATE TABLE team_members (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    role TEXT NOT NULL
);

INSERT INTO users (id, name) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'Alice');

INSERT INTO projects (id, name) VALUES
    ('b0000000-0000-0000-0000-000000000001', 'Alpha'),
    ('b0000000-0000-0000-0000-000000000002', 'Beta');

INSERT INTO tasks (id, project_id, title) VALUES
    ('d0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 'Alpha task'),
    ('d0000000-0000-0000-0000-000000000002', 'b0000000-0000-0000-0000-000000000002', 'Beta task');

INSERT INTO comments (id, task_id, body) VALUES
    ('e0000000-0000-0000-0000-000000000001', 'd0000000-0000-0000-0000-000000000001', 'alpha comment 1'),
    ('e0000000-0000-0000-0000-000000000002', 'd0000000-0000-0000-0000-000000000001', 'alpha comment 2'),
    ('e0000000-0000-0000-0000-000000000003', 'd0000000-0000-0000-0000-000000000002', 'beta comment');

-- Alice is editor on Alpha only.
SELECT letter.assign('public.team_members', 'user_id', 'public.projects',
    role_name := NULL, role_column := 'role', if_fn := NULL);

INSERT INTO team_members (user_id, project_id, role) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 'editor');

-- Two grants sharing one two-hop path (they share a compiled path and memo).
SELECT letter.grant('insert', 'public.reactions', 'editor', ARRAY['*'],
    'public.projects', ARRAY['comment_id', 'task_id'], NULL);
SELECT letter.grant('select', 'public.reactions', 'editor', ARRAY['emoji'],
    'public.projects', ARRAY['comment_id', 'task_id'], NULL);

SET letter.current_user_id = 'a0000000-0000-0000-0000-000000000001';
\set VERBOSITY terse

-- ============================================================
-- Test 1a: bulk insert, 200 rows over the two Alpha comments —
-- every row resolves to Alpha, all pass.
-- ============================================================
INSERT INTO reactions (comment_id, emoji)
SELECT CASE WHEN g % 2 = 0 THEN 'e0000000-0000-0000-0000-000000000001'::uuid
            ELSE 'e0000000-0000-0000-0000-000000000002'::uuid END,
       'bulk-' || g
FROM generate_series(1, 200) g;

SELECT count(*) FROM reactions;

-- ============================================================
-- Test 1b: the same bulk insert with one Beta row in the middle —
-- a memoised "allowed" for Alpha must not leak to the Beta row.
-- The whole statement fails.
-- ============================================================
INSERT INTO reactions (comment_id, emoji)
SELECT CASE WHEN g = 150 THEN 'e0000000-0000-0000-0000-000000000003'::uuid
            ELSE 'e0000000-0000-0000-0000-000000000001'::uuid END,
       'mixed-' || g
FROM generate_series(1, 200) g;

SELECT count(*) FROM reactions;

-- Read path shares the walker: all 200 visible.
SELECT count(*) FROM letter.read('public.reactions') t(row_data);

-- ============================================================
-- Test 2: the memo does not outlive its statement. Inside one
-- transaction: insert on the Beta comment is denied; the Beta task
-- is re-parented to Alpha (tasks has no grants, so no enforcement);
-- the next statement must see the new scope and allow it; after
-- moving it back, denied again.
-- ============================================================
BEGIN;
SAVEPOINT s1;
INSERT INTO reactions (comment_id, emoji)
    VALUES ('e0000000-0000-0000-0000-000000000003', 'before-move');
ROLLBACK TO s1;

UPDATE tasks SET project_id = 'b0000000-0000-0000-0000-000000000001'
    WHERE id = 'd0000000-0000-0000-0000-000000000002';
INSERT INTO reactions (comment_id, emoji)
    VALUES ('e0000000-0000-0000-0000-000000000003', 'after-move');

UPDATE tasks SET project_id = 'b0000000-0000-0000-0000-000000000002'
    WHERE id = 'd0000000-0000-0000-0000-000000000002';
SAVEPOINT s2;
INSERT INTO reactions (comment_id, emoji)
    VALUES ('e0000000-0000-0000-0000-000000000003', 'after-move-back');
ROLLBACK TO s2;

-- ============================================================
-- Test 3: still usable after the rolled-back savepoints.
-- ============================================================
INSERT INTO reactions (comment_id, emoji)
    VALUES ('e0000000-0000-0000-0000-000000000001', 'after-savepoints');
COMMIT;

SELECT emoji FROM reactions WHERE emoji LIKE '%move%' OR emoji LIKE 'after-%' ORDER BY emoji;

-- ============================================================
-- Test 4: DDL invalidates the compiled path. With the first hop's
-- FK dropped the path cannot be resolved: fail loudly, even for a
-- row that was allowed a moment ago.
-- ============================================================
ALTER TABLE reactions DROP CONSTRAINT reactions_comment_fk;

INSERT INTO reactions (comment_id, emoji)
    VALUES ('e0000000-0000-0000-0000-000000000001', 'fk-dropped');

-- Restored: enforcement works again, in scope and out of scope.
ALTER TABLE reactions ADD CONSTRAINT reactions_comment_fk
    FOREIGN KEY (comment_id) REFERENCES comments(id);

INSERT INTO reactions (comment_id, emoji)
    VALUES ('e0000000-0000-0000-0000-000000000001', 'fk-restored');
INSERT INTO reactions (comment_id, emoji)
    VALUES ('e0000000-0000-0000-0000-000000000003', 'fk-restored-beta');

SELECT count(*) FROM reactions WHERE emoji LIKE 'fk-%';
\set VERBOSITY default

-- Cleanup
DROP TABLE team_members CASCADE;
DROP TABLE reactions CASCADE;
DROP TABLE comments CASCADE;
DROP TABLE tasks CASCADE;
DROP TABLE projects CASCADE;
DROP TABLE users CASCADE;
DROP EXTENSION letter CASCADE;

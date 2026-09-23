-- Test: multi-hop scope resolution (the shared path-walker)
--
-- Semantics under test:
--   1. One-hop via: grants on comments scoped to projects via
--      tasks resolve per row by walking the FK chain.
--   2. Explicit final hop: a via that lands on the scope table
--      itself behaves identically to the inferred final hop.
--   3. Two-hop path with an inferred final hop.
--   4. NULL along the chain denies — the grant does not apply to the
--      row. It never enforces as unscoped (the old fail-open bug).
--   5. Fail-loud grant-time validation: ambiguous final hop, no FK
--      path to the scope, via on an unscoped grant.

CREATE EXTENSION letter;
SET letter.enforce_reads = off;   -- this test is not about the read hook

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
    comment_id uuid NOT NULL REFERENCES comments(id),
    emoji TEXT NOT NULL
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
    ('b0000000-0000-0000-0000-000000000001', 'Alpha'),
    ('b0000000-0000-0000-0000-000000000002', 'Beta');

INSERT INTO tasks (id, project_id, title) VALUES
    ('d0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 'Alpha task'),
    ('d0000000-0000-0000-0000-000000000002', 'b0000000-0000-0000-0000-000000000002', 'Beta task');

INSERT INTO comments (id, task_id, body) VALUES
    ('e0000000-0000-0000-0000-000000000001', 'd0000000-0000-0000-0000-000000000001', 'alpha comment'),
    ('e0000000-0000-0000-0000-000000000002', 'd0000000-0000-0000-0000-000000000002', 'beta comment'),
    ('e0000000-0000-0000-0000-000000000003', NULL,                                    'orphan comment');

INSERT INTO reactions (id, comment_id, emoji) VALUES
    ('f0000000-0000-0000-0000-000000000001', 'e0000000-0000-0000-0000-000000000001', 'thumbsup'),
    ('f0000000-0000-0000-0000-000000000002', 'e0000000-0000-0000-0000-000000000003', 'wave');

-- Roles: Alice is editor on Alpha, Bob is editor on Beta.
SET letter.bypass = on;
SELECT letter.assign('public.team_members', 'user_id', role_column := 'role', scope := 'public.projects');
RESET letter.bypass;

INSERT INTO team_members (user_id, project_id, role) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 'editor'),
    ('a0000000-0000-0000-0000-000000000002', 'b0000000-0000-0000-0000-000000000002', 'editor');

-- One-hop grants on comments, scoped to projects via tasks.
SELECT letter.grant_scoped('select', 'public.comments', 'editor', ARRAY['body'], 'public.projects', ARRAY['task_id']);
SELECT letter.grant_scoped('update', 'public.comments', 'editor', ARRAY['body'], 'public.projects', ARRAY['task_id']);

-- Two-hop grant on reactions with an inferred final hop
-- (reactions.comment_id -> comments.task_id -> tasks, then tasks.project_id inferred).
SELECT letter.grant_scoped('select', 'public.reactions', 'editor', ARRAY['emoji'], 'public.projects', ARRAY['comment_id', 'task_id']);

-- ============================================================
-- Test 1: one-hop read — Alice sees only the Alpha comment.
-- The orphan comment (NULL task_id) is excluded, not treated
-- as unscoped. body is visible, task_id redacted (PK always visible).
-- ============================================================
SET letter.user_id = 'a0000000-0000-0000-0000-000000000001';

SELECT * FROM letter._read('public.comments') t(row_data)
    ORDER BY row_data->>'body';

-- ============================================================
-- Test 2: one-hop read — Bob sees only the Beta comment.
-- ============================================================
SET letter.user_id = 'a0000000-0000-0000-0000-000000000002';

SELECT * FROM letter._read('public.comments') t(row_data)
    ORDER BY row_data->>'body';

-- ============================================================
-- Test 3: two-hop read — Alice sees the reaction on the Alpha
-- comment. The reaction on the orphan comment is excluded
-- (NULL at the second hop).
-- ============================================================
SET letter.user_id = 'a0000000-0000-0000-0000-000000000001';

SELECT * FROM letter._read('public.reactions') t(row_data)
    ORDER BY row_data->>'emoji';

-- ============================================================
-- Test 4: one-hop write — Alice can update the Alpha comment...
-- ============================================================
UPDATE comments SET body = 'alpha comment v2'
    WHERE id = 'e0000000-0000-0000-0000-000000000001';

SELECT body FROM comments WHERE id = 'e0000000-0000-0000-0000-000000000001';

-- ============================================================
-- Test 5: ...but not the Beta comment (wrong scope)...
-- ============================================================
\set VERBOSITY terse
UPDATE comments SET body = 'hacked'
    WHERE id = 'e0000000-0000-0000-0000-000000000002';

-- ============================================================
-- Test 6: ...and not the orphan comment (NULL along the chain
-- denies; it must not enforce as unscoped).
-- ============================================================
UPDATE comments SET body = 'hacked'
    WHERE id = 'e0000000-0000-0000-0000-000000000003';
\set VERBOSITY default

-- ============================================================
-- Test 7: explicit final hop — a path that lands on the scope
-- table itself behaves identically to the inferred final hop.
-- ============================================================
SELECT letter.grant_scoped('select', 'public.comments', 'editor', ARRAY['body'], 'public.projects', ARRAY['task_id', 'project_id']);

SELECT * FROM letter._read('public.comments') t(row_data)
    ORDER BY row_data->>'body';

-- ============================================================
-- Test 8: grant-time fail-loud — two FKs to the scope table
-- make the final hop ambiguous.
-- ============================================================
CREATE TABLE links (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    src_project uuid REFERENCES projects(id),
    dst_project uuid REFERENCES projects(id),
    label TEXT
);

\set VERBOSITY terse
SELECT letter.grant_scoped('select', 'public.links', 'editor', ARRAY['label'], 'public.projects');
\set VERBOSITY default

-- Naming the final hop column resolves the ambiguity.
SELECT letter.grant_scoped('select', 'public.links', 'editor', ARRAY['label'], 'public.projects', ARRAY['src_project']);

-- ============================================================
-- Test 9: grant-time fail-loud — no FK path to the scope table.
-- ============================================================
CREATE TABLE isolated (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    note TEXT
);

\set VERBOSITY terse
SELECT letter.grant_scoped('select', 'public.isolated', 'editor', ARRAY['note'], 'public.projects');

-- ============================================================
-- Test 10: grant-time fail-loud — a scoped grant with no scope. (An
-- unscoped grant with a via is no longer expressible: grant_global has
-- no via parameter.)
-- ============================================================
SELECT letter.grant_scoped('select', 'public.comments', 'editor', ARRAY['body'],
    NULL, ARRAY['task_id']);
\set VERBOSITY default

-- Clean up
RESET letter.user_id;
SET letter.bypass = true;
DROP TABLE isolated;
DROP TABLE links CASCADE;
DROP TABLE team_members CASCADE;
DROP TABLE reactions CASCADE;
DROP TABLE comments CASCADE;
DROP TABLE tasks CASCADE;
DROP TABLE projects CASCADE;
DROP TABLE users CASCADE;
DROP EXTENSION letter CASCADE;

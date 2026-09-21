-- Test: grant-time warning for unindexed scope path columns
-- (plan/16-scope-resolution-direction.md §3.4)
--
-- Reads are driven from the user's scopes down the FK chain, which
-- needs an index on each referencing FK column. Semantics under test:
--   1. A select grant whose path columns are unindexed warns once per
--      column (hops and the inferred final hop) — and still succeeds.
--   2. Non-select grants do not warn: the write path never needs it.
--   3. Once the indexes exist, no warning. A multi-column index counts
--      only if the path column leads it; partial indexes do not count.
--   4. Unscoped grants and table-is-scope grants never warn.

CREATE EXTENSION letter;

CREATE TABLE projects (id uuid PRIMARY KEY, name TEXT);
CREATE TABLE tasks (
    id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(id),
    title TEXT
);
CREATE TABLE comments (
    id uuid PRIMARY KEY,
    task_id uuid REFERENCES tasks(id),
    body TEXT
);

-- 1. Both the declared hop (comments.task_id) and the inferred final
--    hop (tasks.project_id) are unindexed.
SELECT letter.grant('select', 'public.comments', 'editor', ARRAY['body'],
    'public.projects', ARRAY['task_id'], NULL);
SELECT count(*) FROM letter.grants;

-- Direct-FK scope: only the inferred final hop.
SELECT letter.grant('select', 'public.tasks', 'editor', ARRAY['title'],
    'public.projects', NULL, NULL);

-- 2. Same path, update privilege: no warning.
SELECT letter.grant('update', 'public.comments', 'editor', ARRAY['body'],
    'public.projects', ARRAY['task_id'], NULL);

-- 3. Indexes that do not count: path column not leading, and partial.
CREATE INDEX comments_body_task ON comments (body, task_id);
CREATE INDEX tasks_project_partial ON tasks (project_id) WHERE title IS NOT NULL;
SELECT letter.grant('select', 'public.comments', 'viewer', ARRAY['body'],
    'public.projects', ARRAY['task_id'], NULL);

--    Indexes that do: leading column of a multi-column index, and a plain one.
CREATE INDEX comments_task_body ON comments (task_id, body);
CREATE INDEX tasks_project ON tasks (project_id);
SELECT letter.grant('select', 'public.comments', 'reader', ARRAY['body'],
    'public.projects', ARRAY['task_id'], NULL);

-- 4. Unscoped, and table-is-scope: nothing to index.
SELECT letter.grant('select', 'public.comments', 'admin', ARRAY['*'], '', NULL, NULL);
SELECT letter.grant('select', 'public.projects', 'editor', ARRAY['name'],
    'public.projects', NULL, NULL);

-- Cleanup
DROP TABLE comments CASCADE;
DROP TABLE tasks CASCADE;
DROP TABLE projects CASCADE;
DROP EXTENSION letter CASCADE;

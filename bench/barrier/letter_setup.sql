-- bench/barrier/letter_setup.sql — the same data under letter itself
-- (plan/17 H5.9, plan/19 W3). Run after setup.sql:
--   psql -d letter_bench -f bench/barrier/letter_setup.sql
-- Models the grants views.sql hand-wrote: editor → body, viewer → author,
-- scoped to lx.projects via {task_id}; admin (root) reads everything unscoped.
DROP EXTENSION IF EXISTS letter CASCADE;
CREATE EXTENSION letter;
SET letter.bypass = on;
SET letter.enforce_reads = off;

INSERT INTO letter.memberships (role, user_id, scope_table, scope_id)
SELECT role, user_id,
       CASE WHEN scope_table IS NULL THEN NULL ELSE 'lx.projects'::regclass END,
       scope_id
FROM lx.roles;

SELECT letter.grant_scoped('select', 'lx.comments', 'editor', ARRAY['body'],   'lx.projects', ARRAY['task_id']);
SELECT letter.grant_scoped('select', 'lx.comments', 'viewer', ARRAY['author'], 'lx.projects', ARRAY['task_id']);
SELECT letter.grant_global('select', 'lx.comments', 'admin', ARRAY['*']);
-- for the joined case (Q4): the scope parent and the hop, readable by editors
SELECT letter.grant_scoped('select', 'lx.tasks',    'editor', ARRAY['title'], 'lx.projects');
SELECT letter.grant_scoped('select', 'lx.projects', 'editor', ARRAY['name'],  'lx.projects');
-- for the write path (W3)
SELECT letter.grant_scoped('update', 'lx.comments', 'editor', ARRAY['body'],   'lx.projects', ARRAY['task_id']);

VACUUM ANALYZE lx.projects, lx.tasks, lx.comments, lx.roles, letter.memberships, letter.grants;
SELECT count(*) AS memberships FROM letter.memberships;
SELECT letter.read_policy('lx.comments');

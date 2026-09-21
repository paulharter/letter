-- bench/walker/bench.sql — path-walker micro-benchmark (checklist 2.7.4).
-- 10k-row bulk insert and a 10k-row letter.read() through a two-hop path
-- (reactions -> comments -> tasks -> projects, final hop inferred).
--
--   createdb letter_walker_bench
--   psql -d letter_walker_bench -f bench/walker/bench.sql
\set QUIET on
DROP EXTENSION IF EXISTS letter CASCADE;
DROP TABLE IF EXISTS reactions, comments, tasks, projects CASCADE;
CREATE EXTENSION letter;

CREATE TABLE projects  (id bigint PRIMARY KEY, name text NOT NULL);
CREATE TABLE tasks     (id bigint PRIMARY KEY, project_id bigint NOT NULL REFERENCES projects(id));
CREATE TABLE comments  (id bigint PRIMARY KEY, task_id bigint REFERENCES tasks(id));
CREATE TABLE reactions (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                        comment_id bigint NOT NULL REFERENCES comments(id), emoji text NOT NULL);

INSERT INTO projects SELECT g, 'p' || g FROM generate_series(1, 10) g;
INSERT INTO tasks    SELECT g, ((g - 1) % 10) + 1 FROM generate_series(1, 100) g;
INSERT INTO comments SELECT g, ((g - 1) % 100) + 1 FROM generate_series(1, 1000) g;

INSERT INTO letter.roles (role, user_id, scope_table, scope_id)
SELECT 'editor', 'alice', 'public.projects', g::text FROM generate_series(1, 10) g;

SELECT letter.grant('insert', 'public.reactions', 'editor', ARRAY['*'],
    'public.projects', ARRAY['comment_id', 'task_id'], NULL);
SELECT letter.grant('select', 'public.reactions', 'editor', ARRAY['emoji'],
    'public.projects', ARRAY['comment_id', 'task_id'], NULL);

SET letter.current_user_id = 'alice';
\set QUIET off
\timing on
\echo == bulk insert: 10k rows over 1000 comments
INSERT INTO reactions (comment_id, emoji) SELECT ((g - 1) % 1000) + 1, 'e' FROM generate_series(1, 10000) g;
\echo == bulk insert: 10k rows over 10 comments
INSERT INTO reactions (comment_id, emoji) SELECT ((g - 1) % 10) + 1, 'e' FROM generate_series(1, 10000) g;
\echo == letter.read: 20k rows
SELECT count(*) FROM letter.read('public.reactions') t(row_data);
\echo == single-row inserts x 3 (one statement each)
INSERT INTO reactions (comment_id, emoji) VALUES (1, 's');
INSERT INTO reactions (comment_id, emoji) VALUES (2, 's');
INSERT INTO reactions (comment_id, emoji) VALUES (3, 's');

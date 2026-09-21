-- bench/barrier/setup.sql — data for the plan/16 §8 Q1 experiment.
--
-- A 2-hop chain   comments -> tasks -> projects   with ~1M leaf rows, and a
-- stand-in for letter.roles with the same column types as the real table
-- (scope_id is VARCHAR, so the generated predicate must cast the role side).
--
--   createdb letter_bench && psql -d letter_bench -f bench/barrier/setup.sql

DROP SCHEMA IF EXISTS lx CASCADE;
CREATE SCHEMA lx;
SET search_path = lx;

CREATE TABLE projects (
    id   bigint PRIMARY KEY,
    name text NOT NULL
);

CREATE TABLE tasks (
    id         bigint PRIMARY KEY,
    project_id bigint NOT NULL REFERENCES projects(id),
    title      text NOT NULL
);

CREATE TABLE comments (
    id      bigint PRIMARY KEY,
    task_id bigint REFERENCES tasks(id),          -- nullable: NULL chain must deny (D4)
    body    text NOT NULL,
    author  text NOT NULL
);

-- Same shape as letter.roles
CREATE TABLE roles (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    role        varchar(64)  NOT NULL,
    user_id     varchar(256) NOT NULL,
    scope_table varchar(64),
    scope_id    varchar(256)
);
CREATE INDEX ON roles (user_id);
CREATE INDEX ON roles (role);

-- 10k projects, 100k tasks (10 per project), 1M comments (10 per task)
INSERT INTO projects SELECT g, 'project ' || g FROM generate_series(1, 10000) g;
INSERT INTO tasks    SELECT g, ((g - 1) / 10) + 1, 'task ' || g FROM generate_series(1, 100000) g;
INSERT INTO comments
SELECT g,
       CASE WHEN g % 1000 = 0 THEN NULL ELSE ((g - 1) / 10) + 1 END,   -- 0.1% orphaned
       'body ' || g, 'author ' || (g % 5000)
FROM generate_series(1, 1000000) g;

-- The referencing-side FK indexes (plan/16 §3.4). run.sql drops and recreates
-- these to show what happens without them.
CREATE INDEX tasks_project_id_idx ON tasks (project_id);
CREATE INDEX comments_task_id_idx ON comments (task_id);

-- Background population: 20k users, each editor or viewer on 5 random projects.
INSERT INTO roles (role, user_id, scope_table, scope_id)
SELECT CASE WHEN random() < 0.5 THEN 'editor' ELSE 'viewer' END,
       'user-' || u, 'lx.projects', (1 + floor(random() * 10000))::bigint::text
FROM generate_series(1, 20000) u, generate_series(1, 5);

-- alice: editor on 3 projects, viewer on 5 (one overlapping) -> 7 distinct
-- projects -> 70 tasks -> ~700 comments out of 1M.
INSERT INTO roles (role, user_id, scope_table, scope_id) VALUES
    ('editor', 'alice', 'lx.projects', '17'),
    ('editor', 'alice', 'lx.projects', '42'),
    ('editor', 'alice', 'lx.projects', '4711'),
    ('viewer', 'alice', 'lx.projects', '42'),
    ('viewer', 'alice', 'lx.projects', '100'),
    ('viewer', 'alice', 'lx.projects', '2500'),
    ('viewer', 'alice', 'lx.projects', '7777'),
    ('viewer', 'alice', 'lx.projects', '9999');

-- bigshot: editor on 2000 projects (20% of the data) — the large-scope-set case.
INSERT INTO roles (role, user_id, scope_table, scope_id)
SELECT 'editor', 'bigshot', 'lx.projects', g::text FROM generate_series(1, 10000, 5) g;

-- root: holds an unscoped admin role (for the OR-shaped visibility case).
INSERT INTO roles (role, user_id, scope_table, scope_id) VALUES ('admin', 'root', NULL, NULL);

VACUUM ANALYZE projects, tasks, comments, roles;

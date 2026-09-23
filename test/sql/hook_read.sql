-- Test: transparent read enforcement, behaviourally
-- (plan/17-planner-hook-implementation.md H5)
--
-- With the hook on, an ordinary SELECT sees exactly what letter._read()
-- shows (plan/15 D5 — the trigger/walker and the hook must agree), with
-- native types; the predicate leak of plan/14 §1 is closed; every query
-- shape reaches the same subquery; cached and generic plans are safe
-- across users; the switches behave inside one transaction; and RI keeps
-- seeing the truth.
--
-- Users (via assignments):
--   alice  editor@Alpha, viewer@Beta, global logger
--   bob    viewer@Alpha
--   carol  global reporter (select on users only)
--   dora   global auditor  (select name on projects)

CREATE EXTENSION letter;
SET letter.bypass = on;

CREATE TABLE users (id uuid PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE projects (
    id uuid PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    budget INTEGER,
    notes TEXT
);
CREATE TABLE tasks (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid NOT NULL REFERENCES projects(id),
    title TEXT NOT NULL
);
CREATE INDEX ON tasks (project_id);
CREATE TABLE team_members (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id),
    project_id uuid NOT NULL REFERENCES projects(id),
    role TEXT NOT NULL
);
CREATE TABLE auditors (user_id uuid PRIMARY KEY);
CREATE TABLE reporters (user_id uuid PRIMARY KEY);
CREATE TABLE loggers (user_id uuid PRIMARY KEY);
CREATE TABLE log (id serial PRIMARY KEY, line TEXT);

INSERT INTO users VALUES
    ('a0000000-0000-0000-0000-000000000001', 'Alice'),
    ('a0000000-0000-0000-0000-000000000002', 'Bob'),
    ('a0000000-0000-0000-0000-000000000003', 'Carol'),
    ('a0000000-0000-0000-0000-000000000004', 'Dora');
INSERT INTO projects VALUES
    ('b0000000-0000-0000-0000-000000000001', 'Alpha', 'active', 50000, 'alpha notes'),
    ('b0000000-0000-0000-0000-000000000002', 'Beta',  'draft',  NULL,  NULL),
    ('b0000000-0000-0000-0000-000000000003', 'Gamma', 'done',   10000, 'gamma notes');
INSERT INTO tasks (id, project_id, title) VALUES
    ('d0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 'Alpha task'),
    ('d0000000-0000-0000-0000-000000000002', 'b0000000-0000-0000-0000-000000000002', 'Beta task'),
    ('d0000000-0000-0000-0000-000000000003', 'b0000000-0000-0000-0000-000000000003', 'Gamma task');

SELECT letter.assign('public.team_members', 'user_id', role_column := 'role', scope := 'public.projects');
SELECT letter.assign('public.auditors', 'user_id', role := 'auditor');
SELECT letter.assign('public.reporters', 'user_id', role := 'reporter');
SELECT letter.assign('public.loggers', 'user_id', role := 'logger');

INSERT INTO team_members (user_id, project_id, role) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 'editor'),
    ('a0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000002', 'viewer'),
    ('a0000000-0000-0000-0000-000000000002', 'b0000000-0000-0000-0000-000000000001', 'viewer');
INSERT INTO auditors  VALUES ('a0000000-0000-0000-0000-000000000004');
INSERT INTO reporters VALUES ('a0000000-0000-0000-0000-000000000003');
INSERT INTO loggers   VALUES ('a0000000-0000-0000-0000-000000000001');

SELECT letter.grant_scoped('select', 'public.projects', 'editor', ARRAY['*'], 'public.projects');
SELECT letter.grant_scoped('select', 'public.projects', 'viewer', ARRAY['name', 'status'], 'public.projects');
SELECT letter.grant_global('select', 'public.projects', 'auditor', ARRAY['name']);
SELECT letter.grant_global('select', 'public.users', 'reporter', ARRAY['*']);
SELECT letter.grant_scoped('select', 'public.tasks', 'editor', ARRAY['title'], 'public.projects');
SELECT letter.grant_global('insert', 'public.tasks', 'logger');
SELECT letter.grant_global('insert', 'public.log', 'logger');
SELECT letter.grant_global('select', 'public.log', 'logger', ARRAY['*']);
SELECT letter.grant_global('update', 'public.log', 'logger', ARRAY['line']);

-- rows found by a plain SELECT (through the hook) and not by letter._read(),
-- and vice versa; values compared as text
CREATE FUNCTION parity(tbl regclass, OUT only_in_select bigint, OUT only_in_read bigint)
LANGUAGE plpgsql AS $$
BEGIN
    EXECUTE format($q$
        WITH sel AS (
            SELECT (SELECT jsonb_object_agg(e.key,
                               CASE WHEN jsonb_typeof(e.value) = 'null' THEN e.value
                                    ELSE to_jsonb(e.value #>> '{}') END)
                    FROM jsonb_each(to_jsonb(x)) e) AS j
            FROM %s x),
        rd AS (SELECT r - '_redacted' AS j FROM letter._read(%L) r)
        SELECT (SELECT count(*) FROM (SELECT j FROM sel EXCEPT SELECT j FROM rd) a),
               (SELECT count(*) FROM (SELECT j FROM rd EXCEPT SELECT j FROM sel) b)
    $q$, tbl, letter._qualname(tbl)) INTO only_in_select, only_in_read;
END $$;

CREATE VIEW project_budgets AS SELECT name, budget FROM projects;
CREATE VIEW project_budgets_inv WITH (security_invoker) AS SELECT name, budget FROM projects;
CREATE FUNCTION project_names() RETURNS SETOF text LANGUAGE sql AS 'SELECT name FROM projects ORDER BY name';
CREATE FUNCTION project_names_plpgsql() RETURNS SETOF text LANGUAGE plpgsql AS $$
BEGIN RETURN QUERY SELECT name FROM projects ORDER BY name; END $$;
CREATE TEMP TABLE scratch (name TEXT);
INSERT INTO scratch VALUES ('Alpha'), ('Gamma');

SET letter.bypass = off;
SET letter.enforce_reads = on;
\set VERBOSITY terse

-- ============================================================
-- 1. Parity with letter._read(), native types.
-- ============================================================
SET letter.user_id = 'a0000000-0000-0000-0000-000000000001';
SELECT name, status, budget, notes FROM projects ORDER BY name;
SELECT * FROM parity('public.projects');
SELECT * FROM parity('public.tasks');
SET letter.user_id = 'a0000000-0000-0000-0000-000000000002';
SELECT name, status, budget, notes FROM projects ORDER BY name;
SELECT * FROM parity('public.projects');
SET letter.user_id = 'a0000000-0000-0000-0000-000000000004';
SELECT name, status, budget, notes FROM projects ORDER BY name;
SELECT * FROM parity('public.projects');
SET letter.user_id = 'a0000000-0000-0000-0000-000000000003';
SELECT name FROM users ORDER BY name;
SELECT * FROM parity('public.users');
SELECT name FROM projects;

SET letter.user_id = 'a0000000-0000-0000-0000-000000000001';
SELECT pg_typeof(budget) AS budget_type, pg_typeof(id) AS id_type FROM projects LIMIT 1;

-- ============================================================
-- 2. The leak is closed: for bob, budget and notes are hidden and
--    nothing distinguishes "no match" from "can't see".
-- ============================================================
SET letter.user_id = 'a0000000-0000-0000-0000-000000000002';
SELECT name FROM projects WHERE budget > 0;
SELECT name FROM projects WHERE budget IS NULL ORDER BY name;
SELECT name FROM projects ORDER BY budget, name;
SELECT budget, count(*) FROM projects GROUP BY budget;
SELECT max(budget), min(notes) FROM projects;
SELECT p.name FROM projects p JOIN scratch s ON s.name = p.notes;
SELECT name FROM projects WHERE notes LIKE 'alpha%';

-- ============================================================
-- 3. Shapes.
-- ============================================================
SET letter.user_id = 'a0000000-0000-0000-0000-000000000001';
-- two protected tables: tasks.project_id is the grant's own path column, so
-- it is visible with the grant (17 D16) and the natural join works
SELECT p.name, t.title FROM projects p JOIN tasks t ON t.project_id = p.id ORDER BY 1;
-- protected + exempt (a temp table)
SELECT p.name, p.budget FROM projects p JOIN scratch s USING (name) ORDER BY 1;
-- subquery in FROM, CTE, sublink, UNION
SELECT count(*) FROM (SELECT budget FROM projects WHERE budget IS NOT NULL) s;
WITH b AS (SELECT name, budget FROM projects) SELECT * FROM b WHERE budget IS NOT NULL ORDER BY 1;
SELECT name FROM projects WHERE id IN (SELECT project_id FROM tasks) ORDER BY 1;
SELECT name FROM projects UNION SELECT title FROM tasks ORDER BY 1;
-- views: plain and security_invoker both expand to the protected table
SELECT * FROM project_budgets ORDER BY 1;
SELECT * FROM project_budgets_inv ORDER BY 1;
-- function bodies
SELECT project_names();
SELECT project_names_plpgsql();
-- whole-row references
SELECT to_jsonb(p) - 'id' FROM projects p ORDER BY p.name;
-- INSERT … SELECT and UPDATE … FROM reading a protected table
INSERT INTO log (line) SELECT name || ':' || coalesce(budget::text, '-') FROM projects ORDER BY name;
SELECT line FROM log ORDER BY id;
UPDATE log SET line = line || ' (' || p.status || ')' FROM projects p WHERE log.line LIKE p.name || ':%';
SELECT line FROM log ORDER BY id;

-- ============================================================
-- 4. Generic-plan safety: one plan, many users.
-- ============================================================
SET plan_cache_mode = force_generic_plan;
PREPARE q AS SELECT name, budget FROM projects ORDER BY name;
SET letter.user_id = 'a0000000-0000-0000-0000-000000000001';
EXECUTE q;
SET letter.user_id = 'a0000000-0000-0000-0000-000000000002';
EXECUTE q;
SET letter.user_id = 'a0000000-0000-0000-0000-000000000004';
EXECUTE q;
SELECT project_names_plpgsql();
SET letter.user_id = 'a0000000-0000-0000-0000-000000000002';
SELECT project_names_plpgsql();
RESET plan_cache_mode;

-- ============================================================
-- 5. Switches, inside one transaction, with a prepared statement.
-- ============================================================
SET letter.user_id = 'a0000000-0000-0000-0000-000000000002';
BEGIN;
EXECUTE q;
SET LOCAL letter.bypass = on;
EXECUTE q;
SET LOCAL letter.bypass = off;
EXECUTE q;
SET LOCAL letter.user_id = '';
-- unset user: an error, from the cached plan too (D2, amended)
EXECUTE q;
ROLLBACK;
DEALLOCATE q;

-- ============================================================
-- 6. letter.visible_columns(): which NULLs are redactions.
-- ============================================================
SET letter.user_id = 'a0000000-0000-0000-0000-000000000001';
SELECT name, letter.visible_columns('public.projects', id) FROM projects ORDER BY name;
SELECT letter.visible_columns('public.projects', 'b0000000-0000-0000-0000-000000000003'::uuid) AS gamma_hidden;
SET letter.user_id = 'a0000000-0000-0000-0000-000000000002';
SELECT name, letter.visible_columns('public.projects', id) FROM projects ORDER BY name;
SET letter.user_id = 'a0000000-0000-0000-0000-000000000004';
SELECT name, letter.visible_columns('public.projects', id) FROM projects ORDER BY name;
SELECT letter.visible_columns('public.projects', 'b0000000-0000-0000-0000-0000000000ff'::uuid) AS no_such_row;
SELECT letter.visible_columns('public.team_members', gen_random_uuid());
SET letter.bypass = on;
SELECT letter.visible_columns('public.projects', 'b0000000-0000-0000-0000-000000000003'::uuid) AS bypass_sees_all;
SET letter.bypass = off;

-- ============================================================
-- 7. RI still sees the truth: alice, as logger, may insert a task
--    into Gamma, a project she cannot read.
-- ============================================================
SET letter.user_id = 'a0000000-0000-0000-0000-000000000001';
SELECT count(*) FROM projects WHERE name = 'Gamma';
INSERT INTO tasks (project_id, title) VALUES ('b0000000-0000-0000-0000-000000000003', 'logged into Gamma');
INSERT INTO tasks (project_id, title) VALUES ('b0000000-0000-0000-0000-0000000000ff', 'no such project');
SET letter.bypass = on;
SELECT title FROM tasks ORDER BY title;

-- ============================================================
-- 8. An if on a select grant, through the hook (plan/20 §3): dora,
--    auditor, reads every name and the budget of active projects only.
-- ============================================================
SELECT letter.grant_global('select', 'public.projects', 'auditor', ARRAY['budget'], if := 'status = ''active''');
SET letter.bypass = off;
SET letter.user_id = 'a0000000-0000-0000-0000-000000000004';
SELECT name, budget FROM projects ORDER BY name;
SELECT name, letter.visible_columns('public.projects', id) FROM projects ORDER BY name;
SELECT name FROM projects WHERE budget > 0 ORDER BY name;
SET letter.bypass = on;

\set VERBOSITY default
-- Cleanup
RESET letter.user_id;
RESET letter.enforce_reads;
DROP FUNCTION parity(regclass), project_names(), project_names_plpgsql();
DROP VIEW project_budgets, project_budgets_inv;
DROP TABLE scratch;
DROP TABLE log, loggers, reporters, auditors, team_members, tasks, projects, users CASCADE;
DROP EXTENSION letter CASCADE;

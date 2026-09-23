-- Test: the barrier generator (plan/17-planner-hook-implementation.md §2, H2)
--
-- letter.barrier_sql(regclass) returns the redacting subquery the planner
-- hook will substitute for a protected table. Each fixture below is
--   * golden text — the SQL is printed, and
--   * executable  — the SQL is installed as a security_barrier view and its
--     rows/redaction compared with letter.read() on the same data. The hook
--     and read() must agree (plan/15 D5); parity() counts rows found by one
--     and not the other, values compared as text.
--
-- Users:  alice  editor@Alpha, viewer@Beta
--         bob    viewer@Alpha, assignee@task-Alpha and @task-Beta, o'brien@Gamma,
--                o'brien@Odd-1
--         carol  auditor (global scope)
--         erin   auditor@Alpha only — never satisfies an unscoped grant (17 D11)
--         dave   member@org-1

CREATE EXTENSION letter;
SET letter.enforce_reads = off;   -- this test is not about the read hook

CREATE TABLE orgs (id bigint PRIMARY KEY, name TEXT);
CREATE TABLE projects (
    id uuid PRIMARY KEY,
    org_id bigint REFERENCES orgs(id),
    name TEXT,
    status TEXT
);
CREATE INDEX ON projects (org_id);
CREATE TABLE tasks (
    id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(id),
    title TEXT,
    estimate varchar(10)
);
CREATE INDEX ON tasks (project_id);
CREATE TABLE comments (
    id uuid PRIMARY KEY,
    task_id uuid REFERENCES tasks(id),
    legacy TEXT,
    author TEXT,
    body TEXT
);
CREATE INDEX ON comments (task_id);
ALTER TABLE comments DROP COLUMN legacy;      -- a hole in the attnums
CREATE TABLE reactions (
    id uuid PRIMARY KEY,
    comment_id uuid REFERENCES comments(id),
    emoji TEXT
);
CREATE INDEX ON reactions (comment_id);
CREATE TABLE memberships (                    -- composite-PK leaf
    project_id uuid REFERENCES projects(id),
    user_name TEXT,
    note TEXT,
    PRIMARY KEY (project_id, user_name)
);
CREATE TABLE pair_scope (a int, b int, name TEXT, PRIMARY KEY (a, b));
CREATE TABLE pair_leaf (
    id int PRIMARY KEY,
    a int,
    b int,
    body TEXT,
    FOREIGN KEY (a, b) REFERENCES pair_scope (a, b)
);
CREATE TABLE "Odd Scope" ("Key" int PRIMARY KEY);
CREATE TABLE "Odd Hop" (
    "Id" int PRIMARY KEY,
    "Scope Id" int REFERENCES "Odd Scope"("Key")
);
CREATE INDEX ON "Odd Hop" ("Scope Id");
CREATE TABLE odd_leaf (
    id int PRIMARY KEY,
    "Hop Id" int REFERENCES "Odd Hop"("Id"),
    "Body Text" TEXT,
    "select" TEXT
);
CREATE INDEX ON odd_leaf ("Hop Id");
CREATE TABLE ungranted (id int PRIMARY KEY, x TEXT);

INSERT INTO orgs VALUES (1, 'Acme'), (2, 'Globex');
INSERT INTO projects VALUES
    ('a0000000-0000-0000-0000-000000000001', 1, 'Alpha', 'active'),
    ('a0000000-0000-0000-0000-000000000002', 1, 'Beta',  'paused'),
    ('a0000000-0000-0000-0000-000000000003', 2, 'Gamma', 'active');
INSERT INTO tasks VALUES
    ('b0000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001', 'task-Alpha', '3d'),
    ('b0000000-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000002', 'task-Beta',  '5d'),
    ('b0000000-0000-0000-0000-000000000003', 'a0000000-0000-0000-0000-000000000003', 'task-Gamma', '8d');
INSERT INTO comments (id, task_id, author, body) VALUES
    ('c0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 'ann', 'on Alpha'),
    ('c0000000-0000-0000-0000-000000000002', 'b0000000-0000-0000-0000-000000000002', 'ben', 'on Beta'),
    ('c0000000-0000-0000-0000-000000000003', 'b0000000-0000-0000-0000-000000000003', 'cat', 'on Gamma'),
    ('c0000000-0000-0000-0000-000000000004', NULL,                                   'dan', 'orphan');
INSERT INTO reactions VALUES
    ('d0000000-0000-0000-0000-000000000001', 'c0000000-0000-0000-0000-000000000001', 'r-Alpha'),
    ('d0000000-0000-0000-0000-000000000002', 'c0000000-0000-0000-0000-000000000002', 'r-Beta'),
    ('d0000000-0000-0000-0000-000000000003', 'c0000000-0000-0000-0000-000000000004', 'r-orphan'),
    ('d0000000-0000-0000-0000-000000000004', NULL,                                   'r-null');
INSERT INTO memberships VALUES
    ('a0000000-0000-0000-0000-000000000001', 'ann', 'm-Alpha'),
    ('a0000000-0000-0000-0000-000000000003', 'cat', 'm-Gamma');
INSERT INTO "Odd Scope" VALUES (1), (2);
INSERT INTO "Odd Hop" VALUES (10, 1), (20, 2);
INSERT INTO odd_leaf VALUES (100, 10, 'odd-1', 'kw-1'), (200, 20, 'odd-2', 'kw-2');

INSERT INTO letter.roles (role, user_id, scope_table, scope_id) VALUES
    ('editor',   'alice', 'public.projects',  'a0000000-0000-0000-0000-000000000001'),
    ('viewer',   'alice', 'public.projects',  'a0000000-0000-0000-0000-000000000002'),
    ('viewer',   'bob',   'public.projects',  'a0000000-0000-0000-0000-000000000001'),
    ('assignee', 'bob',   'public.tasks',     'b0000000-0000-0000-0000-000000000001'),
    ('assignee', 'bob',   'public.tasks',     'b0000000-0000-0000-0000-000000000002'),
    ('o''brien', 'bob',   'public.projects',  'a0000000-0000-0000-0000-000000000003'),
    ('o''brien', 'bob',   'public."Odd Scope"', '1'),
    ('auditor',  'carol', NULL,               NULL),
    ('auditor',  'erin',  'public.projects',  'a0000000-0000-0000-0000-000000000001'),
    ('member',   'dave',  'public.orgs',      '1');

-- The generated text embeds scope-table OIDs (plan/18 §1.3), which differ
-- between runs: show them as names. The views below use the raw text.
CREATE FUNCTION show_sql(sql text) RETURNS text LANGUAGE plpgsql AS $$
DECLARE m text[];
BEGIN
    FOR m IN SELECT regexp_matches(sql, 'r\.scope_table = (\d+)', 'g') LOOP
        sql := replace(sql, 'r.scope_table = ' || m[1],
                       'r.scope_table = <' || m[1]::oid::regclass::text || '>');
    END LOOP;
    RETURN sql;
END $$;

CREATE FUNCTION parity(v regclass, tbl text,
                       OUT only_in_view bigint, OUT only_in_read bigint)
LANGUAGE plpgsql AS $$
BEGIN
    EXECUTE format($q$
        WITH vw AS (
            SELECT (SELECT jsonb_object_agg(e.key,
                               CASE WHEN jsonb_typeof(e.value) = 'null' THEN e.value
                                    ELSE to_jsonb(e.value #>> '{}') END)
                    FROM jsonb_each(to_jsonb(x)) e
                    WHERE e.key NOT LIKE '%%pg.dropped%%') AS j
            FROM %s x),
        rd AS (SELECT r - '_redacted' AS j FROM letter.read(%L) r)
        SELECT (SELECT count(*) FROM (SELECT j FROM vw EXCEPT SELECT j FROM rd) a),
               (SELECT count(*) FROM (SELECT j FROM rd EXCEPT SELECT j FROM vw) b)
    $q$, v, tbl) INTO only_in_view, only_in_read;
END $$;

-- ============================================================
-- Fixture 1: direct FK (no hops). No grant covers estimate.
-- ============================================================
SELECT letter.grant('select', 'public.tasks', 'editor', ARRAY['title'],
    'public.projects', NULL, NULL);

SELECT letter.barrier_sql('public.tasks') AS sql \gset
SELECT show_sql(:'sql') AS sql_shown \gset
\echo :sql_shown
CREATE VIEW v_tasks WITH (security_barrier) AS :sql;

SET letter.current_user_id = 'alice';
SELECT title, estimate FROM v_tasks ORDER BY title;
SELECT * FROM parity('v_tasks', 'public.tasks');
SET letter.current_user_id = 'bob';
SELECT title, estimate FROM v_tasks ORDER BY title;
SELECT * FROM parity('v_tasks', 'public.tasks');

-- Native types survive redaction, granted or not.
SELECT a.attname, format_type(a.atttypid, a.atttypmod) AS view_type,
       format_type(t.atttypid, t.atttypmod) AS table_type
FROM pg_attribute a JOIN pg_attribute t
  ON t.attrelid = 'tasks'::regclass AND t.attnum = a.attnum
WHERE a.attrelid = 'v_tasks'::regclass ORDER BY a.attnum;

-- ============================================================
-- Fixture 2: one hop, final hop inferred; two roles with different
-- columns on one chain; a dropped column; a NULL mid-chain (the
-- orphan comment is visible to nobody).
-- ============================================================
SELECT letter.grant('select', 'public.comments', 'editor', ARRAY['body'],
    'public.projects', ARRAY['task_id'], NULL);
SELECT letter.grant('select', 'public.comments', 'viewer', ARRAY['author'],
    'public.projects', ARRAY['task_id'], NULL);

SELECT letter.barrier_sql('public.comments') AS sql \gset
SELECT show_sql(:'sql') AS sql_shown \gset
\echo :sql_shown
CREATE VIEW v_comments WITH (security_barrier) AS :sql;

SET letter.current_user_id = 'alice';
SELECT author, body FROM v_comments ORDER BY id;
SELECT * FROM parity('v_comments', 'public.comments');
SET letter.current_user_id = 'bob';
SELECT author, body FROM v_comments ORDER BY id;
SELECT * FROM parity('v_comments', 'public.comments');

-- ============================================================
-- Fixture 3: two hops, final hop inferred; a '*' grant.
-- ============================================================
SELECT letter.grant('select', 'public.reactions', 'viewer', ARRAY['*'],
    'public.projects', ARRAY['comment_id', 'task_id'], NULL);

SELECT letter.barrier_sql('public.reactions') AS sql \gset
SELECT show_sql(:'sql') AS sql_shown \gset
\echo :sql_shown
CREATE VIEW v_reactions WITH (security_barrier) AS :sql;

SET letter.current_user_id = 'alice';
SELECT emoji FROM v_reactions ORDER BY id;
SELECT * FROM parity('v_reactions', 'public.reactions');
SET letter.current_user_id = 'bob';
SELECT emoji FROM v_reactions ORDER BY id;
SELECT * FROM parity('v_reactions', 'public.reactions');

-- ============================================================
-- Fixture 4: the same chain with the final hop explicit.
-- ============================================================
DROP VIEW v_reactions;
SELECT letter.revoke('select', 'public.reactions', 'viewer', ARRAY['*'], 'public.projects');
SELECT letter.grant('select', 'public.reactions', 'viewer', ARRAY['emoji'],
    'public.projects', ARRAY['comment_id', 'task_id', 'project_id'], NULL);

SELECT letter.barrier_sql('public.reactions') AS sql \gset
SELECT show_sql(:'sql') AS sql_shown \gset
\echo :sql_shown
CREATE VIEW v_reactions WITH (security_barrier) AS :sql;

SET letter.current_user_id = 'alice';
SELECT emoji FROM v_reactions ORDER BY id;
SELECT * FROM parity('v_reactions', 'public.reactions');

-- ============================================================
-- Fixture 5: an unscoped grant alone — one gated branch, no joins.
-- ============================================================
SELECT letter.grant('select', 'public.orgs', 'auditor', ARRAY['name'], NULL, NULL, NULL);

SELECT letter.barrier_sql('public.orgs') AS sql \gset
SELECT show_sql(:'sql') AS sql_shown \gset
\echo :sql_shown
CREATE VIEW v_orgs WITH (security_barrier) AS :sql;

SET letter.current_user_id = 'carol';
SELECT id, name FROM v_orgs ORDER BY id;
SELECT * FROM parity('v_orgs', 'public.orgs');
SET letter.current_user_id = 'alice';
SELECT id, name FROM v_orgs ORDER BY id;
SELECT * FROM parity('v_orgs', 'public.orgs');
-- erin holds 'auditor' scoped to a project, not globally: nothing (17 D11)
SET letter.current_user_id = 'erin';
SELECT id, name FROM v_orgs ORDER BY id;
SELECT * FROM parity('v_orgs', 'public.orgs');

-- ============================================================
-- Fixture 6: unscoped + scoped on one table; the table is its own
-- scope; a second chain to a bigint-keyed scope.
-- ============================================================
SELECT letter.grant('select', 'public.projects', 'auditor', ARRAY['name'], NULL, NULL, NULL);
SELECT letter.grant('select', 'public.projects', 'editor', ARRAY['*'],
    'public.projects', NULL, NULL);
SELECT letter.grant('select', 'public.projects', 'member', ARRAY['status'],
    'public.orgs', NULL, NULL);

SELECT letter.barrier_sql('public.projects') AS sql \gset
SELECT show_sql(:'sql') AS sql_shown \gset
\echo :sql_shown
CREATE VIEW v_projects WITH (security_barrier) AS :sql;

SET letter.current_user_id = 'carol';
SELECT name, status, org_id FROM v_projects ORDER BY name;
SELECT * FROM parity('v_projects', 'public.projects');
SET letter.current_user_id = 'alice';
SELECT name, status, org_id FROM v_projects ORDER BY name;
SELECT * FROM parity('v_projects', 'public.projects');
SET letter.current_user_id = 'dave';
SELECT name, status, org_id FROM v_projects ORDER BY name;
SELECT * FROM parity('v_projects', 'public.projects');
SET letter.current_user_id = 'erin';
SELECT name, status, org_id FROM v_projects ORDER BY name;
SELECT * FROM parity('v_projects', 'public.projects');

-- ============================================================
-- Fixture 7: two chains and an unscoped grant on comments. bob
-- reaches the Alpha comment through BOTH chains (viewer on the
-- project, assignee on the task): it appears once, with the columns
-- of both grants. Beta he reaches through the tasks chain only.
-- carol sees every row, the orphan included.
-- ============================================================
DROP VIEW v_comments;
SELECT letter.grant('select', 'public.comments', 'assignee', ARRAY['body'],
    'public.tasks', NULL, NULL);
SELECT letter.grant('select', 'public.comments', 'auditor', ARRAY['author'], NULL, NULL, NULL);

SELECT letter.barrier_sql('public.comments') AS sql \gset
SELECT show_sql(:'sql') AS sql_shown \gset
\echo :sql_shown
CREATE VIEW v_comments WITH (security_barrier) AS :sql;

SET letter.current_user_id = 'alice';
SELECT author, body FROM v_comments ORDER BY id;
SELECT * FROM parity('v_comments', 'public.comments');
SET letter.current_user_id = 'bob';
SELECT author, body FROM v_comments ORDER BY id;
SELECT * FROM parity('v_comments', 'public.comments');
SET letter.current_user_id = 'carol';
SELECT author, body FROM v_comments ORDER BY id;
SELECT * FROM parity('v_comments', 'public.comments');

-- The write path's correlated form (plan/19 W1): the row qual and the
-- per-column tests over alias b, hops as scalar sublinks. Executable: the
-- qual must select exactly the rows letter.read() shows.
SELECT letter.barrier_write_sql('public.comments') AS wsql \gset
SELECT show_sql(:'wsql') AS wsql_shown \gset
\echo :wsql_shown
SELECT letter.barrier_write_sql('public.reactions') AS wsql \gset
SELECT show_sql(:'wsql') AS wsql_shown \gset
\echo :wsql_shown

CREATE FUNCTION write_qual_parity(tbl regclass, OUT by_qual bigint, OUT by_read bigint)
LANGUAGE plpgsql AS $$
DECLARE q text;
BEGIN
    q := split_part(letter.barrier_write_sql(tbl), E'\n', 1);   -- the WHERE line
    EXECUTE format('SELECT count(*) FROM %s b %s', tbl, q) INTO by_qual;
    EXECUTE format('SELECT count(*) FROM letter.read(%L)', letter._qualname(tbl)) INTO by_read;
END $$;
SET letter.current_user_id = 'alice';
SELECT * FROM write_qual_parity('public.comments');
SELECT * FROM write_qual_parity('public.reactions');
SET letter.current_user_id = 'bob';
SELECT * FROM write_qual_parity('public.comments');
SELECT * FROM write_qual_parity('public.reactions');
SET letter.current_user_id = 'carol';
SELECT * FROM write_qual_parity('public.comments');
SET letter.current_user_id = 'erin';
SELECT * FROM write_qual_parity('public.comments');
DROP FUNCTION write_qual_parity(regclass);

-- ============================================================
-- Fixture 8: composite primary keys (D4). Allowed on a leaf — every
-- PK column is visible. (letter.read() shows only the first PK column,
-- so parity is not asserted here.)
-- ============================================================
SELECT letter.grant('select', 'public.memberships', 'editor', ARRAY['note'],
    'public.projects', NULL, NULL);

SELECT letter.barrier_sql('public.memberships') AS sql \gset
SELECT show_sql(:'sql') AS sql_shown \gset
\echo :sql_shown
CREATE VIEW v_memberships WITH (security_barrier) AS :sql;

SET letter.current_user_id = 'alice';
SELECT user_name, note FROM v_memberships ORDER BY user_name;

-- Rejected at grant time on a scope table, on a table along the path,
-- and on a table that is its own scope — for any privilege.
\set VERBOSITY terse
SELECT letter.grant('select', 'public.pair_leaf', 'viewer', ARRAY['body'],
    'public.pair_scope', NULL, NULL);
SELECT letter.grant('update', 'public.pair_leaf', 'viewer', ARRAY['body'],
    'public.orgs', ARRAY['a'], NULL);
SELECT letter.grant('select', 'public.pair_scope', 'viewer', ARRAY['name'],
    'public.pair_scope', NULL, NULL);
\set VERBOSITY default
SELECT count(*) FROM letter.grants WHERE on_table::text LIKE '%pair%';

-- ============================================================
-- Fixture 9: identifiers that need quoting (mixed case, spaces, a
-- keyword) and a role name containing a quote.
-- ============================================================
SELECT letter.grant('select', 'public.odd_leaf', 'o''brien', ARRAY['Body Text'],
    'public."Odd Scope"', ARRAY['Hop Id'], NULL);

SELECT letter.barrier_sql('public.odd_leaf') AS sql \gset
SELECT show_sql(:'sql') AS sql_shown \gset
\echo :sql_shown
CREATE VIEW v_odd WITH (security_barrier) AS :sql;

SET letter.current_user_id = 'bob';
SELECT id, "Body Text", "select" FROM v_odd ORDER BY id;
SELECT * FROM parity('v_odd', 'public.odd_leaf');

-- ============================================================
-- Entry criterion (plan/16 §7): nothing user-specific in the text.
-- Generated as a sentinel user who holds a role, the SQL contains
-- neither the user id nor any of that user's scope ids.
-- ============================================================
INSERT INTO letter.roles (role, user_id, scope_table, scope_id) VALUES
    ('editor', 'SENTINEL-USER', 'public.projects', 'a0000000-0000-0000-0000-000000000002');
SET letter.current_user_id = 'SENTINEL-USER';

SELECT t.tbl,
       position('SENTINEL' in letter.barrier_sql(t.tbl)) AS user_id_at,
       (SELECT count(*) FROM letter.roles r
         WHERE length(r.scope_id) > 8
           AND position(r.scope_id in letter.barrier_sql(t.tbl)) > 0) AS scope_ids_found
FROM (VALUES ('public.comments'::regclass), ('public.projects'), ('public.reactions')) t(tbl);

RESET letter.current_user_id;

-- A table with no select grants has no barrier.
SELECT letter.barrier_sql('public.ungranted') IS NULL AS no_barrier;

-- Cleanup
DROP VIEW v_tasks, v_comments, v_reactions, v_orgs, v_projects, v_memberships, v_odd;
DROP FUNCTION parity(regclass, text);
DROP FUNCTION show_sql(text);
DROP TABLE ungranted, odd_leaf, "Odd Hop", "Odd Scope", pair_leaf, pair_scope,
    memberships, reactions, comments, tasks, projects, orgs CASCADE;
DROP EXTENSION letter CASCADE;

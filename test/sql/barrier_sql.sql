-- Test: the barrier generator (plan/17-planner-hook-implementation.md §2, H2)
--
-- letter.read_policy(regclass) returns the redacting subquery the planner
-- hook will substitute for a protected table. Each fixture below is
--   * golden text — the SQL is printed, and
--   * executable  — the SQL is installed as a security_barrier view and its
--     rows/redaction compared with letter._read() on the same data. The hook
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

INSERT INTO letter.memberships (role, user_id, scope_table, scope_id) VALUES
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
                                    WHEN jsonb_typeof(e.value) = 'boolean'    -- _read() prints booleans as t/f
                                         THEN to_jsonb(CASE WHEN (e.value #>> '{}') = 'true' THEN 't' ELSE 'f' END)
                                    ELSE to_jsonb(e.value #>> '{}') END)
                    FROM jsonb_each(to_jsonb(x)) e
                    WHERE e.key NOT LIKE '%%pg.dropped%%') AS j
            FROM %s x),
        rd AS (SELECT r - '_redacted' AS j FROM letter._read(%L) r)
        SELECT (SELECT count(*) FROM (SELECT j FROM vw EXCEPT SELECT j FROM rd) a),
               (SELECT count(*) FROM (SELECT j FROM rd EXCEPT SELECT j FROM vw) b)
    $q$, v, tbl) INTO only_in_view, only_in_read;
END $$;

-- ============================================================
-- Fixture 1: direct FK (no hops). No grant covers estimate.
-- ============================================================
SELECT letter.grant_scoped('select', 'public.tasks', 'editor', ARRAY['title'], 'public.projects');

SELECT letter.read_policy('public.tasks') AS sql \gset
SELECT show_sql(:'sql') AS sql_shown \gset
\echo :sql_shown
CREATE VIEW v_tasks WITH (security_barrier) AS :sql;

SET letter.user_id = 'alice';
SELECT title, estimate FROM v_tasks ORDER BY title;
SELECT * FROM parity('v_tasks', 'public.tasks');
SET letter.user_id = 'bob';
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
SELECT letter.grant_scoped('select', 'public.comments', 'editor', ARRAY['body'], 'public.projects', ARRAY['task_id']);
SELECT letter.grant_scoped('select', 'public.comments', 'viewer', ARRAY['author'], 'public.projects', ARRAY['task_id']);

SELECT letter.read_policy('public.comments') AS sql \gset
SELECT show_sql(:'sql') AS sql_shown \gset
\echo :sql_shown
CREATE VIEW v_comments WITH (security_barrier) AS :sql;

SET letter.user_id = 'alice';
SELECT author, body FROM v_comments ORDER BY id;
SELECT * FROM parity('v_comments', 'public.comments');
SET letter.user_id = 'bob';
SELECT author, body FROM v_comments ORDER BY id;
SELECT * FROM parity('v_comments', 'public.comments');

-- ============================================================
-- Fixture 3: two hops, final hop inferred; a '*' grant.
-- ============================================================
SELECT letter.grant_scoped('select', 'public.reactions', 'viewer', ARRAY['*'], 'public.projects', ARRAY['comment_id', 'task_id']);

SELECT letter.read_policy('public.reactions') AS sql \gset
SELECT show_sql(:'sql') AS sql_shown \gset
\echo :sql_shown
CREATE VIEW v_reactions WITH (security_barrier) AS :sql;

SET letter.user_id = 'alice';
SELECT emoji FROM v_reactions ORDER BY id;
SELECT * FROM parity('v_reactions', 'public.reactions');
SET letter.user_id = 'bob';
SELECT emoji FROM v_reactions ORDER BY id;
SELECT * FROM parity('v_reactions', 'public.reactions');

-- ============================================================
-- Fixture 4: the same chain with the final hop explicit.
-- ============================================================
DROP VIEW v_reactions;
SELECT letter.revoke_scoped('select', 'public.reactions', 'viewer', ARRAY['*'], 'public.projects');
SELECT letter.grant_scoped('select', 'public.reactions', 'viewer', ARRAY['emoji'], 'public.projects', ARRAY['comment_id', 'task_id', 'project_id']);

SELECT letter.read_policy('public.reactions') AS sql \gset
SELECT show_sql(:'sql') AS sql_shown \gset
\echo :sql_shown
CREATE VIEW v_reactions WITH (security_barrier) AS :sql;

SET letter.user_id = 'alice';
SELECT emoji FROM v_reactions ORDER BY id;
SELECT * FROM parity('v_reactions', 'public.reactions');

-- ============================================================
-- Fixture 5: an unscoped grant alone — one gated branch, no joins.
-- ============================================================
SELECT letter.grant_global('select', 'public.orgs', 'auditor', ARRAY['name']);

SELECT letter.read_policy('public.orgs') AS sql \gset
SELECT show_sql(:'sql') AS sql_shown \gset
\echo :sql_shown
CREATE VIEW v_orgs WITH (security_barrier) AS :sql;

SET letter.user_id = 'carol';
SELECT id, name FROM v_orgs ORDER BY id;
SELECT * FROM parity('v_orgs', 'public.orgs');
SET letter.user_id = 'alice';
SELECT id, name FROM v_orgs ORDER BY id;
SELECT * FROM parity('v_orgs', 'public.orgs');
-- erin holds 'auditor' scoped to a project, not globally: nothing (17 D11)
SET letter.user_id = 'erin';
SELECT id, name FROM v_orgs ORDER BY id;
SELECT * FROM parity('v_orgs', 'public.orgs');

-- ============================================================
-- Fixture 6: unscoped + scoped on one table; the table is its own
-- scope; a second chain to a bigint-keyed scope.
-- ============================================================
SELECT letter.grant_global('select', 'public.projects', 'auditor', ARRAY['name']);
SELECT letter.grant_scoped('select', 'public.projects', 'editor', ARRAY['*'], 'public.projects');
SELECT letter.grant_scoped('select', 'public.projects', 'member', ARRAY['status'], 'public.orgs');

SELECT letter.read_policy('public.projects') AS sql \gset
SELECT show_sql(:'sql') AS sql_shown \gset
\echo :sql_shown
CREATE VIEW v_projects WITH (security_barrier) AS :sql;

SET letter.user_id = 'carol';
SELECT name, status, org_id FROM v_projects ORDER BY name;
SELECT * FROM parity('v_projects', 'public.projects');
SET letter.user_id = 'alice';
SELECT name, status, org_id FROM v_projects ORDER BY name;
SELECT * FROM parity('v_projects', 'public.projects');
SET letter.user_id = 'dave';
SELECT name, status, org_id FROM v_projects ORDER BY name;
SELECT * FROM parity('v_projects', 'public.projects');
SET letter.user_id = 'erin';
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
SELECT letter.grant_scoped('select', 'public.comments', 'assignee', ARRAY['body'], 'public.tasks');
SELECT letter.grant_global('select', 'public.comments', 'auditor', ARRAY['author']);

SELECT letter.read_policy('public.comments') AS sql \gset
SELECT show_sql(:'sql') AS sql_shown \gset
\echo :sql_shown
CREATE VIEW v_comments WITH (security_barrier) AS :sql;

SET letter.user_id = 'alice';
SELECT author, body FROM v_comments ORDER BY id;
SELECT * FROM parity('v_comments', 'public.comments');
SET letter.user_id = 'bob';
SELECT author, body FROM v_comments ORDER BY id;
SELECT * FROM parity('v_comments', 'public.comments');
SET letter.user_id = 'carol';
SELECT author, body FROM v_comments ORDER BY id;
SELECT * FROM parity('v_comments', 'public.comments');

-- ============================================================
-- Fixture 7b: two rules for one role differing only in their path
-- (plan/17 D15): messages between projects, readable by a member of
-- EITHER project. Both rules stand; the barrier unions them.
-- ============================================================
CREATE TABLE messages (
    id uuid PRIMARY KEY,
    from_project uuid REFERENCES projects(id),
    to_project uuid REFERENCES projects(id),
    body TEXT
);
CREATE INDEX ON messages (from_project);
CREATE INDEX ON messages (to_project);
INSERT INTO messages VALUES
    ('e0000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000003', 'Alpha→Gamma'),
    ('e0000000-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000003', 'a0000000-0000-0000-0000-000000000002', 'Gamma→Beta'),
    ('e0000000-0000-0000-0000-000000000003', 'a0000000-0000-0000-0000-000000000003', 'a0000000-0000-0000-0000-000000000003', 'Gamma→Gamma');
SELECT letter.grant_scoped('select', 'public.messages', 'editor', ARRAY['body'], 'public.projects', ARRAY['from_project']);
SELECT letter.grant_scoped('select', 'public.messages', 'editor', ARRAY['body'], 'public.projects', ARRAY['to_project']);
SELECT letter.grant_scoped('select', 'public.messages', 'editor', ARRAY['body'], 'public.projects', ARRAY['to_project']);   -- same rule: no-op
SELECT count(*) AS rules FROM letter.grants WHERE on_table = 'public.messages'::regclass;

SELECT letter.read_policy('public.messages') AS sql \gset
SELECT show_sql(:'sql') AS sql_shown \gset
\echo :sql_shown
CREATE VIEW v_messages WITH (security_barrier) AS :sql;
SET letter.user_id = 'alice';     -- editor@Alpha: the Alpha→Gamma message only
SELECT body FROM v_messages ORDER BY body;
SELECT * FROM parity('v_messages', 'public.messages');
DROP VIEW v_messages;
DROP TABLE messages;

-- The write path's correlated form (plan/19 W1): the row qual and the
-- per-column tests over alias b, hops as scalar sublinks. Executable: the
-- qual must select exactly the rows letter._read() shows.
SELECT letter.write_policy('public.comments') AS wsql \gset
SELECT show_sql(:'wsql') AS wsql_shown \gset
\echo :wsql_shown
SELECT letter.write_policy('public.reactions') AS wsql \gset
SELECT show_sql(:'wsql') AS wsql_shown \gset
\echo :wsql_shown

CREATE FUNCTION write_qual_parity(tbl regclass, OUT by_qual bigint, OUT by_read bigint)
LANGUAGE plpgsql AS $$
DECLARE q text;
BEGIN
    q := split_part(letter.write_policy(tbl), E'\n', 1);   -- the WHERE line
    EXECUTE format('SELECT count(*) FROM %s b %s', tbl, q) INTO by_qual;
    EXECUTE format('SELECT count(*) FROM letter._read(%L)', letter._qualname(tbl)) INTO by_read;
END $$;
SET letter.user_id = 'alice';
SELECT * FROM write_qual_parity('public.comments');
SELECT * FROM write_qual_parity('public.reactions');
SET letter.user_id = 'bob';
SELECT * FROM write_qual_parity('public.comments');
SELECT * FROM write_qual_parity('public.reactions');
SET letter.user_id = 'carol';
SELECT * FROM write_qual_parity('public.comments');
SET letter.user_id = 'erin';
SELECT * FROM write_qual_parity('public.comments');
DROP FUNCTION write_qual_parity(regclass);

-- ============================================================
-- Fixture 8: composite primary keys (D4). Allowed on a leaf — every
-- PK column is visible. (letter._read() shows only the first PK column,
-- so parity is not asserted here.)
-- ============================================================
SELECT letter.grant_scoped('select', 'public.memberships', 'editor', ARRAY['note'], 'public.projects');

SELECT letter.read_policy('public.memberships') AS sql \gset
SELECT show_sql(:'sql') AS sql_shown \gset
\echo :sql_shown
CREATE VIEW v_memberships WITH (security_barrier) AS :sql;

SET letter.user_id = 'alice';
SELECT user_name, note FROM v_memberships ORDER BY user_name;

-- Rejected at grant time on a scope table, on a table along the path,
-- and on a table that is its own scope — for any privilege.
\set VERBOSITY terse
SELECT letter.grant_scoped('select', 'public.pair_leaf', 'viewer', ARRAY['body'], 'public.pair_scope');
SELECT letter.grant_scoped('update', 'public.pair_leaf', 'viewer', ARRAY['body'], 'public.orgs', ARRAY['a']);
SELECT letter.grant_scoped('select', 'public.pair_scope', 'viewer', ARRAY['name'], 'public.pair_scope');
\set VERBOSITY default
SELECT count(*) FROM letter.grants WHERE on_table::text LIKE '%pair%';

-- ============================================================
-- Fixture 9: identifiers that need quoting (mixed case, spaces, a
-- keyword) and a role name containing a quote.
-- ============================================================
SELECT letter.grant_scoped('select', 'public.odd_leaf', 'o''brien', ARRAY['Body Text'], 'public."Odd Scope"', ARRAY['Hop Id']);

SELECT letter.read_policy('public.odd_leaf') AS sql \gset
SELECT show_sql(:'sql') AS sql_shown \gset
\echo :sql_shown
CREATE VIEW v_odd WITH (security_barrier) AS :sql;

SET letter.user_id = 'bob';
SELECT id, "Body Text", "select" FROM v_odd ORDER BY id;
SELECT * FROM parity('v_odd', 'public.odd_leaf');

-- ============================================================
-- Fixture 10: `if` — a boolean expression over the row (plan/20 §3).
-- Three rules on notes: editors read the body of non-private notes;
-- editors read everything of their own notes (same role, scope and
-- path, a different if: two rules, two groups — 17 D15); auditors read
-- the kind of public notes, the row named as the table. Parity is
-- against visible_columns() (letter._read() does not evaluate if).
-- ============================================================
CREATE TABLE notes (
    id int PRIMARY KEY,
    project_id uuid REFERENCES projects(id),
    author TEXT,
    body TEXT,
    kind TEXT
);
CREATE INDEX ON notes (project_id);
INSERT INTO notes VALUES
    (1, 'a0000000-0000-0000-0000-000000000001', 'alice', 'mine, private',   'private'),
    (2, 'a0000000-0000-0000-0000-000000000001', 'bob',   'theirs, public',  'public'),
    (3, 'a0000000-0000-0000-0000-000000000001', 'bob',   'theirs, private', 'private'),
    (4, 'a0000000-0000-0000-0000-000000000002', 'alice', 'beta, mine',      'public'),
    (5, 'a0000000-0000-0000-0000-000000000001', 'bob',   'kind unknown',    NULL);
CREATE FUNCTION is_public(n notes) RETURNS boolean LANGUAGE sql IMMUTABLE
    AS $$ SELECT n.kind = 'public' $$;

SELECT letter.grant_scoped('select', 'public.notes', 'editor', ARRAY['body'], 'public.projects',
                           if := 'kind <> ''private''');
SELECT letter.grant_scoped('select', 'public.notes', 'editor', ARRAY['*'], 'public.projects',
                           if := 'author = letter.user_id()');
SELECT letter.grant_global('select', 'public.notes', 'auditor', ARRAY['kind'],
                           if := 'is_public(notes)');
SELECT role, column_name, "if" FROM letter.grants WHERE on_table = 'public.notes'::regclass ORDER BY 1, 2, 3;

SELECT letter.read_policy('public.notes') AS sql \gset
SELECT show_sql(:'sql') AS sql_shown \gset
\echo :sql_shown
CREATE VIEW v_notes WITH (security_barrier) AS :sql;

CREATE FUNCTION vc_parity(v regclass, tbl regclass, OUT mismatches bigint, OUT hidden_rows bigint)
LANGUAGE plpgsql AS $$
BEGIN
    EXECUTE format($q$
        WITH base AS (SELECT x.id, to_jsonb(x) AS j, letter.visible_columns(%L, x.id::text) AS vc FROM %s x),
        expect AS (
            SELECT id, (SELECT jsonb_object_agg(e.key, CASE WHEN e.key = ANY (vc) THEN e.value ELSE 'null'::jsonb END)
                        FROM jsonb_each(j) e) AS j
            FROM base WHERE vc IS NOT NULL),
        vw AS (SELECT x.id, to_jsonb(x) AS j FROM %s x)
        SELECT (SELECT count(*) FROM (SELECT * FROM expect EXCEPT SELECT * FROM vw) a)
             + (SELECT count(*) FROM (SELECT * FROM vw EXCEPT SELECT * FROM expect) b),
               (SELECT count(*) FROM base WHERE vc IS NULL)
    $q$, tbl, tbl, v) INTO mismatches, hidden_rows;
END $$;

SET letter.user_id = 'alice';     -- editor@Alpha: 1 (hers, all columns), 2 (body); 3 private, 4 not editor, 5 kind NULL
SELECT id, author, body, kind FROM v_notes ORDER BY id;
SELECT * FROM vc_parity('v_notes', 'public.notes');
SET letter.user_id = 'bob';       -- viewer@Alpha: no rule
SELECT id, author, body, kind FROM v_notes ORDER BY id;
SELECT * FROM vc_parity('v_notes', 'public.notes');
SET letter.user_id = 'carol';     -- auditor: the kind of public notes
SELECT id, author, body, kind FROM v_notes ORDER BY id;
SELECT * FROM vc_parity('v_notes', 'public.notes');

-- The write path's correlated form carries the same if; the qual selects
-- exactly the rows the barrier shows.
SELECT letter.write_policy('public.notes') AS wsql \gset
SELECT show_sql(:'wsql') AS wsql_shown \gset
\echo :wsql_shown
CREATE FUNCTION if_qual_rows(tbl regclass) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE n bigint;
BEGIN
    EXECUTE format('SELECT count(*) FROM %s b %s', tbl,
                   split_part(letter.write_policy(tbl), E'\n', 1)) INTO n;
    RETURN n;
END $$;
SET letter.user_id = 'alice';
SELECT if_qual_rows('public.notes') AS by_qual, (SELECT count(*) FROM v_notes) AS by_view;
SET letter.user_id = 'carol';
SELECT if_qual_rows('public.notes') AS by_qual, (SELECT count(*) FROM v_notes) AS by_view;
DROP FUNCTION if_qual_rows(regclass);

-- Refused shapes: validated at grant time by analysis in the row's
-- context — not boolean, a subquery, an aggregate, a user function that
-- is not IMMUTABLE, old/new on a select rule, a column of another table
-- on the path, and text that is not one expression.
CREATE FUNCTION flaky() RETURNS boolean LANGUAGE sql STABLE AS $$ SELECT true $$;
\set VERBOSITY terse
SELECT letter.grant_global('select', 'public.notes', 'auditor', ARRAY['body'], if := 'kind');
SELECT letter.grant_global('select', 'public.notes', 'auditor', ARRAY['body'], if := 'EXISTS (SELECT 1)');
SELECT letter.grant_global('select', 'public.notes', 'auditor', ARRAY['body'], if := 'count(*) > 0');
SELECT letter.grant_global('select', 'public.notes', 'auditor', ARRAY['body'], if := 'flaky()');
SELECT letter.grant_global('select', 'public.notes', 'auditor', ARRAY['body'], if := 'old.kind = new.kind');
SELECT letter.grant_scoped('select', 'public.notes', 'auditor', ARRAY['body'], 'public.projects', if := 'name = ''Alpha''');
SELECT letter.grant_global('select', 'public.notes', 'auditor', ARRAY['body'], if := 'true) OR (true');
SELECT letter.grant_global('select', 'public.notes', 'auditor', ARRAY['body'], if := 'true; DROP TABLE notes');
SELECT letter.grant_global('select', 'public.notes', 'auditor', ARRAY['body'], if := 'true FROM projects');
SELECT letter.grant_global('select', 'public.notes', 'auditor', ARRAY['body'], if := 'no_such_column');
\set VERBOSITY default
-- A trailing comment is harmless: the generator puts the expression on its own lines.
SELECT letter.grant_global('select', 'public.notes', 'auditor', ARRAY['body'], if := 'kind = ''public'' -- public only');
SELECT count(*) AS rules FROM letter.grants WHERE on_table = 'public.notes'::regclass;
SELECT letter.read_policy('public.notes') AS sql \gset
CREATE VIEW v_notes_comment WITH (security_barrier) AS :sql;
SET letter.user_id = 'carol';
SELECT id, body, kind FROM v_notes_comment ORDER BY id;
DROP VIEW v_notes_comment;
SELECT letter.revoke_global('select', 'public.notes', 'auditor', ARRAY['body']);
DROP FUNCTION flaky();

-- Lifecycle: an if is revalidated like a path. Renaming a column it names
-- is refused; dropping the column removes the rule with a NOTICE (the rule
-- through is_public() stays — letter cannot see inside a function body,
-- so it is revoked first).
SELECT letter.revoke_global('select', 'public.notes', 'auditor', ARRAY['kind']);
DROP VIEW v_notes;
\set VERBOSITY terse
ALTER TABLE notes RENAME COLUMN kind TO category;
\set VERBOSITY default
ALTER TABLE notes DROP COLUMN kind;
SELECT role, column_name, "if" FROM letter.grants WHERE on_table = 'public.notes'::regclass ORDER BY 1, 2, 3;
DROP FUNCTION is_public(notes);
DROP TABLE notes;

-- ============================================================
-- Fixture 11: the built-in roles (plan/22). anyone reads titles of
-- published pages — with no user set at all; any_user reads bodies too
-- once a user is set, membership or not; editors of the project read
-- everything, drafts included. A table with an anyone grant serves the
-- anonymous session; a table without one (tasks) still errors.
-- ============================================================
CREATE TABLE pages (
    id int PRIMARY KEY,
    project_id uuid REFERENCES projects(id),
    title TEXT,
    body TEXT,
    draft boolean NOT NULL DEFAULT false
);
CREATE INDEX ON pages (project_id);
INSERT INTO pages VALUES
    (1, 'a0000000-0000-0000-0000-000000000001', 'Alpha page',  'alpha body', false),
    (2, 'a0000000-0000-0000-0000-000000000001', 'Alpha draft', 'draft body', true),
    (3, 'a0000000-0000-0000-0000-000000000002', 'Beta page',   'beta body',  false);
SELECT letter.grant_global('select', 'public.pages', 'anyone',   ARRAY['title'],         if := 'NOT draft');
SELECT letter.grant_global('select', 'public.pages', 'any_user', ARRAY['title', 'body'], if := 'NOT draft');
SELECT letter.grant_scoped('select', 'public.pages', 'editor',   ARRAY['*'], 'public.projects');

SELECT letter.read_policy('public.pages') AS sql \gset
SELECT show_sql(:'sql') AS sql_shown \gset
\echo :sql_shown
CREATE VIEW v_pages WITH (security_barrier) AS :sql;

SET letter.user_id = 'alice';     -- editor@Alpha: 1 and 2 in full; 3 as any user
SELECT id, title, body, draft FROM v_pages ORDER BY id;
SET letter.user_id = 'nobody';    -- a user with no membership at all: any_user
SELECT id, title, body, draft FROM v_pages ORDER BY id;
RESET letter.user_id;             -- no user: the anonymous view
SELECT id, title, body, draft FROM v_pages ORDER BY id;
\set VERBOSITY terse
SELECT count(*) FROM v_tasks;     -- no anyone grant on tasks: still an error
\set VERBOSITY default
-- The triggers' view (visible_columns) and the walker (_read) agree with the
-- barrier for all three sessions — anonymous included.
SET letter.user_id = 'alice';
SELECT * FROM vc_parity('v_pages', 'public.pages');
SELECT * FROM parity('v_pages', 'public.pages');
SET letter.user_id = 'nobody';
SELECT * FROM vc_parity('v_pages', 'public.pages');
SELECT * FROM parity('v_pages', 'public.pages');
RESET letter.user_id;
SELECT * FROM vc_parity('v_pages', 'public.pages');
SELECT * FROM parity('v_pages', 'public.pages');
\set VERBOSITY terse
SELECT letter.visible_columns('public.tasks', 'b0000000-0000-0000-0000-000000000001');   -- still an error
\set VERBOSITY default

-- ============================================================
-- Entry criterion (plan/16 §7): nothing user-specific in the text.
-- Generated as a sentinel user who holds a role, the SQL contains
-- neither the user id nor any of that user's scope ids.
-- ============================================================
INSERT INTO letter.memberships (role, user_id, scope_table, scope_id) VALUES
    ('editor', 'SENTINEL-USER', 'public.projects', 'a0000000-0000-0000-0000-000000000002');
SET letter.user_id = 'SENTINEL-USER';

SELECT t.tbl,
       position('SENTINEL' in letter.read_policy(t.tbl)) AS user_id_at,
       (SELECT count(*) FROM letter.memberships r
         WHERE length(r.scope_id) > 8
           AND position(r.scope_id in letter.read_policy(t.tbl)) > 0) AS scope_ids_found
FROM (VALUES ('public.comments'::regclass), ('public.projects'), ('public.reactions')) t(tbl);

RESET letter.user_id;

-- A table with no select grants has no barrier.
SELECT letter.read_policy('public.ungranted') IS NULL AS no_barrier;

-- Cleanup
DROP VIEW v_tasks, v_comments, v_reactions, v_orgs, v_projects, v_memberships, v_odd, v_pages;
DROP FUNCTION parity(regclass, text);
DROP FUNCTION vc_parity(regclass, regclass);
DROP FUNCTION show_sql(text);
DROP TABLE pages, ungranted, odd_leaf, "Odd Hop", "Odd Scope", pair_leaf, pair_scope,
    memberships, reactions, comments, tasks, projects, orgs CASCADE;
DROP EXTENSION letter CASCADE;

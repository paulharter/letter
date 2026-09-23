-- Test: grant and revoke functions

CREATE EXTENSION letter;
SET letter.enforce_reads = off;   -- this test is not about the read hook

-- Configuration is a superuser's (plan/21 D9): any other role is refused,
-- bypass or not.
CREATE ROLE letter_test_nobody;
GRANT USAGE ON SCHEMA letter TO letter_test_nobody;   -- what an application role has
SET ROLE letter_test_nobody;
\set VERBOSITY terse
SELECT letter.grant_global('select', 'pg_class', 'r', ARRAY['*']);
SELECT letter.revoke_global('select', 'pg_class', 'r');
SELECT letter.assign('pg_class', 'relname', role := 'r');
SELECT letter.unassign('pg_class', 'relname', role := 'r');
\set VERBOSITY default
RESET ROLE;
REVOKE USAGE ON SCHEMA letter FROM letter_test_nobody;
DROP ROLE letter_test_nobody;

-- The built-in roles anyone and any_user (plan/22 A1): global only, never a
-- membership row, never conferred by a rule; granted like any role globally.
CREATE TABLE public_pages (id int PRIMARY KEY, body text);
\set VERBOSITY terse
SELECT letter.grant_scoped('select', 'public.public_pages', 'anyone', ARRAY['*'], 'public.public_pages');
SELECT letter.grant_scoped('select', 'public.public_pages', 'any_user', ARRAY['*'], 'public.public_pages');
INSERT INTO letter.memberships (role, user_id) VALUES ('anyone', 'someone');
INSERT INTO letter.memberships (role, user_id) VALUES ('any_user', 'someone');
SET letter.bypass = on;
SELECT letter.assign('public.public_pages', 'body', role := 'anyone');
SELECT letter.assign('public.public_pages', 'body', role := 'any_user');
RESET letter.bypass;
\set VERBOSITY default
SELECT letter.grant_global('select', 'public.public_pages', 'anyone', ARRAY['*']);
SELECT letter.grant_global('insert', 'public.public_pages', 'any_user', if := 'id > 0');
SELECT role, privilege, column_name, "if" FROM letter.grants WHERE on_table = 'public.public_pages'::regclass ORDER BY 1, 2;
SELECT letter.revoke_global('select', 'public.public_pages', 'anyone');
SELECT letter.revoke_global('insert', 'public.public_pages', 'any_user');
DROP TABLE public_pages;

-- insert and delete are row-level (plan/21 D14): a column list is refused,
-- ARRAY['*'] and no list are the same thing.
CREATE TABLE rows_only (id int PRIMARY KEY, body text);
\set VERBOSITY terse
SELECT letter.grant_global('insert', 'public.rows_only', 'r', ARRAY['body']);
SELECT letter.grant_scoped('delete', 'public.rows_only', 'r', ARRAY['body'], 'public.rows_only');
\set VERBOSITY default
SELECT letter.grant_global('insert', 'public.rows_only', 'r');
SELECT letter.grant_global('insert', 'public.rows_only', 'r', ARRAY['*']);      -- the same rule
SELECT count(*) AS rules FROM letter.grants WHERE on_table = 'public.rows_only'::regclass;
DROP TABLE rows_only;

-- A grant names one of the five privileges and columns that exist (plan/24
-- B2): a misspelt privilege would be stored and never enforced, a wrong
-- column would break the next unrelated ALTER TABLE. Nothing is stored.
CREATE TABLE checked (id int PRIMARY KEY, body text);
\set VERBOSITY terse
SELECT letter.grant_global('slect', 'public.checked', 'r', ARRAY['body']);
SELECT letter.grant_global('select', 'public.checked', 'r', ARRAY['body', 'no_such']);
SELECT letter.grant_global('select', 'public.checked', 'r', ARRAY['body', NULL]);
INSERT INTO letter.grants (privilege, on_table, role, column_name, scope)
    VALUES ('slect', 'public.checked'::regclass, 'r', '*', 0);        -- the table says so too
-- the plumbing is not STRICT, so it checks what it needs (plan/24 D)
SELECT letter._grant(NULL, 'public.checked', 'r', ARRAY['*']);
SELECT letter._revoke('select', 'public.checked', NULL, ARRAY['*']);
SET letter.bypass = on;
SELECT letter._assign(NULL, 'body');
RESET letter.bypass;
\set VERBOSITY default
SELECT count(*) AS stored FROM letter.grants WHERE on_table = 'public.checked'::regclass;
SELECT count(*) AS triggers FROM pg_trigger WHERE tgrelid = 'public.checked'::regclass;
DROP TABLE checked;

-- A scope or hop table needs a single-column primary key (plan/17 D4; no
-- key at all refused since plan/24): a unique column is enough for the
-- foreign key but not for letter.
CREATE TABLE keyless (id int UNIQUE, name text);
CREATE TABLE keyless_leaf (id int PRIMARY KEY, keyless_id int REFERENCES keyless(id), body text);
\set VERBOSITY terse
SELECT letter.grant_scoped('select', 'public.keyless_leaf', 'r', ARRAY['body'], 'public.keyless');
\set VERBOSITY default
DROP TABLE keyless_leaf, keyless;

-- Tables are regclass (plan/18 D1): letter.grant_global() refuses one that does
-- not exist (plan/17 D10) and handles names that need quoting.
CREATE TABLE orgs (id uuid PRIMARY KEY DEFAULT gen_random_uuid());
CREATE TABLE projects (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id uuid REFERENCES orgs(id),
    alt_org_id uuid REFERENCES orgs(id),
    name TEXT,
    description TEXT,
    status TEXT
);
CREATE TABLE documents (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT
);

-- grant a single column privilege
SELECT letter.grant_global('select', 'public.projects', 'admin', ARRAY['name']);

SELECT privilege, on_table, role, column_name, scope, via, if
    FROM letter.grants ORDER BY column_name;

-- grant multiple columns in one call
SELECT letter.grant_global('select', 'public.projects', 'admin', ARRAY['description', 'status']);

SELECT privilege, on_table, role, column_name, scope
    FROM letter.grants ORDER BY column_name;

-- grant with via and if
SELECT letter.grant_scoped('update', 'public.projects', 'member', ARRAY['status'], 'public.orgs', ARRAY['org_id'], 'status <> ''archived''');

SELECT privilege, on_table, role, column_name, scope, via, if
    FROM letter.grants WHERE role = 'member';

-- a grant's identity is the whole rule (plan/17 D15): the same rule again is
-- one rule; a rule that differs in its path is another rule alongside it
SELECT letter.grant_scoped('update', 'public.projects', 'member', ARRAY['status'], 'public.orgs', ARRAY['org_id'], 'status <> ''archived''');
SELECT letter.grant_scoped('update', 'public.projects', 'member', ARRAY['status'], 'public.orgs', ARRAY['alt_org_id'], 'status <> ''archived''');

SELECT privilege, on_table, role, column_name, scope, via, if
    FROM letter.grants WHERE role = 'member' ORDER BY via;

-- revoke removes every rule under its key
SELECT letter.revoke_scoped('update', 'public.projects', 'member', ARRAY['status'], 'public.orgs');
SELECT count(*) FROM letter.grants WHERE role = 'member';

-- grant with wildcard '*' means all columns (sentinel value)
SELECT letter.grant_global('select', 'public.documents', 'viewer', ARRAY['*']);

SELECT privilege, on_table, role, column_name, scope
    FROM letter.grants WHERE on_table = 'public.documents'::regclass;

-- wildcard grant can coexist with column-specific grants on different tables
SELECT count(*) FROM letter.grants;

-- revoke wildcard grant
SELECT letter.revoke_global('select', 'public.documents', 'viewer');

SELECT count(*) FROM letter.grants WHERE on_table = 'public.documents'::regclass;

-- revoke specific columns
SELECT letter.revoke_global('select', 'public.projects', 'admin', ARRAY['name']);

SELECT privilege, on_table, role, column_name, scope
    FROM letter.grants WHERE privilege = 'select' ORDER BY column_name;

-- revoke with wildcard removes all columns for that grant
SELECT letter.revoke_global('select', 'public.projects', 'admin');

SELECT count(*) FROM letter.grants WHERE privilege = 'select' AND role = 'admin';

-- revoke non-existent grant is a no-op
SELECT letter.revoke_global('delete', 'public.projects', 'nobody');

-- via FK validation: create real tables and verify
CREATE TABLE scope_parent (id uuid PRIMARY KEY DEFAULT gen_random_uuid());
CREATE TABLE scope_child (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_id uuid NOT NULL REFERENCES scope_parent(id),
    plain_col TEXT
);

-- valid: parent_id is an FK
SELECT letter.grant_scoped('select', 'public.scope_child', 'r', ARRAY['plain_col'], 'public.scope_parent', ARRAY['parent_id']);

-- invalid: plain_col is not an FK
\set VERBOSITY terse
SELECT letter.grant_scoped('select', 'public.scope_child', 'r', ARRAY['plain_col'], 'public.scope_parent', ARRAY['plain_col']);

-- invalid: no_such_column doesn't exist
SELECT letter.grant_scoped('select', 'public.scope_child', 'r', ARRAY['plain_col'], 'public.scope_parent', ARRAY['no_such_column']);

-- a grant on a table that doesn't exist is refused (regclass resolution),
-- scoped or not — and nothing is stored
SELECT letter.grant_scoped('select', 'public.future_table', 'r', ARRAY['x'], 'public.scope_parent', ARRAY['anything']);
SELECT letter.grant_global('insert', 'public.future_table', 'r');
\set VERBOSITY default

SELECT count(*) FROM letter.grants;

-- a table whose name needs quoting: grant installs triggers, revoke removes them
CREATE TABLE "Mixed Leaf" (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), "Some Col" TEXT);
SELECT letter.grant_global('select', 'public."Mixed Leaf"', 'r', ARRAY['Some Col']);
SELECT tgname FROM pg_trigger WHERE tgrelid = '"Mixed Leaf"'::regclass ORDER BY 1;
SELECT on_table, column_name FROM letter.grants WHERE on_table = '"Mixed Leaf"'::regclass;
SELECT letter.revoke_global('select', 'public."Mixed Leaf"', 'r');
SELECT count(*) FROM pg_trigger WHERE tgrelid = '"Mixed Leaf"'::regclass;
DROP TABLE "Mixed Leaf";

DROP TABLE scope_child;
DROP TABLE scope_parent;
DROP TABLE documents;
DROP TABLE projects;
DROP TABLE orgs;

-- clean up
DROP EXTENSION letter CASCADE;

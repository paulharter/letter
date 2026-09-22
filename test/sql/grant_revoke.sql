-- Test: grant and revoke functions

CREATE EXTENSION letter;
SET letter.enforce_reads = off;   -- this test is not about the read hook

-- Tables are regclass (plan/18 D1): letter.grant() refuses one that does
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
SELECT letter.grant('select', 'public.projects', 'admin', ARRAY['name'], NULL, NULL, NULL);

SELECT privilege, on_table, role, column_name, scope, using_path, check_fn
    FROM letter.grants ORDER BY column_name;

-- grant multiple columns in one call
SELECT letter.grant('select', 'public.projects', 'admin', ARRAY['description', 'status'], NULL, NULL, NULL);

SELECT privilege, on_table, role, column_name, scope
    FROM letter.grants ORDER BY column_name;

-- grant with using_path and check_fn
SELECT letter.grant('update', 'public.projects', 'member', ARRAY['status'], 'public.orgs', ARRAY['org_id'], 'is_active()');

SELECT privilege, on_table, role, column_name, scope, using_path, check_fn
    FROM letter.grants WHERE role = 'member';

-- upsert: granting same privilege again updates using_path and check_fn
SELECT letter.grant('update', 'public.projects', 'member', ARRAY['status'], 'public.orgs', ARRAY['alt_org_id'], 'new_check()');

SELECT privilege, on_table, role, column_name, scope, using_path, check_fn
    FROM letter.grants WHERE role = 'member';

-- grant with wildcard '*' means all columns (sentinel value)
SELECT letter.grant('select', 'public.documents', 'viewer', ARRAY['*'], NULL, NULL, NULL);

SELECT privilege, on_table, role, column_name, scope
    FROM letter.grants WHERE on_table = 'public.documents'::regclass;

-- wildcard grant can coexist with column-specific grants on different tables
SELECT count(*) FROM letter.grants;

-- revoke wildcard grant
SELECT letter.revoke('select', 'public.documents', 'viewer', ARRAY['*'], NULL);

SELECT count(*) FROM letter.grants WHERE on_table = 'public.documents'::regclass;

-- revoke specific columns
SELECT letter.revoke('select', 'public.projects', 'admin', ARRAY['name'], NULL);

SELECT privilege, on_table, role, column_name, scope
    FROM letter.grants WHERE privilege = 'select' ORDER BY column_name;

-- revoke with wildcard removes all columns for that grant
SELECT letter.revoke('select', 'public.projects', 'admin', ARRAY['*'], NULL);

SELECT count(*) FROM letter.grants WHERE privilege = 'select' AND role = 'admin';

-- revoke non-existent grant is a no-op
SELECT letter.revoke('delete', 'public.projects', 'nobody', ARRAY['*'], NULL);

-- using_path FK validation: create real tables and verify
CREATE TABLE scope_parent (id uuid PRIMARY KEY DEFAULT gen_random_uuid());
CREATE TABLE scope_child (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_id uuid NOT NULL REFERENCES scope_parent(id),
    plain_col TEXT
);

-- valid: parent_id is an FK
SELECT letter.grant('select', 'public.scope_child', 'r', ARRAY['plain_col'],
    'public.scope_parent', ARRAY['parent_id'], NULL);

-- invalid: plain_col is not an FK
\set VERBOSITY terse
SELECT letter.grant('select', 'public.scope_child', 'r', ARRAY['plain_col'],
    'public.scope_parent', ARRAY['plain_col'], NULL);

-- invalid: no_such_column doesn't exist
SELECT letter.grant('select', 'public.scope_child', 'r', ARRAY['plain_col'],
    'public.scope_parent', ARRAY['no_such_column'], NULL);

-- a grant on a table that doesn't exist is refused (regclass resolution),
-- scoped or not — and nothing is stored
SELECT letter.grant('select', 'public.future_table', 'r', ARRAY['x'],
    'public.scope_parent', ARRAY['anything'], NULL);
SELECT letter.grant('insert', 'public.future_table', 'r', ARRAY['*'], NULL, NULL, NULL);
\set VERBOSITY default

SELECT count(*) FROM letter.grants;

-- a table whose name needs quoting: grant installs triggers, revoke removes them
CREATE TABLE "Mixed Leaf" (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), "Some Col" TEXT);
SELECT letter.grant('select', 'public."Mixed Leaf"', 'r', ARRAY['Some Col']);
SELECT tgname FROM pg_trigger WHERE tgrelid = '"Mixed Leaf"'::regclass ORDER BY 1;
SELECT on_table, column_name FROM letter.grants WHERE on_table = '"Mixed Leaf"'::regclass;
SELECT letter.revoke('select', 'public."Mixed Leaf"', 'r', ARRAY['*']);
SELECT count(*) FROM pg_trigger WHERE tgrelid = '"Mixed Leaf"'::regclass;
DROP TABLE "Mixed Leaf";

DROP TABLE scope_child;
DROP TABLE scope_parent;
DROP TABLE documents;
DROP TABLE projects;
DROP TABLE orgs;

-- clean up
DROP EXTENSION letter CASCADE;

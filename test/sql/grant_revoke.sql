-- Test: grant and revoke functions

CREATE EXTENSION letter;

-- grant a single column privilege
SELECT letter.grant('select', 'public.projects', 'admin', ARRAY['name'], '', NULL, NULL);

SELECT privilege, on_table, role, column_name, scope, using_path, check_fn
    FROM letter.grants ORDER BY column_name;

-- grant multiple columns in one call
SELECT letter.grant('select', 'public.projects', 'admin', ARRAY['description', 'status'], '', NULL, NULL);

SELECT privilege, on_table, role, column_name, scope
    FROM letter.grants ORDER BY column_name;

-- grant with using_path and check_fn
SELECT letter.grant('update', 'public.projects', 'member', ARRAY['status'], 'public.projects', ARRAY['project_id'], 'is_active()');

SELECT privilege, on_table, role, column_name, scope, using_path, check_fn
    FROM letter.grants WHERE role = 'member';

-- upsert: granting same privilege again updates using_path and check_fn
SELECT letter.grant('update', 'public.projects', 'member', ARRAY['status'], 'public.projects', ARRAY['new_path'], 'new_check()');

SELECT privilege, on_table, role, column_name, scope, using_path, check_fn
    FROM letter.grants WHERE role = 'member';

-- grant with wildcard '*' means all columns (sentinel value)
SELECT letter.grant('select', 'public.documents', 'viewer', ARRAY['*'], '', NULL, NULL);

SELECT privilege, on_table, role, column_name, scope
    FROM letter.grants WHERE on_table = 'public.documents';

-- wildcard grant can coexist with column-specific grants on different tables
SELECT count(*) FROM letter.grants;

-- revoke wildcard grant
SELECT letter.revoke('select', 'public.documents', 'viewer', ARRAY['*'], '');

SELECT count(*) FROM letter.grants WHERE on_table = 'public.documents';

-- revoke specific columns
SELECT letter.revoke('select', 'public.projects', 'admin', ARRAY['name'], '');

SELECT privilege, on_table, role, column_name, scope
    FROM letter.grants WHERE privilege = 'select' ORDER BY column_name;

-- revoke with wildcard removes all columns for that grant
SELECT letter.revoke('select', 'public.projects', 'admin', ARRAY['*'], '');

SELECT count(*) FROM letter.grants WHERE privilege = 'select' AND role = 'admin';

-- revoke non-existent grant is a no-op
SELECT letter.revoke('delete', 'public.projects', 'nobody', ARRAY['*'], '');

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
\set VERBOSITY default

-- validation is skipped when the target table doesn't exist yet
SELECT letter.grant('select', 'public.future_table', 'r', ARRAY['x'],
    'public.scope_parent', ARRAY['anything'], NULL);

DROP TABLE scope_child;
DROP TABLE scope_parent;

-- clean up
DROP EXTENSION letter CASCADE;

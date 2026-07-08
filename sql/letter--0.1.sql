-- letter: role-based access control extension

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION letter" to load this file. \quit

-- Core tables

CREATE TABLE letter.roles (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    role VARCHAR(64) NOT NULL,
    user_id VARCHAR(256) NOT NULL,
    scope_table VARCHAR(64),
    scope_id VARCHAR(256)
);

CREATE TABLE letter.grants (
    privilege VARCHAR(20) NOT NULL,
    on_table VARCHAR(64) NOT NULL,
    role VARCHAR(64) NOT NULL,
    column_name VARCHAR(64) NOT NULL,
    scope VARCHAR(64) NOT NULL,
    using_path TEXT[],
    check_fn TEXT,
    CONSTRAINT grants_pkey PRIMARY KEY (privilege, on_table, role, scope, column_name)
);

CREATE TABLE letter.assignments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    table_name VARCHAR(64) NOT NULL,
    scope_table VARCHAR(64),
    user_column VARCHAR(64) NOT NULL,
    role_name VARCHAR(64),
    role_column VARCHAR(64),
    if_fn TEXT,
    CONSTRAINT unique_assign UNIQUE (table_name, scope_table, user_column, role_name, role_column),
    CONSTRAINT role_name_or_column CHECK (
        (role_name IS NOT NULL AND role_column IS NULL) OR
        (role_name IS NULL AND role_column IS NOT NULL)
    )
);

CREATE TABLE letter.role_assignments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    assignment_id uuid NOT NULL REFERENCES letter.assignments(id) ON DELETE CASCADE,
    role_id uuid NOT NULL REFERENCES letter.roles(id),
    source_table VARCHAR(64) NOT NULL,
    source_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    scope_table VARCHAR(64),
    scope_id TEXT
);

-- Indexes for enforcement query performance
CREATE INDEX roles_user_id_idx ON letter.roles (user_id);
CREATE INDEX roles_role_idx ON letter.roles (role);
CREATE INDEX grants_on_table_role_idx ON letter.grants (on_table, role);

-- Cleanup trigger: when a role_assignment is deleted, remove the associated role
CREATE FUNCTION letter.role_cleanup() RETURNS trigger
AS 'MODULE_PATHNAME', 'letter_role_cleanup'
LANGUAGE C;

-- Session-cache invalidation: any write to roles or grants invalidates this
-- backend's cache, so role changes made by assignment triggers take effect
-- immediately.
CREATE FUNCTION letter.cache_inval() RETURNS trigger
AS 'MODULE_PATHNAME', 'letter_cache_inval'
LANGUAGE C;

CREATE TRIGGER roles_cache_inval
    AFTER INSERT OR UPDATE OR DELETE ON letter.roles
    FOR EACH STATEMENT
    EXECUTE FUNCTION letter.cache_inval();

CREATE TRIGGER grants_cache_inval
    AFTER INSERT OR UPDATE OR DELETE ON letter.grants
    FOR EACH STATEMENT
    EXECUTE FUNCTION letter.cache_inval();

-- Enforcement trigger functions (generic, installed on protected tables by grant/revoke)
CREATE FUNCTION letter.enforce_insert() RETURNS trigger
AS 'MODULE_PATHNAME', 'letter_enforce_insert'
LANGUAGE C;

CREATE FUNCTION letter.enforce_update() RETURNS trigger
AS 'MODULE_PATHNAME', 'letter_enforce_update'
LANGUAGE C;

CREATE FUNCTION letter.enforce_delete() RETURNS trigger
AS 'MODULE_PATHNAME', 'letter_enforce_delete'
LANGUAGE C;

CREATE TRIGGER role_assignment_cleanup
    AFTER DELETE ON letter.role_assignments
    FOR EACH ROW
    EXECUTE FUNCTION letter.role_cleanup();

-- Functions

CREATE FUNCTION letter.grant(
    privilege text,
    on_table text,
    role text,
    columns text[],
    scope text,
    using_path text[] DEFAULT NULL,
    check_fn text DEFAULT NULL
) RETURNS boolean
AS 'MODULE_PATHNAME', 'letter_grant'
LANGUAGE C VOLATILE;

CREATE FUNCTION letter.revoke(
    privilege text,
    on_table text,
    role text,
    columns text[],
    scope text
) RETURNS boolean
AS 'MODULE_PATHNAME', 'letter_revoke'
LANGUAGE C STRICT VOLATILE;

CREATE FUNCTION letter.assign(
    source_table text,
    user_column text,
    scope_table text DEFAULT NULL,
    role_name text DEFAULT NULL,
    role_column text DEFAULT NULL,
    if_fn text DEFAULT NULL
) RETURNS boolean
AS 'MODULE_PATHNAME', 'letter_assign'
LANGUAGE C VOLATILE;

CREATE FUNCTION letter.unassign(
    source_table text,
    user_column text,
    scope_table text DEFAULT NULL,
    role_name text DEFAULT NULL,
    role_column text DEFAULT NULL
) RETURNS boolean
AS 'MODULE_PATHNAME', 'letter_unassign'
LANGUAGE C VOLATILE;

-- Read enforcement

CREATE FUNCTION letter.read(
    table_name text,
    condition text DEFAULT NULL
) RETURNS SETOF jsonb
AS 'MODULE_PATHNAME', 'letter_read'
LANGUAGE C VOLATILE;

-- Info/debug functions

CREATE FUNCTION letter.list_grants(filter_role text DEFAULT NULL)
RETURNS TABLE (
    role VARCHAR(64),
    privilege VARCHAR(20),
    on_table VARCHAR(64),
    column_name VARCHAR(64),
    scope VARCHAR(64),
    using_path TEXT[],
    check_fn TEXT
) AS $$
    SELECT g.role, g.privilege, g.on_table, g.column_name, g.scope, g.using_path, g.check_fn
    FROM letter.grants g
    WHERE (filter_role IS NULL OR g.role = filter_role);
$$ LANGUAGE SQL STABLE;

CREATE FUNCTION letter.user_permissions(p_user_id text)
RETURNS TABLE (
    role VARCHAR(64),
    privilege VARCHAR(20),
    on_table VARCHAR(64),
    column_name VARCHAR(64),
    scope VARCHAR(64),
    scope_table VARCHAR(64),
    scope_id VARCHAR(256),
    using_path TEXT[],
    check_fn TEXT
) AS $$
    SELECT r.role, g.privilege, g.on_table, g.column_name, g.scope,
           r.scope_table, r.scope_id, g.using_path, g.check_fn
    FROM letter.roles r
    JOIN letter.grants g ON g.role = r.role
        AND (
            -- Scoped grant: scope matches the role's scope_table
            g.scope = r.scope_table
            -- Unscoped grant: applies to anyone with the role
            OR g.scope = ''
        )
    WHERE r.user_id = p_user_id;
$$ LANGUAGE SQL STABLE;

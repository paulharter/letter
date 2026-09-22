-- letter: role-based access control extension

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION letter" to load this file. \quit

-- Core tables

CREATE TABLE letter.roles (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    role VARCHAR(64) NOT NULL,
    user_id VARCHAR(256) NOT NULL CHECK (user_id <> ''),
    scope_table regclass,               -- NULL = the global scope
    scope_id VARCHAR(256)
);

CREATE TABLE letter.grants (
    privilege VARCHAR(20) NOT NULL,
    on_table regclass NOT NULL,
    role VARCHAR(64) NOT NULL,
    column_name VARCHAR(64) NOT NULL,
    scope regclass NOT NULL,            -- 0 = unscoped
    using_path TEXT[],
    check_fn TEXT,
    CONSTRAINT grants_pkey PRIMARY KEY (privilege, on_table, role, scope, column_name)
);

CREATE TABLE letter.assignments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    table_name regclass NOT NULL,
    scope_table regclass,
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
    source_table regclass NOT NULL,
    source_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    scope_table regclass,
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

-- An empty table whose only purpose is to carry a relcache invalidation
-- (plan/17 H4): the roles trigger invalidates it, and every backend's
-- session cache follows, without invalidating the rewritten plans, which
-- depend on letter.grants but not on role rows.
CREATE TABLE letter.roles_epoch ();

-- Session-cache invalidation: any write to roles or grants invalidates this
-- backend's cache at once and, through the relcache, every other backend's
-- at commit; a grants write also invalidates every rewritten plan.
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

CREATE FUNCTION letter.enforce_truncate() RETURNS trigger
AS 'MODULE_PATHNAME', 'letter_enforce_truncate'
LANGUAGE C;

-- Lifecycle (plan/18 §3): drop cascades, alter refuses.
CREATE FUNCTION letter.on_sql_drop() RETURNS event_trigger
AS 'MODULE_PATHNAME', 'letter_on_sql_drop'
LANGUAGE C;

CREATE FUNCTION letter.on_ddl_command_end() RETURNS event_trigger
AS 'MODULE_PATHNAME', 'letter_on_ddl_command_end'
LANGUAGE C;

CREATE EVENT TRIGGER letter_sql_drop ON sql_drop
    EXECUTE FUNCTION letter.on_sql_drop();

CREATE EVENT TRIGGER letter_ddl_command_end ON ddl_command_end
    WHEN TAG IN ('ALTER TABLE')
    EXECUTE FUNCTION letter.on_ddl_command_end();

CREATE TRIGGER role_assignment_cleanup
    AFTER DELETE ON letter.role_assignments
    FOR EACH ROW
    EXECUTE FUNCTION letter.role_cleanup();

-- Functions

-- Tables are identified by OID (regclass): a grant follows its table through
-- renames. scope NULL = unscoped (stored as 0).
CREATE FUNCTION letter.grant(
    privilege text,
    on_table regclass,
    role text,
    columns text[],
    scope regclass DEFAULT NULL,
    using_path text[] DEFAULT NULL,
    check_fn text DEFAULT NULL
) RETURNS boolean
AS 'MODULE_PATHNAME', 'letter_grant'
LANGUAGE C VOLATILE;

CREATE FUNCTION letter.revoke(
    privilege text,
    on_table regclass,
    role text,
    columns text[],
    scope regclass DEFAULT NULL
) RETURNS boolean
AS 'MODULE_PATHNAME', 'letter_revoke'
LANGUAGE C VOLATILE;

-- assign/unassign are admin operations: they require letter.bypass = on
-- (plan/17 D13).
CREATE FUNCTION letter.assign(
    source_table regclass,
    user_column text,
    scope_table regclass DEFAULT NULL,
    role_name text DEFAULT NULL,
    role_column text DEFAULT NULL,
    if_fn text DEFAULT NULL
) RETURNS boolean
AS 'MODULE_PATHNAME', 'letter_assign'
LANGUAGE C VOLATILE;

CREATE FUNCTION letter.unassign(
    source_table regclass,
    user_column text,
    scope_table regclass DEFAULT NULL,
    role_name text DEFAULT NULL,
    role_column text DEFAULT NULL
) RETURNS boolean
AS 'MODULE_PATHNAME', 'letter_unassign'
LANGUAGE C VOLATILE;

-- Read enforcement

-- The columns of one row that the current user may read, or NULL if the
-- row is not visible to them: the in-band way to tell a hidden column from
-- a NULL one (plan/17 D3).
CREATE FUNCTION letter.visible_columns(rel regclass, pk anyelement) RETURNS text[]
AS 'MODULE_PATHNAME', 'letter_visible_columns'
LANGUAGE C STABLE STRICT;

-- DEPRECATED (plan/17 D3, 2026-09-22): plain SELECT is the enforced read.
-- letter.read() predates the planner hook, returns strings, and its raw
-- condition is evaluated against true values. Kept for parity tests; will
-- be removed.
CREATE FUNCTION letter.read(
    table_name text,
    condition text DEFAULT NULL
) RETURNS SETOF jsonb
AS 'MODULE_PATHNAME', 'letter_read'
LANGUAGE C VOLATILE;

-- Info/debug functions

-- Debugging aid: the redacting subquery the planner hook substitutes for a
-- protected table (NULL if the table has no select grants).
CREATE FUNCTION letter.barrier_sql(rel regclass) RETURNS text
AS 'MODULE_PATHNAME', 'letter_barrier_sql'
LANGUAGE C STABLE STRICT;

-- Health check (plan/18 I4). Severity: error (enforcement is not what the
-- catalogue says), warning (works, but not as intended), info.
CREATE FUNCTION letter._problems()
RETURNS TABLE (severity text, object text, message text)
AS 'MODULE_PATHNAME', 'letter_problems'
LANGUAGE C VOLATILE;

CREATE FUNCTION letter._qualname(rel oid) RETURNS text
LANGUAGE sql STABLE AS $$
    SELECT n.nspname || '.' || c.relname
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = rel
$$;

CREATE FUNCTION letter.check_health()
RETURNS TABLE (severity text, object text, message text)
LANGUAGE sql VOLATILE AS $$
    WITH preload AS (
        SELECT string_to_array(replace(current_setting('shared_preload_libraries'), ' ', ''), ',')
            || string_to_array(replace(current_setting('session_preload_libraries'), ' ', ''), ',') AS libs
    ),
    assignment AS (
        SELECT a.*, replace(a.id::text, '-', '_') AS safe_id,
               EXISTS (SELECT 1 FROM pg_class WHERE oid = a.table_name) AS source_exists
        FROM letter.assignments a
    )
    -- deployment
    SELECT 'warning', 'library',
           'letter is not in shared_preload_libraries or session_preload_libraries: a session that never calls a letter function has no planner hook, so read enforcement does not apply to it'
    FROM preload WHERE NOT ('letter' = ANY (libs))
    UNION ALL
    SELECT 'info', 'letter.enforce_reads', 'read enforcement is switched off'
    WHERE current_setting('letter.enforce_reads') = 'off'
    UNION ALL
    SELECT 'info', 'role ' || r.rolname, 'has letter.bypass = on by default'
    FROM pg_db_role_setting s JOIN pg_roles r ON r.oid = s.setrole
    WHERE s.setconfig @> ARRAY['letter.bypass=on']
    UNION ALL
    -- grants
    SELECT 'error', 'grant ' || g.role || '/' || g.privilege,
           'refers to a table that no longer exists (OID ' || g.on_table::oid || ')'
    FROM letter.grants g WHERE NOT EXISTS (SELECT 1 FROM pg_class WHERE oid = g.on_table)
    UNION ALL
    SELECT 'error', 'grant ' || g.role || '/' || g.privilege || ' on ' || letter._qualname(g.on_table),
           'is scoped to a table that no longer exists (OID ' || g.scope::oid || ')'
    FROM letter.grants g
    WHERE g.scope <> 0 AND EXISTS (SELECT 1 FROM pg_class WHERE oid = g.on_table)
      AND NOT EXISTS (SELECT 1 FROM pg_class WHERE oid = g.scope)
    UNION ALL
    -- enforcement triggers
    SELECT 'error', 'table ' || letter._qualname(t.on_table), 'has grants but no ' || tg.name || ' trigger'
    FROM (SELECT DISTINCT g.on_table FROM letter.grants g
          WHERE EXISTS (SELECT 1 FROM pg_class WHERE oid = g.on_table)) t
    CROSS JOIN (VALUES ('letter_enforce_insert'), ('letter_enforce_update'),
                       ('letter_enforce_delete'), ('letter_enforce_truncate')) tg(name)
    WHERE NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = t.on_table AND tgname = tg.name)
    UNION ALL
    SELECT 'warning', 'table ' || letter._qualname(tr.tgrelid),
           'has enforcement trigger ' || tr.tgname || ' but no grants'
    FROM pg_trigger tr
    WHERE tr.tgname LIKE 'letter\_enforce\_%'
      AND NOT EXISTS (SELECT 1 FROM letter.grants g WHERE g.on_table = tr.tgrelid)
    UNION ALL
    SELECT 'warning', 'table ' || letter._qualname(tr.tgrelid), 'letter trigger ' || tr.tgname || ' is disabled'
    FROM pg_trigger tr WHERE tr.tgname LIKE 'letter\_%' AND tr.tgenabled = 'D'
    UNION ALL
    -- assignments
    SELECT 'error', 'assignment ' || a.id::text, 'source table no longer exists (OID ' || a.table_name::oid || ')'
    FROM assignment a WHERE NOT a.source_exists
    UNION ALL
    SELECT 'error', 'assignment on ' || letter._qualname(a.table_name),
           'scope table no longer exists (OID ' || a.scope_table::oid || ')'
    FROM assignment a
    WHERE a.source_exists AND a.scope_table IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM pg_class WHERE oid = a.scope_table)
    UNION ALL
    SELECT 'error', 'assignment on ' || letter._qualname(a.table_name), 'is missing function letter.' || f.name
    FROM assignment a
    CROSS JOIN LATERAL (VALUES ('source_upsert_' || a.safe_id), ('source_delete_' || a.safe_id)) f(name)
    WHERE a.source_exists
      AND NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                      WHERE n.nspname = 'letter' AND p.proname = f.name)
    UNION ALL
    SELECT 'error', 'assignment on ' || letter._qualname(a.table_name), 'is missing trigger ' || tg.name
    FROM assignment a
    CROSS JOIN LATERAL (VALUES ('letter_insert_' || a.safe_id), ('letter_update_' || a.safe_id),
                               ('letter_delete_' || a.safe_id)) tg(name)
    WHERE a.source_exists
      AND NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = a.table_name AND tgname = tg.name)
    UNION ALL
    -- roles
    SELECT 'error', 'role ' || r.role || ' of ' || r.user_id,
           'is scoped to a table that no longer exists (OID ' || r.scope_table::oid || ')'
    FROM letter.roles r
    WHERE r.scope_table IS NOT NULL AND NOT EXISTS (SELECT 1 FROM pg_class WHERE oid = r.scope_table)
    UNION ALL
    SELECT 'info', 'roles', count(*) || ' role row(s) are managed directly, not by an assignment'
    FROM letter.roles r
    WHERE NOT EXISTS (SELECT 1 FROM letter.role_assignments ra WHERE ra.role_id = r.id)
    HAVING count(*) > 0
    UNION ALL
    -- validation and index coverage
    SELECT DISTINCT p.severity, p.object, p.message FROM letter._problems() p;
$$;

CREATE FUNCTION letter.list_grants(filter_role text DEFAULT NULL)
RETURNS TABLE (
    role VARCHAR(64),
    privilege VARCHAR(20),
    on_table regclass,
    column_name VARCHAR(64),
    scope regclass,
    using_path TEXT[],
    check_fn TEXT
) AS $$
    SELECT g.role, g.privilege, g.on_table, g.column_name,
           NULLIF(g.scope, 0), g.using_path, g.check_fn
    FROM letter.grants g
    WHERE (filter_role IS NULL OR g.role = filter_role);
$$ LANGUAGE SQL STABLE;

CREATE FUNCTION letter.user_permissions(p_user_id text)
RETURNS TABLE (
    role VARCHAR(64),
    privilege VARCHAR(20),
    on_table regclass,
    column_name VARCHAR(64),
    scope regclass,
    scope_table regclass,
    scope_id VARCHAR(256),
    using_path TEXT[],
    check_fn TEXT
) AS $$
    SELECT r.role, g.privilege, g.on_table, g.column_name, NULLIF(g.scope, 0),
           r.scope_table, r.scope_id, g.using_path, g.check_fn
    FROM letter.roles r
    JOIN letter.grants g ON g.role = r.role
        AND (
            -- Scoped grant: scope matches the role's scope_table
            g.scope = r.scope_table
            -- Unscoped grant: the role held in the global scope (plan/17 D11)
            OR (g.scope = 0 AND r.scope_table IS NULL)
        )
    WHERE r.user_id = p_user_id;
$$ LANGUAGE SQL STABLE;

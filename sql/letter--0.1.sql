-- letter: relationship-based access control extension

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION letter" to load this file. \quit

-- Core tables

CREATE TABLE letter.memberships (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- anyone and any_user are held by everyone (plan/22): never a membership row
    role VARCHAR(64) NOT NULL CHECK (role NOT IN ('anyone', 'any_user')),
    user_id VARCHAR(256) NOT NULL CHECK (user_id <> ''),
    scope_table regclass,               -- NULL = the global scope
    scope_id VARCHAR(256)
);

CREATE TABLE letter.grants (
    privilege VARCHAR(20) NOT NULL CHECK (privilege IN ('select', 'insert', 'update', 'delete', 'fill')),
    on_table regclass NOT NULL,
    role VARCHAR(64) NOT NULL,
    column_name VARCHAR(64) NOT NULL,
    scope regclass NOT NULL,            -- 0 = unscoped
    via TEXT[],
    if TEXT,
    -- A grant's identity is the whole rule (plan/17 D15): grants are a set of
    -- permissive rules — the same rule twice is one rule, a rule that differs
    -- in its path or check is another rule, and rules only ever add.
    CONSTRAINT grants_rule UNIQUE NULLS NOT DISTINCT
        (privilege, on_table, role, scope, column_name, via, if)
);

CREATE TABLE letter.membership_rules (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    table_name regclass NOT NULL,
    scope_table regclass,
    user_column VARCHAR(64) NOT NULL,
    role VARCHAR(64) CHECK (role NOT IN ('anyone', 'any_user')),   -- a rule cannot confer what everyone holds (plan/22)
    role_column VARCHAR(64),
    if TEXT,
    -- The generated functions bake these in (plan/24 B1): the source
    -- table's key, and the FK to the scope (the key again when the table
    -- is its own scope). Stored so that renaming either is refused.
    pk_column VARCHAR(64) NOT NULL,
    scope_column VARCHAR(64),
    CONSTRAINT unique_assign UNIQUE (table_name, scope_table, user_column, role, role_column),
    CONSTRAINT role_or_column CHECK (
        (role IS NOT NULL AND role_column IS NULL) OR
        (role IS NULL AND role_column IS NOT NULL)
    )
);

CREATE TABLE letter.membership_sources (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    assignment_id uuid NOT NULL REFERENCES letter.membership_rules(id) ON DELETE CASCADE,
    role_id uuid NOT NULL REFERENCES letter.memberships(id),
    source_table regclass NOT NULL,
    source_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    scope_table regclass,
    scope_id TEXT
);

-- The users table(s) (plan/24 B8): deleting a row of one forgets the user its
-- key names. The key column is stored so that renaming it is refused.
CREATE TABLE letter.user_tables (
    table_name regclass PRIMARY KEY,
    key_column VARCHAR(64) NOT NULL
);

-- All five tables are configuration as far as pg_dump is concerned (plan/18
-- D6): memberships and membership_sources are normally derived by the rule
-- triggers, but memberships the application manages directly would otherwise
-- be lost. Restore with session_replication_role = replica and letter.bypass
-- (README): triggers and event triggers off, everything reloaded verbatim.
SELECT pg_catalog.pg_extension_config_dump('letter.grants', '');
SELECT pg_catalog.pg_extension_config_dump('letter.membership_rules', '');
SELECT pg_catalog.pg_extension_config_dump('letter.memberships', '');
SELECT pg_catalog.pg_extension_config_dump('letter.membership_sources', '');
SELECT pg_catalog.pg_extension_config_dump('letter.user_tables', '');

-- Indexes for enforcement query performance
CREATE INDEX memberships_user_id_idx ON letter.memberships (user_id);
CREATE INDEX memberships_role_idx ON letter.memberships (role);
CREATE INDEX grants_on_table_role_idx ON letter.grants (on_table, role);

-- Cleanup trigger: when a membership source is deleted, remove the membership it derived
CREATE FUNCTION letter._membership_cleanup() RETURNS trigger
AS 'MODULE_PATHNAME', 'letter_membership_cleanup'
LANGUAGE C;

-- An empty table whose only purpose is to carry a relcache invalidation
-- (plan/17 H4): the memberships trigger invalidates it, and every backend's
-- session cache follows, without invalidating the rewritten plans, which
-- depend on letter.grants but not on membership rows.
CREATE TABLE letter._membership_signal ();

-- Session-cache invalidation: any write to memberships or grants invalidates this
-- backend's cache at once and, through the relcache, every other backend's
-- at commit; a grants write also invalidates every rewritten plan.
CREATE FUNCTION letter._cache_inval() RETURNS trigger
AS 'MODULE_PATHNAME', 'letter_cache_inval'
LANGUAGE C;

CREATE TRIGGER _memberships_cache_inval
    AFTER INSERT OR UPDATE OR DELETE ON letter.memberships
    FOR EACH STATEMENT
    EXECUTE FUNCTION letter._cache_inval();

CREATE TRIGGER _grants_cache_inval
    AFTER INSERT OR UPDATE OR DELETE ON letter.grants
    FOR EACH STATEMENT
    EXECUTE FUNCTION letter._cache_inval();

-- Enforcement trigger functions (generic, installed on protected tables by grant/revoke)
CREATE FUNCTION letter._enforce_insert() RETURNS trigger
AS 'MODULE_PATHNAME', 'letter_enforce_insert'
LANGUAGE C;

CREATE FUNCTION letter._enforce_update() RETURNS trigger
AS 'MODULE_PATHNAME', 'letter_enforce_update'
LANGUAGE C;

CREATE FUNCTION letter._enforce_delete() RETURNS trigger
AS 'MODULE_PATHNAME', 'letter_enforce_delete'
LANGUAGE C;

CREATE FUNCTION letter._enforce_truncate() RETURNS trigger
AS 'MODULE_PATHNAME', 'letter_enforce_truncate'
LANGUAGE C;

-- The users table's trigger (plan/24 B8): installed by letter.users().
CREATE FUNCTION letter._users_forget() RETURNS trigger
AS 'MODULE_PATHNAME', 'letter_users_forget'
LANGUAGE C;

-- Lifecycle (plan/18 §3): drop cascades, alter refuses.
CREATE FUNCTION letter._on_sql_drop() RETURNS event_trigger
AS 'MODULE_PATHNAME', 'letter_on_sql_drop'
LANGUAGE C;

CREATE FUNCTION letter._on_ddl_command_end() RETURNS event_trigger
AS 'MODULE_PATHNAME', 'letter_on_ddl_command_end'
LANGUAGE C;

CREATE EVENT TRIGGER letter_sql_drop ON sql_drop
    EXECUTE FUNCTION letter._on_sql_drop();

-- CREATE FUNCTION: a CREATE OR REPLACE can change a function an if names
-- (plan/24); the handler skips letter's own generated functions.
CREATE EVENT TRIGGER letter_ddl_command_end ON ddl_command_end
    WHEN TAG IN ('ALTER TABLE', 'ALTER FUNCTION', 'CREATE FUNCTION')
    EXECUTE FUNCTION letter._on_ddl_command_end();

CREATE TRIGGER _membership_cleanup
    AFTER DELETE ON letter.membership_sources
    FOR EACH ROW
    EXECUTE FUNCTION letter._membership_cleanup();

-- Functions

-- Tables are identified by OID (regclass): a grant follows its table through
-- renames. scope NULL = unscoped (stored as 0).
-- Plumbing: the C entry points. The API is grant_global / grant_scoped,
-- revoke_global / revoke_scoped, assign / unassign below.
-- scoped: called through grant_scoped/revoke_scoped, whose scope may not
-- be NULL — checked in C so the wrappers stay inlinable SQL functions,
-- which add no CONTEXT line to an error (plan/24 C).
CREATE FUNCTION letter._grant(
    privilege text,
    on_table regclass,
    role text,
    columns text[],
    scope regclass DEFAULT NULL,
    via text[] DEFAULT NULL,
    if text DEFAULT NULL,
    scoped boolean DEFAULT false
) RETURNS boolean
AS 'MODULE_PATHNAME', 'letter_grant'
LANGUAGE C VOLATILE;

CREATE FUNCTION letter._revoke(
    privilege text,
    on_table regclass,
    role text,
    columns text[],
    scope regclass DEFAULT NULL,
    scoped boolean DEFAULT false
) RETURNS boolean
AS 'MODULE_PATHNAME', 'letter_revoke'
LANGUAGE C VOLATILE;

CREATE FUNCTION letter._assign(
    source_table regclass,
    user_column text,
    scope_table regclass DEFAULT NULL,
    role text DEFAULT NULL,
    role_column text DEFAULT NULL,
    if text DEFAULT NULL
) RETURNS boolean
AS 'MODULE_PATHNAME', 'letter_assign'
LANGUAGE C VOLATILE;

CREATE FUNCTION letter._unassign(
    source_table regclass,
    user_column text,
    scope_table regclass DEFAULT NULL,
    role text DEFAULT NULL,
    role_column text DEFAULT NULL
) RETURNS boolean
AS 'MODULE_PATHNAME', 'letter_unassign'
LANGUAGE C VOLATILE;

-- insert and delete are row-level: their column list is always '*'. The
-- others need one.
CREATE FUNCTION letter._columns_or_default(privilege text, columns text[]) RETURNS text[]
LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
    IF privilege IN ('insert', 'delete') THEN
        -- row-level: the whole row or nothing (plan/21 D14)
        IF columns IS NULL OR columns = ARRAY['*'] THEN
            RETURN ARRAY['*'];
        END IF;
        RAISE EXCEPTION 'letter: % is row-level: give it no column list', privilege
            USING ERRCODE = 'invalid_parameter_value',
                  HINT = 'An insert or delete grant covers the whole row.';
    END IF;
    IF columns IS NOT NULL THEN
        RETURN columns;
    END IF;
    RAISE EXCEPTION 'letter: a % grant needs a column list (or ARRAY[''*''])', privilege
        USING ERRCODE = 'null_value_not_allowed';
END $$;

-- Grants are a set of permissive rules: the same rule twice is one rule, a
-- rule that differs in its path or its condition is another rule, and a rule
-- only ever adds (plan/17 D15).

-- What a role held in the global scope may do.
CREATE FUNCTION letter.grant_global(
    privilege text,
    on_table regclass,
    role text,
    columns text[] DEFAULT NULL,
    if text DEFAULT NULL
) RETURNS boolean
LANGUAGE sql VOLATILE AS $$
    SELECT letter._grant(privilege, on_table, role,
                         letter._columns_or_default(privilege, columns), NULL, NULL, "if")
$$;

-- What a role held in the scope a row belongs to may do. The row reaches its
-- scope via a chain of foreign keys; the final hop is inferred when it is
-- unambiguous.
CREATE FUNCTION letter.grant_scoped(
    privilege text,
    on_table regclass,
    role text,
    columns text[],
    scope regclass,
    via text[] DEFAULT NULL,
    if text DEFAULT NULL
) RETURNS boolean
LANGUAGE sql VOLATILE AS $$
    SELECT letter._grant(privilege, on_table, role,
                         letter._columns_or_default(privilege, columns), scope, via, "if", true)
$$;

-- Revoke removes every rule under its key.
CREATE FUNCTION letter.revoke_global(
    privilege text,
    on_table regclass,
    role text,
    columns text[] DEFAULT ARRAY['*']
) RETURNS boolean
LANGUAGE sql VOLATILE AS $$
    SELECT letter._revoke(privilege, on_table, role, columns, NULL)
$$;

CREATE FUNCTION letter.revoke_scoped(
    privilege text,
    on_table regclass,
    role text,
    columns text[],
    scope regclass
) RETURNS boolean
LANGUAGE sql VOLATILE AS $$
    SELECT letter._revoke(privilege, on_table, role, columns, scope, true)
$$;

-- Memberships come from one of your tables: each row confers on the user in
-- user_column the role (a constant, or read from role_column), in the scope
-- the row's foreign key points at — or in the global scope when there is no
-- scope. Admin operations: require letter.bypass (plan/17 D13).
CREATE FUNCTION letter.assign(
    source_table regclass,
    user_column text,
    role text DEFAULT NULL,
    role_column text DEFAULT NULL,
    scope regclass DEFAULT NULL,
    if text DEFAULT NULL
) RETURNS boolean
LANGUAGE sql VOLATILE AS $$
    SELECT letter._assign(source_table, user_column, scope, role, role_column, "if")
$$;

CREATE FUNCTION letter.unassign(
    source_table regclass,
    user_column text,
    role text DEFAULT NULL,
    role_column text DEFAULT NULL,
    scope regclass DEFAULT NULL
) RETURNS boolean
LANGUAGE sql VOLATILE AS $$
    SELECT letter._unassign(source_table, user_column, scope, role, role_column)
$$;

-- The users table (plan/24 B8): a row of it going — or its key changing —
-- forgets the user the key names: every membership they hold, the ones
-- rules derived (with their sources) and the ones an administrator inserted
-- directly. So an identifier that is later reused starts from nothing. The
-- trigger runs with letter's authority: the application's own delete of a
-- user forgets them too. Configuration: a superuser's.
CREATE FUNCTION letter.users(rel regclass) RETURNS boolean
AS 'MODULE_PATHNAME', 'letter_users'
LANGUAGE C VOLATILE;

CREATE FUNCTION letter.unusers(rel regclass) RETURNS boolean
AS 'MODULE_PATHNAME', 'letter_unusers'
LANGUAGE C VOLATILE;

-- Plumbing: what the users trigger does (plan/18 D7, demoted from the API by
-- plan/24 B8). Removes every membership the user holds and the membership
-- sources behind them; returns the number of memberships removed.
-- Memberships derived from source rows that still exist will be derived
-- again on the next write to those rows.
CREATE FUNCTION letter._forget_user(p_user_id text) RETURNS bigint
LANGUAGE plpgsql VOLATILE AS $$
DECLARE
    n bigint;
BEGIN
    SELECT count(*) INTO n FROM letter.memberships WHERE user_id = p_user_id;
    DELETE FROM letter.membership_sources WHERE user_id = p_user_id;   -- cleanup trigger drops their memberships
    DELETE FROM letter.memberships WHERE user_id = p_user_id;          -- the directly-managed rest
    RETURN n;
END $$;

-- Read enforcement

-- The columns of one row that the current user may read, or NULL if the
-- row is not visible to them: the in-band way to tell a hidden column from
-- a NULL one (plan/17 D3).
CREATE FUNCTION letter.visible_columns(rel regclass, pk text) RETURNS text[]
AS 'MODULE_PATHNAME', 'letter_visible_columns'
LANGUAGE C STABLE STRICT;

-- Plumbing, test-only (plan/20 S2): the walker-based read, kept as the
-- parity oracle for the generator (plan/15 D5). Not an API: plain SELECT is
-- the enforced read. Returns strings; its raw condition is evaluated against
-- true values — with letter's authority, so never the application's to call
-- (plan/24 A3).
CREATE FUNCTION letter._read(
    table_name text,
    condition text DEFAULT NULL
) RETURNS SETOF jsonb
AS 'MODULE_PATHNAME', 'letter_read'
LANGUAGE C VOLATILE;
REVOKE EXECUTE ON FUNCTION letter._read(text, text) FROM PUBLIC;

-- The current end user, as the application set it — or NULL when unset. For
-- application SQL and for check expressions ("only the author may edit"):
--   owner_id = letter.user_id()::uuid
-- Is this session protected? True when letter was preloaded (every session
-- of the database has the planner hook), reads are enforced, and bypass is
-- off. The application's start-up probe: call it on a fresh connection.
CREATE FUNCTION letter.enforcing() RETURNS boolean
AS 'MODULE_PATHNAME', 'letter_enforcing'
LANGUAGE C STABLE PARALLEL SAFE;

CREATE FUNCTION letter.user_id() RETURNS text
AS 'MODULE_PATHNAME', 'letter_user_id_fn'
LANGUAGE C STABLE PARALLEL SAFE;

-- Plumbing the planner hook puts into an INSERT … ON CONFLICT DO UPDATE on a
-- protected table (plan/24 A4): reached when the conflicting row is one the
-- user cannot see, it raises the refusal. VOLATILE so it is never folded away.
CREATE FUNCTION letter._hidden_conflict(rel oid) RETURNS boolean
AS 'MODULE_PATHNAME', 'letter_hidden_conflict'
LANGUAGE C VOLATILE;

-- Nobody, in either identity mode.
CREATE FUNCTION letter.logout() RETURNS void
AS 'MODULE_PATHNAME', 'letter_logout'
LANGUAGE C VOLATILE;

-- For check_health(): why letter.jwt_keys does not parse, or NULL.
CREATE FUNCTION letter._jwt_keys_check() RETURNS text
AS 'MODULE_PATHNAME', 'letter_jwt_keys_check'
LANGUAGE C STABLE;

-- Identity from claims a proxy has already verified (plan/23 T1): PostgREST and
-- Supabase check the JWT and expose its claims as request.jwt.claims; as their
-- pre-request function this sets letter.user_id for the transaction from the
-- claim named (sub by default). No claim — an anonymous request — leaves the user
-- unset, so only anyone grants apply. Returns the user id, or NULL.
CREATE FUNCTION letter.user_from_claims(claim text DEFAULT 'sub',
                                        setting text DEFAULT 'request.jwt.claims') RETURNS text
LANGUAGE plpgsql VOLATILE AS $$
DECLARE
    claims text := pg_catalog.current_setting(setting, true);
    uid text;
BEGIN
    IF pg_catalog.current_setting('letter.identity') = 'token' THEN
        RAISE EXCEPTION 'letter: letter.identity is token: the setting user_from_claims() would make is ignored'
            USING ERRCODE = 'invalid_authorization_specification',
                  HINT = 'In token mode the database verifies the token itself: call letter.login(token).';
    END IF;
    IF claims IS NOT NULL AND claims <> '' THEN
        uid := (claims::jsonb) ->> claim;
    END IF;
    PERFORM pg_catalog.set_config('letter.user_id', coalesce(uid, ''), true);
    RETURN uid;
END $$;

-- Token identity (plan/23): verify a JWT against the issuer's public keys
-- (letter.jwt_keys; RSA, ECDSA or Ed25519 — never HMAC) and its exp/nbf, iss and
-- aud, and make the user it names (letter.jwt_claim, sub by default) the current
-- user — for the transaction (local, the pool-safe default) or the session.
-- Returns the user id. A rejected token is an error: "letter: token rejected: …".
CREATE FUNCTION letter.login(token text, local boolean DEFAULT true) RETURNS text
AS 'MODULE_PATHNAME', 'letter_login'
LANGUAGE C VOLATILE;

-- The current end user, or an error when unset. Every generated barrier reads
-- the user through this, so an unidentified session cannot read a protected
-- table any more than it can write one.
CREATE FUNCTION letter._user_id() RETURNS text
AS 'MODULE_PATHNAME', 'letter_require_user'
LANGUAGE C STABLE PARALLEL SAFE;

-- Info/debug functions

-- Debugging aid: the redacting subquery the planner hook substitutes for a
-- protected table (NULL if the table has no select grants).
CREATE FUNCTION letter.read_policy(rel regclass) RETURNS text
AS 'MODULE_PATHNAME', 'letter_barrier_sql'
LANGUAGE C STABLE STRICT;
REVOKE EXECUTE ON FUNCTION letter.read_policy(regclass) FROM PUBLIC;   -- configuration, not the application's (plan/24 A3)

-- Debugging aid for the write path (plan/19): the row-visibility qual and
-- the per-column tests applied to a protected result relation.
CREATE FUNCTION letter.write_policy(rel regclass) RETURNS text
AS 'MODULE_PATHNAME', 'letter_barrier_write_sql'
LANGUAGE C STABLE STRICT;
REVOKE EXECUTE ON FUNCTION letter.write_policy(regclass) FROM PUBLIC;

-- Health check (plan/18 I4). Severity: error (enforcement is not what the
-- catalogue says), warning (works, but not as intended), info.
CREATE FUNCTION letter._problems()
RETURNS TABLE (severity text, object text, message text)
AS 'MODULE_PATHNAME', 'letter_problems'
LANGUAGE C VOLATILE;
REVOKE EXECUTE ON FUNCTION letter._problems() FROM PUBLIC;

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
    rule AS (
        SELECT a.*, left(a.id::text, 8) AS short_id,
               EXISTS (SELECT 1 FROM pg_class WHERE oid = a.table_name) AS source_exists
        FROM letter.membership_rules a
    )
    -- deployment
    SELECT 'warning', 'library',
           'letter is not in shared_preload_libraries or session_preload_libraries: a session that never calls a letter function has no planner hook, so read enforcement does not apply to it'
    FROM preload WHERE NOT ('letter' = ANY (libs))
    UNION ALL
    SELECT 'info', 'letter.enforce_reads', 'read enforcement is switched off'
    WHERE current_setting('letter.enforce_reads') = 'off'
    UNION ALL
    -- token identity (plan/23)
    SELECT 'info', 'letter.identity', 'token: the current user comes from letter.login() only'
    WHERE current_setting('letter.identity') = 'token'
    UNION ALL
    SELECT 'error', 'letter.jwt_keys', 'letter.identity is token but no keys are configured: nobody can log in'
    WHERE current_setting('letter.identity') = 'token' AND current_setting('letter.jwt_keys') = ''
    UNION ALL
    SELECT 'error', 'letter.jwt_keys', letter._jwt_keys_check()
    WHERE letter._jwt_keys_check() IS NOT NULL
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
    -- default deny (plan/17 D14): a table with no grants is unreadable and unwritable
    -- by the application — usually a migration that forgot the grant
    SELECT 'info', 'table ' || letter._qualname(c.oid),
           'has no grants: neither readable nor writable by the application (default deny)'
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind IN ('r', 'p') AND NOT c.relispartition
      AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'letter')
      AND n.nspname NOT LIKE 'pg\_%'
      AND NOT EXISTS (SELECT 1 FROM letter.grants g WHERE g.on_table = c.oid)
    UNION ALL
    -- a write grant whose role sees no row of the table can change none (plan/21 finding 6)
    SELECT DISTINCT 'warning', 'grant ' || g.role || '/' || g.privilege || ' on ' || letter._qualname(g.on_table),
           'the role has no select grant on the table: it can see no row, so it can change none'
    FROM letter.grants g
    WHERE g.privilege IN ('update', 'delete', 'fill')
      AND EXISTS (SELECT 1 FROM pg_class WHERE oid = g.on_table)
      AND NOT EXISTS (SELECT 1 FROM letter.grants s
                      WHERE s.on_table = g.on_table AND s.privilege = 'select'
                        AND s.role IN (g.role, 'anyone', 'any_user'))
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
    -- membership rules
    SELECT 'error', 'rule ' || a.id::text, 'source table no longer exists (OID ' || a.table_name::oid || ')'
    FROM rule a WHERE NOT a.source_exists
    UNION ALL
    SELECT 'error', 'rule on ' || letter._qualname(a.table_name),
           'scope table no longer exists (OID ' || a.scope_table::oid || ')'
    FROM rule a
    WHERE a.source_exists AND a.scope_table IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM pg_class WHERE oid = a.scope_table)
    UNION ALL
    SELECT 'error', 'rule on ' || letter._qualname(a.table_name), 'is missing function letter.' || f.name
    FROM rule a
    CROSS JOIN LATERAL (VALUES ('_rule_' || a.short_id || '_upsert'), ('_rule_' || a.short_id || '_delete')) f(name)
    WHERE a.source_exists
      AND NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                      WHERE n.nspname = 'letter' AND p.proname = f.name)
    UNION ALL
    SELECT 'error', 'rule on ' || letter._qualname(a.table_name), 'is missing trigger ' || tg.name
    FROM rule a
    CROSS JOIN LATERAL (VALUES ('letter_rule_' || a.short_id || '_insert'), ('letter_rule_' || a.short_id || '_update'),
                               ('letter_rule_' || a.short_id || '_delete')) tg(name)
    WHERE a.source_exists
      AND NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = a.table_name AND tgname = tg.name)
    UNION ALL
    -- memberships
    SELECT 'error', 'membership ' || r.role || ' of ' || r.user_id,
           'is scoped to a table that no longer exists (OID ' || r.scope_table::oid || ')'
    FROM letter.memberships r
    WHERE r.scope_table IS NOT NULL AND NOT EXISTS (SELECT 1 FROM pg_class WHERE oid = r.scope_table)
    UNION ALL
    SELECT 'info', 'memberships', count(*) || ' membership(s) are managed directly, not by a rule'
    FROM letter.memberships r
    WHERE NOT EXISTS (SELECT 1 FROM letter.membership_sources ra WHERE ra.role_id = r.id)
    HAVING count(*) > 0
    UNION ALL
    -- users tables (plan/24 B8)
    SELECT 'error', 'users table (OID ' || u.table_name::oid || ')', 'no longer exists'
    FROM letter.user_tables u WHERE NOT EXISTS (SELECT 1 FROM pg_class WHERE oid = u.table_name)
    UNION ALL
    SELECT 'error', 'users table ' || letter._qualname(u.table_name), 'has no letter_users_forget trigger'
    FROM letter.user_tables u
    WHERE EXISTS (SELECT 1 FROM pg_class WHERE oid = u.table_name)
      AND NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = u.table_name AND tgname = 'letter_users_forget')
    UNION ALL
    SELECT 'warning', 'table ' || letter._qualname(tr.tgrelid), 'has the users trigger but is not a declared users table'
    FROM pg_trigger tr
    WHERE tr.tgname = 'letter_users_forget'
      AND NOT EXISTS (SELECT 1 FROM letter.user_tables u WHERE u.table_name = tr.tgrelid)
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
    via TEXT[],
    if TEXT
) AS $$
    SELECT g.role, g.privilege, g.on_table, g.column_name,
           NULLIF(g.scope, 0), g.via, g.if
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
    via TEXT[],
    if TEXT
) AS $$
    SELECT r.role, g.privilege, g.on_table, g.column_name, NULLIF(g.scope, 0),
           r.scope_table, r.scope_id, g.via, g.if
    FROM letter.memberships r
    JOIN letter.grants g ON g.role = r.role
        AND (
            -- Scoped grant: scope matches the role's scope_table
            g.scope = r.scope_table
            -- Unscoped grant: the role held in the global scope (plan/17 D11)
            OR (g.scope = 0 AND r.scope_table IS NULL)
        )
    WHERE r.user_id = p_user_id;
$$ LANGUAGE SQL STABLE;

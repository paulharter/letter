# letter

Relationship-based access control (ReBAC) for PostgreSQL, as an extension. Permissions
follow the relationships between rows — "editors of the project this task belongs to
may read its title" — rather than static per-table grants. Writes are enforced by
triggers; reads will be enforced transparently by a planner hook (in progress, see
`plan/17`).

**Status:** pre-release. Write enforcement, transparent read enforcement (the planner
hook, `letter.enforce_reads`, on by default), assignments, `letter.read()` and the
lifecycle machinery are complete and tested. PostgreSQL 16 and 17 (17 tested).

## Install

```sh
make && make install && make installcheck
```

```sql
CREATE EXTENSION letter;
```

Add `letter` to `shared_preload_libraries` (or `session_preload_libraries`). Read
enforcement is a planner hook, and a session that never calls a letter function would
otherwise run without it. The library warns when loaded any other way, and
`letter.check_health()` reports it.

## Concepts

- **Tables are identified by OID.** Every letter function takes tables as `regclass`
  (`'public.tasks'`, `'"Odd Schema"."Odd Table"'`), and letter stores the OID, so
  protection follows a table through `RENAME` and `SET SCHEMA`. Columns are identified
  by name.
- **Roles** are rows in `letter.roles`: `(role, user_id, scope_table, scope_id)`. A role
  is held either in the scope of one row of a *scope table* (`editor` of project 42) or
  globally (`scope_table IS NULL`). The global scope is just another scope: a role held
  in fifty projects never adds up to a global one, and a global role never satisfies a
  scoped grant.
- **Grants** say what a role may do to which columns of which table, and — for scoped
  grants — how a row of that table reaches its scope: a chain of foreign keys, the
  `using_path`. The final hop is inferred when it is unambiguous.
- **Assignments** derive role rows from your own tables (a `team_members` table with a
  `user_id`, a `project_id` and a `role` column) and keep them in step through triggers.
- **The current user** is the session setting `letter.current_user_id`, which the
  application sets per request. Letter assumes end users never hold a raw SQL
  connection: the application layer that sets it is the enforcement perimeter.

## API

```sql
-- privileges: select | insert | update | delete | set   ('set' = update only while NULL)
letter.grant (privilege text, on_table regclass, role text, columns text[],
              scope regclass DEFAULT NULL,           -- NULL = unscoped
              using_path text[] DEFAULT NULL, check_fn text DEFAULT NULL)
letter.revoke(privilege text, on_table regclass, role text, columns text[],
              scope regclass DEFAULT NULL)

letter.assign  (source_table regclass, user_column text, scope_table regclass DEFAULT NULL,
                role_name text DEFAULT NULL, role_column text DEFAULT NULL, if_fn text DEFAULT NULL)
letter.unassign(source_table regclass, user_column text, scope_table regclass DEFAULT NULL,
                role_name text DEFAULT NULL, role_column text DEFAULT NULL)

letter.visible_columns(rel regclass, pk anyelement)        -- text[]: what this user may read of that row
letter.read(table_name text, condition text DEFAULT NULL)   -- DEPRECATED: plain SELECT is the enforced read
letter.list_grants(role text DEFAULT NULL)
letter.user_permissions(user_id text)
letter.barrier_sql(rel regclass)                            -- the read-enforcement subquery
letter.check_health()                                       -- (severity, object, message)
```

`columns` may be `ARRAY['*']`. A grant on a table that does not exist is refused; a
scoped grant whose `using_path` is not a chain of foreign keys, or whose scope or hop
tables have composite primary keys, is refused. Primary-key columns are always
readable.

Example:

```sql
SELECT letter.assign('public.team_members', 'user_id', 'public.projects',
                     role_column := 'role');
SELECT letter.grant('select', 'public.tasks',    'editor', ARRAY['title', 'estimate'],
                    'public.projects');                       -- FK tasks.project_id inferred
SELECT letter.grant('update', 'public.comments', 'editor', ARRAY['body'],
                    'public.projects', ARRAY['task_id']);     -- comments → tasks → projects
SELECT letter.grant('select', 'public.projects', 'auditor', ARRAY['name']);   -- unscoped

SET letter.current_user_id = '…';
```

A hidden column reads as NULL. When an application needs to tell a hidden column from
a NULL one — a lock icon, no edit box — `letter.visible_columns('public.projects',
id)` returns the columns of that row the current user may read, or NULL if the row is
not visible at all.

Hand-written queries against `letter.grants` or `letter.roles` must compare table
columns with a `regclass`, e.g. `WHERE on_table = 'public.tasks'::regclass` (a bare
string literal is taken as an OID).

## Default deny

Without `letter.bypass`, only what a grant allows is allowed — across the whole
database. A table with no grants can be neither read nor written by an application
session (an error, not an empty result: a missing grant is a configuration mistake).
Exempt: `pg_catalog`, `information_schema`, the session's own temporary tables, and
letter's own schema, which you keep out of the application's reach with ordinary SQL
privileges (`REVOKE ALL ON ALL TABLES IN SCHEMA letter FROM app`). Scope and hop tables
are ordinary tables in this respect: directly readable only with a grant, and readable
*through* a scope path exactly as far as the path's author decided.

## Deployment model

Enforcement is a property of the connecting database role. The application connects
as a role without `letter.bypass`; administrators, migrations and `pg_dump` connect as
roles that have it by default:

```sql
ALTER ROLE migrator SET letter.bypass = on;
```

`letter.bypass` is superuser-settable only (`PGC_SUSET`). Superusers are **not**
bypassed implicitly — the same `ALTER ROLE` opts them in. `letter.assign()` and
`letter.unassign()` require bypass. `TRUNCATE` on a protected table requires bypass.

## Lifecycle

Letter keeps its state consistent with your schema:

- **Dropping** a table or column removes the letter state that depended on it — grants
  on it, grants whose scope path crosses it, assignments that use it, roles scoped to
  it — with a `NOTICE`.
- **Altering** something so that existing letter state stops making sense — renaming a
  granted column, dropping a foreign key on a scope path, adding a second foreign key
  that makes an inferred hop ambiguous, giving a scope table a composite key — is
  **refused**. Revoke or unassign first.
- Renames and schema moves need nothing: identity is by OID.
- `DROP EXTENSION letter` is refused while enforcement or assignment triggers exist on
  your tables; `DROP EXTENSION letter CASCADE` removes them all.
- `letter.check_health()` reports what the above cannot prevent: state edited by hand,
  disabled triggers, tables with grants but no triggers, scope-path columns without an
  index, and the deployment settings.

Scope-path columns should be indexed (`CREATE INDEX ON comments (task_id)`);
`letter.grant()` warns when they are not, since scoped reads are driven from the
user's scopes through those indexes.

## Known gaps

- The result relation of an UPDATE/DELETE is not redacted: `RETURNING` and the SET
  expressions see true values (`plan/15` §8). `MERGE` on a protected table is refused.
- `COPY table TO` is refused (use `COPY (SELECT …) TO`, which is enforced); `COPY table
  FROM` needs an insert grant; `TRUNCATE` needs bypass.
- A foreign-key column used in a join condition must itself be granted, or it is NULL
  in the join and nothing matches.
- Dump and restore: letter's tables are not yet registered with
  `pg_extension_config_dump`, so `pg_dump` omits grants, roles and assignments.
  (`plan/18` §4.)
- Partitions and inheritance children are not protected unless granted on directly.
- Logical replication of `letter.*` rows between databases carries the wrong OIDs.

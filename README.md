# letter

Relationship-based access control (ReBAC) for PostgreSQL, as an extension. Permissions
follow the relationships between rows — "editors of the project this task belongs to
may read its title" — rather than static per-table grants. Writes are enforced by
triggers; reads transparently, by a planner hook.

**Status:** pre-release. Write enforcement, transparent read enforcement (the planner
hook, `letter.enforce_reads`, on by default), membership rules, `if` conditions and
the lifecycle machinery are complete and tested on PostgreSQL 16 and 17.

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
- **Memberships** are rows in `letter.memberships`: `(role, user_id, scope_table,
  scope_id)`. A user holds a role either in the scope of one row of a *scope table*
  (`editor` of project 42) or in the global scope (`scope_table IS NULL`). The global
  scope is just another scope: a role held in fifty projects never adds up to a global
  one, and a global membership never satisfies a scoped grant.
- **Grants are a set of permissive rules.** They cannot contradict each other and their
  order does not matter; a rule can only add. Granting the same rule twice is one rule;
  two rules for one role that differ in their path both stand. Narrowing means revoking.
- **Grants** say what a role may do to which columns of which table, and — for scoped
  grants — how a row of that table reaches its scope: a chain of foreign keys, the
  `via`. The final hop is inferred when it is unambiguous. A scoped select grant also
  makes its own path column visible — the row is visible because of where it points —
  so joins to the scope parent just work.
- **`if`** narrows a rule to the rows that satisfy a boolean expression over the row's
  own columns: `status <> 'archived'`, `author = letter.user_id()::uuid`. It is
  validated when the rule is made and enforced wherever the rule is — in the read
  policy and in the write triggers. On `update` and `fill` it is checked on the row
  before and after the change, and both must pass; a rule that names `old` and `new`
  (`old.status = 'draft' AND new.status = 'published'`) is checked once, on the
  transition. The expression sees only the row: no subqueries, and any function it
  calls must be `IMMUTABLE` (`pg_catalog` functions and `letter.user_id()` are allowed).
- **Membership rules** (`letter.assign`) derive memberships from your own tables (a
  `team_members` table with a `user_id`, a `project_id` and a `role` column) and keep
  them in step through triggers. An `if` limits them to the source rows that satisfy it.
- **Users** are opaque strings to letter. Memberships derived by rules follow their
  source rows; memberships the application inserts directly are the application's to
  remove — `letter.forget_user(user_id)` removes every membership a user holds, of both
  kinds.
- **The current user** is the session setting `letter.user_id`, which the
  application sets per request. While it is unset, any read or write of a protected
  table is an error. `letter.user_id()` reads it back (NULL when unset), for SQL
  such as `WHERE owner_id = letter.user_id()::uuid`. Letter
  assumes end users never hold a raw SQL connection: the application layer that sets
  it is the enforcement perimeter.

## API

```sql
-- privileges: select | insert | update | delete | fill   ('fill' = update only while NULL)
letter.grant_global(privilege text, on_table regclass, role text, columns text[] DEFAULT NULL,
                    if text DEFAULT NULL)
letter.grant_scoped(privilege text, on_table regclass, role text, columns text[],
                    scope regclass, via text[] DEFAULT NULL, if text DEFAULT NULL)
letter.revoke_global(privilege text, on_table regclass, role text, columns text[] DEFAULT ARRAY['*'])
letter.revoke_scoped(privilege text, on_table regclass, role text, columns text[], scope regclass)

letter.assign  (source_table regclass, user_column text,
                role text DEFAULT NULL, role_column text DEFAULT NULL,
                scope regclass DEFAULT NULL, if text DEFAULT NULL)
letter.unassign(source_table regclass, user_column text,
                role text DEFAULT NULL, role_column text DEFAULT NULL, scope regclass DEFAULT NULL)

letter.visible_columns(rel regclass, pk anyelement)        -- text[]: what this user may read of that row
letter.forget_user(user_id text)                            -- remove every membership the user holds; bigint
letter.user_id()                                       -- the current user id as text, NULL when unset
letter.enforcing()                                     -- is this session protected? the application's start-up probe
letter.list_grants(role text DEFAULT NULL)
letter.user_permissions(user_id text)
letter.read_policy(rel regclass)                            -- the read-enforcement subquery
letter.check_health()                                       -- (severity, object, message)
```

`columns` may be `ARRAY['*']`, and for `insert` and `delete` — row-level privileges —
it may be omitted. A grant on a table that does not exist is refused; a scoped grant
whose `via` is not a chain of foreign keys, or whose scope or hop tables have
composite primary keys, is refused. Primary-key columns are always readable.
`revoke_*` removes every rule under its key.

Example:

```sql
SELECT letter.assign('public.team_members', 'user_id', role_column := 'role',
                     scope := 'public.projects');
SELECT letter.grant_scoped('select', 'public.tasks',    'editor', ARRAY['title', 'estimate'],
                           'public.projects');                    -- FK tasks.project_id inferred
SELECT letter.grant_scoped('update', 'public.comments', 'editor', ARRAY['body'],
                           'public.projects', via := ARRAY['task_id']);  -- comments → tasks → projects
SELECT letter.grant_global('select', 'public.projects', 'auditor', ARRAY['name']);
SELECT letter.grant_global('insert', 'public.log', 'logger');    -- row-level: no column list
SELECT letter.grant_scoped('update', 'public.tasks',    'editor', ARRAY['title'],
                           'public.projects', if := 'status <> ''done''');       -- open tasks only
SELECT letter.grant_scoped('delete', 'public.comments', 'editor', NULL,
                           'public.projects', via := ARRAY['task_id'],
                           if := 'author_id = letter.user_id()::uuid');         -- your own

SET letter.user_id = '…';
```

A hidden column reads as NULL. When an application needs to tell a hidden column from
a NULL one — a lock icon, no edit box — `letter.visible_columns('public.projects',
id)` returns the columns of that row the current user may read, or NULL if the row is
not visible at all.

Hand-written queries against `letter.grants` or `letter.memberships` must compare table
columns with a `regclass`, e.g. `WHERE on_table = 'public.tasks'::regclass` (a bare
string literal is taken as an OID).

## Using letter from an application

The current user is a session setting, and a session outlives a request. Letter cannot
tell where one request ends and the next begins, so the application must:

```python
# per request, inside the request's transaction — the setting dies with it
with conn.transaction():
    conn.execute("SELECT set_config('letter.user_id', %s, true)", (user_id,))   # SET LOCAL
    ...

# or, on an autocommit connection: set on entry, reset on the way out, whatever happened
conn.execute("SELECT set_config('letter.user_id', %s, false)", (user_id,))
try:
    ...
finally:
    conn.execute("RESET letter.user_id")
```

and, as a second line of defence, reset connections when they return to the pool
(`psycopg_pool`'s `reset=` hook, or `DISCARD ALL`). A handler that sets the user and
never resets it leaves that user on the connection for the next borrower, and letter
has no way to notice. Under pgbouncer in transaction mode, only the `SET LOCAL` form
is safe: a session-level `SET` follows the server connection to the next client.

At start-up, call `letter.enforcing()` on a fresh connection and refuse to serve if
it returns false: it is true only when letter is preloaded for every session of the
database, reads are enforced and bypass is off. (A session that loads the library on
demand is protected from then on, but its neighbours in the pool are not, so it answers
false.) A request that never sets the user gets an error on its first protected read
or write, never somebody else's data. Prepared statements, including the ones a driver prepares
on its own, are safe across users: the user is read when the statement runs, not when
it is planned.

## Default deny

Without `letter.bypass`, only what a grant allows is allowed — across the whole
database. A table with no grants can be neither read nor written by an application
session (an error, not an empty result: a missing grant is a configuration mistake).
Exempt: `pg_catalog`, `information_schema`, the session's own temporary tables, and
letter's own schema, which you keep out of the application's reach with ordinary SQL
privileges (`REVOKE ALL ON ALL TABLES IN SCHEMA letter FROM app`). Scope and hop tables
are ordinary tables in this respect: directly readable only with a grant, and readable
*through* a scope path exactly as far as the path's author decided.

### Writes

The table a statement writes to is protected the same way. Rows the user cannot see
are not there for `UPDATE` or `DELETE` either — they are skipped, silently, so neither
a row count nor an error reveals them. Rows the user can see but may not change are
refused loudly by the enforcement triggers. Hidden columns read as NULL wherever a
write reads them: in the `WHERE`, in `SET` expressions, in `RETURNING`, in
`ON CONFLICT`. `INSERT … RETURNING` is redacted too.

## Deployment model

Enforcement is a property of the connecting database role. The application connects
as a role without `letter.bypass` and without any privilege on letter's tables — it
needs `USAGE` on schema `letter` to call `letter.user_id()` and
`letter.visible_columns()`, and nothing else. Letter's own reads and writes — the
grants it consults, the memberships its rules maintain — run with letter's authority
(the extension owner's), the way a `SECURITY DEFINER` function does, so the
application can only ever reach a membership through a rule:

```sql
GRANT USAGE ON SCHEMA letter TO app;
REVOKE ALL ON ALL TABLES IN SCHEMA letter FROM app;
```

Configuration — `grant_*`, `revoke_*`, `assign`, `unassign` — is done by a superuser;
any other role is refused. Administrators, migrations and `pg_dump` connect as roles
that have bypass by default:

```sql
ALTER ROLE migrator SET letter.bypass = on;      -- a superuser, for now
```

`letter.bypass` is superuser-settable only (`PGC_SUSET`). Superusers are **not**
bypassed implicitly — the same `ALTER ROLE` opts them in. `letter.assign()` and
`letter.unassign()` require bypass. `TRUNCATE` on a protected table requires bypass.

Most memberships never need an administrator: they follow from the application's
own writes. A user who inserts a project with `owner_id = letter.user_id()::uuid`
(an insert grant's `if`) becomes its owner through a rule
(`assign('projects', 'owner_id', role := 'owner', scope := 'projects')`); an owner
who inserts a `team_members` row confers that role. Privileged, RBAC-style
administration is done directly on `letter.memberships` by a superuser or a backend
process with bypass, never through a letter-enforced route.

## Backup and restore

`pg_dump` includes letter's grants, memberships, membership rules and membership
sources. Restore
with letter switched off, so that nothing is re-derived or re-validated while the
schema is half-built:

```sh
PGOPTIONS='-c letter.bypass=on -c session_replication_role=replica' psql -d newdb -f dump.sql
```

Both are needed. `pg_dump` loads letter's tables first, then your data, then the
constraints and triggers. Without `letter.bypass` the restore stops at the first
`COPY` into a table whose grants are already loaded ("no insert grant"). Without
`session_replication_role = replica` — which disables ordinary triggers *and* event
triggers — it stops at the first `ALTER TABLE … ADD CONSTRAINT`, because letter
revalidates every grant after an `ALTER TABLE` and the foreign keys the grants depend
on have not been added yet. The dump role should have `letter.bypass = on` by default
(see above).

## Lifecycle

Letter keeps its state consistent with your schema:

- **Dropping** a table or column removes the letter state that depended on it — grants
  on it, grants whose scope path or `if` crosses it, membership rules that use it,
  memberships scoped to it — with a `NOTICE`.
- **Altering** something so that existing letter state stops making sense — renaming a
  granted column or one an `if` names, dropping a foreign key on a scope path, adding a
  second foreign key that makes an inferred hop ambiguous, giving a scope table a
  composite key — is **refused**. Revoke or unassign first.
- Renames and schema moves need nothing: identity is by OID.
- `DROP EXTENSION letter` is refused while enforcement or membership-rule triggers exist on
  your tables; `DROP EXTENSION letter CASCADE` removes them all.
- `letter.check_health()` reports what the above cannot prevent: state edited by hand,
  disabled triggers, tables with grants but no triggers, scope-path columns without an
  index, and the deployment settings.

Scope-path columns should be indexed (`CREATE INDEX ON comments (task_id)`);
`letter.grant_scoped()` warns when they are not, since scoped reads are driven from the
user's scopes through those indexes.

## Known gaps

- `MERGE` on a protected table is refused, as is a whole-row reference to the table a
  statement writes to (`UPDATE t … RETURNING t`).
- `COPY table TO` is refused (use `COPY (SELECT …) TO`, which is enforced); `COPY table
  FROM` needs an insert grant; `TRUNCATE` needs bypass.
- A foreign-key column that is *not* on a grant's scope path must be granted like any
  other column before it can be used in a join; the path's own column is visible with
  the grant.
- Partitions and inheritance children are not protected unless granted on directly.
- Logical replication of `letter.*` rows between databases carries the wrong OIDs.

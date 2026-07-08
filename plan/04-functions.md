# Letter — Functions

## letter.grant(privilege, on_table, role, columns text[], scope, using_path text[], check_fn)

Declares that a role has a privilege on specific columns of a table. All table names must be schema-qualified (e.g., `'public.projects'`).

- Inserts one row into `letter.grants` per column in the array
- On conflict (same privilege/table/role/scope/column), updates `using_path` and `check_fn`
- `using_path` is a `text[]` array of FK column names for scope resolution (nullable)
- `check_fn` is deferred — stored but not evaluated by enforcement yet
- `columns` can include `'*'` as a sentinel meaning "all columns"
- `scope` is `''` for unscoped grants, or the scope table name for scoped grants
- Automatically installs enforcement triggers on the table when the first grant is added

```sql
-- Grant select on all columns (unscoped)
SELECT letter.grant('select', 'public.projects', 'viewer', ARRAY['*'], '', NULL, NULL);

-- Grant update on specific columns, scoped to projects
SELECT letter.grant('update', 'public.projects', 'editor', ARRAY['name', 'status'],
    'public.projects', ARRAY['project_id'], NULL);
```

## letter.revoke(privilege, on_table, role, columns text[], scope)

Removes privilege grants.

- If `columns` contains `'*'`, removes **all** grants matching that privilege/table/role/scope
- Otherwise removes only the specified columns
- No-op if no matching rows exist
- Automatically removes enforcement triggers from the table when the last grant is removed

```sql
-- Revoke a specific column
SELECT letter.revoke('update', 'public.projects', 'editor', ARRAY['status'], 'public.projects');

-- Revoke all columns at once
SELECT letter.revoke('select', 'public.projects', 'viewer', ARRAY['*'], '');
```

## letter.assign(source_table, user_column, scope_table, role_name, role_column, if_fn)

Creates an assignment rule that automatically maintains `letter.roles` based on data in an application table.

- Inserts a rule into `letter.assignments`
- Introspects the source table's primary key and foreign keys via the system catalog
- Creates trigger functions and installs INSERT/UPDATE/DELETE triggers on the source table
- If scoped, installs a DELETE trigger on the scope table for cleanup
- Backfills existing rows
- Exactly one of `role_name` or `role_column` must be provided

```sql
-- Scoped: role comes from a column
SELECT letter.assign('public.team_members', 'user_id', 'public.projects',
    role_name := NULL, role_column := 'role', if_fn := NULL);

-- Unscoped: fixed role name
SELECT letter.assign('public.admins', 'user_id', NULL,
    role_name := 'superadmin', role_column := NULL, if_fn := NULL);
```

## letter.unassign(source_table, user_column, scope_table, role_name, role_column)

Removes an assignment rule and all its artifacts.

- Finds the matching assignment by its attributes
- Drops triggers from the source table (and scope table if scoped)
- Drops the trigger functions
- Deletes the assignment row — FK CASCADE removes role_assignments, and the cleanup trigger removes the associated roles

```sql
SELECT letter.unassign('public.team_members', 'user_id', 'public.projects',
    role_name := NULL, role_column := 'role');
```

## letter.read(table_name text, condition text DEFAULT NULL) → SETOF jsonb

Performs an enforced read. Returns one JSONB object per row with column-level redaction.

- Requires `letter.current_user_id` to be set (fails closed otherwise)
- For each row, checks the user's scoped roles against `select` grants
- Columns without permission are set to `null` in the JSONB
- PK columns are always visible
- `_redacted` key contains an array of column names that were hidden
- Uses the session cache for role/grant lookups

```sql
SET letter.current_user_id = 'a0000000-0000-0000-0000-000000000001';

-- Read with condition
SELECT * FROM letter.read('public.projects', 'status = ''active''') t(row_data);

-- Extract specific fields
SELECT
    row_data->>'name' AS name,
    row_data->>'budget' AS budget,
    row_data->'_redacted' AS redacted
FROM letter.read('public.projects') t(row_data);
```

## letter.list_grants(filter_role text DEFAULT NULL)

Lists all grants, optionally filtered by role. Returns a table.

```sql
-- All grants
SELECT * FROM letter.list_grants();

-- Grants for a specific role
SELECT * FROM letter.list_grants('editor');
```

## letter.user_permissions(p_user_id text)

Shows all effective permissions for a user by joining their roles against grants. Handles both scoped and unscoped grants.

```sql
SELECT * FROM letter.user_permissions('a0000000-0000-0000-0000-000000000001');
```

# Letter — Read Enforcement

## Core Principle: Fully Runtime

Read enforcement is **not** based on generated views or policies. It is evaluated entirely at runtime using:

1. The current user ID (from `letter.current_user_id` GUC)
2. The contents of `letter.roles` — which roles this user has
3. The contents of `letter.grants` — what those roles permit
4. Scope data derived from the row being read

`letter.enable()` marks a table as protected and installs infrastructure, but the actual permission rules (users, roles, grants) are added and changed independently at any time. Enforcement always reflects the current state of the roles and grants tables.

## Session Caching

The roles and grants tables are small and change infrequently relative to reads. For a given user session:

- The user's roles can be looked up once and cached for the session (or transaction)
- The grants for those roles can similarly be cached
- This avoids repeated joins on every row of every query

Cache invalidation happens when `letter.current_user_id` changes (new transaction) or could be explicit.

## Per-Row Evaluation

For each row returned by a query on a protected table:

1. Determine the **scope** for this row (see Scope Resolution below)
2. Find which of the user's roles apply — both unscoped roles and roles scoped to the relevant scope_id
3. Collect the `select` grants for those roles on this table
4. For each column: if the user has a `select` grant on that column (or `*`), show the value; otherwise return NULL
5. Build a `_redacted` text array listing the columns that were NULLed due to permissions

This means the same query can return different column visibility per row, depending on the user's scoped roles.

## The _redacted Column

Every read through the enforcement layer includes a `_redacted` text array column:

```
id | name   | budget | status | _redacted
1  | Alpha  | 50000  | active | {}
2  | Beta   | NULL   | active | {budget}
3  | Gamma  | NULL   | done   | {}
```

- Row 2: `budget` was redacted — user lacks `select` on `budget` for this row's scope
- Row 3: `budget` is genuinely NULL — `_redacted` is empty

This solves the ambiguity between "value is NULL" and "value was hidden."

## Scope Resolution (Implemented)

For each row, the system determines the scope_id via the shared path-walker: direct FKs (0 hops) and table-is-scope read from the row; multi-hop `using_path` chains are walked hop by hop, with the final hop either explicit in the path or inferred when exactly one FK leads to the scope table. NULL along the chain means the grant does not apply to the row. Unresolvable configurations error loudly.

See `09-scope-resolution.md` for the full design.

## No enable()/disable()

There is no `enable()` or `disable()` function. Enforcement is derived from the grants themselves:

- Write enforcement triggers are installed by `letter.grant()` when the first grant is added to a table
- Write enforcement triggers are removed by `letter.revoke()` when the last grant is removed
- `letter.read()` checks grants at runtime — any table with grants can be read through it

## letter.read() (Implemented)

```sql
SET letter.current_user_id = 'alice';
SELECT * FROM letter.read('public.projects') t(row_data);
```

The function:
1. Fails closed if `letter.current_user_id` is not set
2. Queries all rows from the target table (with optional WHERE condition)
3. Uses the C-level session cache for role/grant lookups
4. For each row, resolves scope_id via FK introspection
5. Checks `select` grants per column — PK columns are always visible
6. Builds a JSONB object with visible columns + `_redacted` array
7. Returns `SETOF jsonb`

## Future: Planner hook (Phase 5)

Transparent enforcement on normal `SELECT * FROM tasks` queries via a C planner hook. See `10-query-hooks.md`. Once implemented, `letter.read()` can be kept as an explicit alternative or deprecated.

## Resolved Questions

- **Rows with zero visible columns:** returned with all non-PK columns redacted (PK always visible)
- **PK visibility:** always visible
- **Read mechanism:** `letter.read()` function returning JSONB (Phase 3), planner hook (Phase 5)
- **Session caching:** C-level cache in backend memory, keyed by user_id, invalidated by grant/revoke

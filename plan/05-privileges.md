# Letter — Privilege Model

## The five privileges

| Privilege | Meaning | Column granularity | Enforcement |
|---|---|---|---|
| `select` | Read rows/columns | Yes — controls which columns are visible | RLS on SELECT, or column-level grants/views |
| `insert` | Create new rows | Yes — controls which columns can be set on insert | RLS on INSERT, column-level grants |
| `update` | Modify a column regardless of its current value | Yes — controls which columns can be changed | RLS on UPDATE, column-level grants |
| `delete` | Remove rows | No — row-level only (use `*`) | RLS on DELETE |
| `set` | Set a column only if its current value is NULL | Yes — controls which NULL columns can be filled in | RLS/trigger check: allow UPDATE only where OLD.column IS NULL |

## Relationships between privileges

- `update` implies `set` — if you can change any value, you can certainly fill in a NULL
- `set` is a strict subset of `update` — you can fill blanks but not overwrite existing values
- `delete` has no column dimension — you either can or cannot delete the row

## Scope convention

The `scope` column in `letter.grants` uses an empty string `''` for unscoped (global) grants. Scoped grants use the scope table name (e.g., `'projects'`).

- `scope = ''` — grant applies to anyone with the role, regardless of scope
- `scope = 'projects'` — grant only applies when the user has the role scoped to a specific project

In `user_permissions()`, unscoped grants (`scope = ''`) match all of a user's roles. Scoped grants only match roles where `scope_table` equals the grant's `scope`.

## The `*` wildcard

When `column_name = '*'` in a grant, it means "all columns" — including columns added to the table after the grant was created. This matches PostgreSQL's own behaviour where `GRANT SELECT ON table` covers all columns.

In revoke, passing `ARRAY['*']` as the columns argument means "remove all grants for this privilege/table/role/scope combination" regardless of what column_name values exist.

## Use case for `set`

Consider a task board where tasks can be "claimed" by setting an assignee:

```sql
-- Anyone with 'member' role can claim an unassigned task
SELECT letter.grant('set', 'tasks', 'member', ARRAY['assignee_id'], 'projects', NULL, NULL);

-- But only admins can reassign tasks (overwrite existing assignee)
SELECT letter.grant('update', 'tasks', 'admin', ARRAY['assignee_id'], 'projects', NULL, NULL);
```

## Enforcement (implemented)

- **Write enforcement** via BEFORE triggers, installed automatically when grants are added to a table
- **Read enforcement** via `letter.read()` function returning JSONB with `_redacted` array
- **`set` privilege** enforced on UPDATE: allows changing a column only when OLD value is NULL
- **No `enable()`/`disable()`** — enforcement is derived from the grants themselves
- **Future: planner hook** for transparent read enforcement on normal SELECT queries

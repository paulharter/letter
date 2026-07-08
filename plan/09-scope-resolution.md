# Letter — Scope Resolution

## The Problem

Grants can be scoped: "editor can `select` `budget` on `tasks`, scoped to `projects`." When evaluating permissions on a `tasks` row, the system needs to determine which `projects` scope_id applies to that row.

The path from the protected table to the scope table varies:

- **Direct:** `tasks.project_id` → scope is right on the row (zero hops)
- **One hop:** `comments.task_id` → `tasks.project_id` (one FK join)
- **Multi-hop:** `comment_reactions.comment_id` → `comments.task_id` → `tasks.project_id` (two FK joins)

## using_path

The `using_path` column in `letter.grants` is a `text[]` (PostgreSQL array) of FK column names describing the many-to-one chain from the protected table to the scope table.

### Direction: Many-to-One Only

The path always follows FK columns "upward" — from child to parent. Each hop resolves to exactly one row. This means:

- One-to-many (downward) paths are not supported — a row should resolve to one scope, not many
- Many-to-many paths are not supported — these are handled by the role/assignment system instead

### Examples

**Direct** — scope column is on the row itself:

```sql
-- tasks.project_id points directly to projects
SELECT letter.grant('select', 'tasks', 'editor', ARRAY['budget'], 'projects',
    NULL,  -- using_path: NULL means scope column is on the row
    NULL);
```

The system infers the FK from `tasks` to `projects` automatically.

**One hop** — follow one FK:

```sql
-- comments.task_id → tasks, and tasks has project_id → projects
SELECT letter.grant('select', 'comments', 'editor', ARRAY['body'], 'projects',
    '{task_id}',  -- follow task_id FK to tasks, then find projects FK
    NULL);
```

**Multi-hop** — follow a chain of FKs:

```sql
-- comment_reactions.comment_id → comments.task_id → tasks.project_id → projects
SELECT letter.grant('select', 'comment_reactions', 'viewer', ARRAY['emoji'], 'projects',
    '{comment_id, task_id}',  -- follow comment_id to comments, then task_id to tasks
    NULL);
```

The final hop (from `tasks` to `projects`) is inferred — the system looks up the FK from the last table in the chain to the scope table. Inference requires exactly **one** such FK; zero or multiple is an error at grant time and enforcement time. When the last table has more than one FK to the scope (e.g. `owner_project_id` and `source_project_id`), extend `using_path` with the final hop column explicitly — a path whose last hop lands on the scope table itself needs no inference.

### Resolution logic

Given `using_path = '{comment_id, task_id}'` and scope `'projects'`:

1. Start at the protected table (`comment_reactions`)
2. Follow `comment_id` FK → look up `pg_constraint` to find it points to `comments`
3. Follow `task_id` FK on `comments` → look up to find it points to `tasks`
4. Find the FK from `tasks` to `projects` (the scope table) → get the scope_id
5. Result: one `projects` scope_id for this row

Each hop is validated: the column must be an FK, and it must resolve to exactly one target table.

### NULL using_path

When `using_path` is NULL, the system looks for a direct FK from the protected table to the scope table. If none exists, it's an error at grant time.

## Schema Change

`using_path` should be changed from `text` to `text[]` in `letter.grants`:

```sql
using_path text[]  -- was: using_path text
```

## Default Mechanism: Runtime Joins

Scope resolution uses runtime joins along the FK chain. For a query returning many rows, PostgreSQL turns this into a standard multi-table join plan — not per-row lookups. With indexed FK/PK columns:

- 0-1 hops: negligible (sub-millisecond)
- 2-3 hops: typically 1-5ms additional
- These are PK/FK index lookups, which PostgreSQL excels at

## Optional: Scope Index Cache

For tables with deep paths (3+ hops) and high read volume, an optional scope index provides Russian-doll caching. See below.

### Structure

```sql
letter.scope_index (
    table_name  text NOT NULL,
    row_id      text NOT NULL,
    scope_table text NOT NULL,
    scope_id    text NOT NULL,
    path        text[],         -- e.g., {'comments:99', 'tasks:12', 'projects:42'}
    PRIMARY KEY (table_name, row_id, scope_table)
)
```

The `path` array records every intermediate scope in the chain, enabling efficient invalidation.

### Russian-Doll Invalidation

If task 12 moves to a different project:

```sql
DELETE FROM letter.scope_index WHERE 'tasks:12' = ANY(path);
```

One query invalidates everything nested under that task. No recomputation — entries are repopulated lazily on next read.

### Opting In

The mechanism for opting into the scope cache is TBD — there is no `enable()` function. It could be a separate function or a parameter on `letter.grant()`. Without the cache, scope resolution always uses runtime joins.

## Limitations

- Many-to-one only — covers approximately 90% of real-world permission models
- Deep paths (4+ hops) are supported but may benefit from the scope index cache
- Tables with two FKs to the same target table from the same column are not supported (rare/invalid in practice)
- Validated at grant time: each column in the path must be an FK resolving to exactly one target

# Letter — Schema

## Tables

### letter.roles

The denormalized result: "user X has role Y, optionally scoped to a specific row in a table."

| Column | Type | Description |
|---|---|---|
| id | uuid PK | Auto-generated |
| role | varchar(64) | Role name (e.g., `editor`, `admin`) |
| user_id | varchar(256) | The user who holds this role |
| scope_table | varchar(64) | Table the role is scoped to (nullable) |
| scope_id | varchar(256) | Row ID in the scope table (nullable) |

Unscoped roles have `scope_table` and `scope_id` as NULL (e.g., a global `superadmin` role).

### letter.grants

Declarations of what privileges a role has on a table, per-column.

| Column | Type | Description |
|---|---|---|
| privilege | varchar(20) | One of: `select`, `insert`, `update`, `delete`, `set` |
| on_table | varchar(64) | The table the privilege applies to |
| role | varchar(64) | The role being granted the privilege |
| column_name | varchar(64) | Column name, or `*` for all columns |
| scope | varchar(64) | Scope table name for scoped grants, or `''` for unscoped |
| using_path | text[] | Array of FK column names for scope resolution (nullable) |
| check_fn | text | Check function expression (nullable) |

**Primary key:** `(privilege, on_table, role, scope, column_name)`

### letter.assignments

Rules that describe how roles get automatically assigned based on data in application tables.

| Column | Type | Description |
|---|---|---|
| id | uuid PK | Auto-generated |
| table_name | varchar(64) | Source table to watch |
| scope_table | varchar(64) | Scope table (nullable for unscoped) |
| user_column | varchar(64) | Column in source table that references the user |
| role_name | varchar(64) | Fixed role name to assign (nullable) |
| role_column | varchar(64) | Column in source table containing the role name (nullable) |
| if_fn | text | Condition expression — role is only assigned when this evaluates to true (nullable) |

**Constraint:** Exactly one of `role_name` or `role_column` must be set (CHECK constraint `role_name_or_column`).

### letter.role_assignments

Links each assigned role back to the rule and source row that created it. Enables cleanup.

| Column | Type | Description |
|---|---|---|
| id | uuid PK | Auto-generated |
| assignment_id | uuid FK | References `assignments(id)` ON DELETE CASCADE |
| role_id | uuid FK | References `roles(id)` |
| source_table | varchar(64) | Source table name |
| source_id | text | Primary key of the source row |
| user_id | text | The user who received the role |
| scope_table | varchar(64) | Scope table (nullable) |
| scope_id | text | Scope row ID (nullable) |

## Triggers

### role_assignment_cleanup

`AFTER DELETE ON letter.role_assignments` — when a role_assignment row is deleted (by any mechanism), the associated `letter.roles` row is also deleted. Implemented in C (`letter_role_cleanup`).

### Per-assignment triggers (created dynamically by `assign()`)

For each assignment rule, three triggers are installed on the source table:

- `letter_insert_<safe_id>` — AFTER INSERT, creates a role
- `letter_update_<safe_id>` — AFTER UPDATE, updates or removes a role
- `letter_delete_<safe_id>` — AFTER DELETE, removes the role_assignment

If the assignment is scoped, an additional trigger is installed on the scope table:

- `letter_scope_delete_<safe_id>` — BEFORE DELETE, removes role_assignments for that scope row

Where `<safe_id>` is the assignment UUID with dashes replaced by underscores.

### Enforcement triggers (installed automatically by `grant()`)

When the first grant is added to a table, three generic BEFORE triggers are installed:

- `letter_enforce_insert` — BEFORE INSERT, row-level check
- `letter_enforce_update` — BEFORE UPDATE, per-column check (update vs set)
- `letter_enforce_delete` — BEFORE DELETE, row-level check

These are removed by `revoke()` when the last grant is removed from a table. The trigger functions are generic C functions that read grants at runtime — no per-table code generation.

## GUCs

- `letter.current_user_id` (string) — the application user ID for the current transaction. Must be set via `SET` or `SET LOCAL` before any enforced operation. Empty string = not set. Settable by any role **by design** — see the trust boundary note in `06-enforcement.md`.
- `letter.bypass` (boolean, default false, **superuser-only** `PGC_SUSET`) — when true, skips all enforcement. For migrations and admin operations. Grant to non-superuser migration roles with `GRANT SET ON PARAMETER letter.bypass`.

## Session Cache

The current user's roles and grants are cached in backend-local C memory on first enforcement check. The cache is keyed by `letter.current_user_id` and automatically repopulated when the user ID changes. Statement-level triggers (`letter.cache_inval`) on `letter.roles` and `letter.grants` invalidate it on any write to either table — including writes made by assignment triggers — so role and grant changes take effect immediately within the backend. (Cross-backend invalidation is not yet implemented.)

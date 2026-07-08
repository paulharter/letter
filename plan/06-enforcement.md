add# Letter — Enforcement Overview

## Core Principles

1. **Fully runtime** — enforcement always reads from the live `roles` and `grants` tables. No policies, views, or rules are generated from the permission data. Roles and grants can be changed at any time and enforcement immediately reflects the current state.

2. **Fail closed** — if `letter.current_user_id` is not set, all operations on tables with grants are denied (for app users). Table owners may bypass enforcement for migrations and admin operations.

3. **No enable/disable** — there is no `letter.enable()` or `letter.disable()` function. A table is implicitly enforced if it has any grants in `letter.grants`. Write enforcement triggers are installed automatically by `letter.grant()` when the first grant is added to a table, and removed by `letter.revoke()` when the last grant is removed.

4. **Grants are the source of truth** — the set of protected tables is always derivable from `letter.grants`. No separate metadata table needed.

## User Identity

The current user is identified via a transaction-local GUC:

```sql
SET LOCAL letter.current_user_id = 'alice';
```

The application must set this at the start of every transaction. Triggers and read enforcement read the identity via `current_setting('letter.current_user_id', true)`.

If not set, NULL, or empty: deny all operations on tables with grants (unless `letter.bypass` is true).

**Trust boundary (explicit precondition).** `letter.current_user_id` is deliberately
settable by any role — the application sets it per transaction on behalf of its end
users. This is only safe because **letter assumes end users never hold a raw SQL
connection**: the application layer that sets the GUC is the enforcement perimeter,
exactly the PostgREST/Supabase request-scoped-settings model. Anyone who can run
arbitrary SQL on the database can impersonate any user by setting the GUC; that is
outside letter's threat model and must be prevented at the connection layer, not by
letter.

`letter.bypass`, by contrast, is `PGC_SUSET`: only superusers can set it, and
migration/admin roles must be granted access explicitly
(`GRANT SET ON PARAMETER letter.bypass TO migrator`). The users being enforced can
never switch enforcement off.

The GUC value must match the `::text` representation of the user table's primary key. Since `letter.roles.user_id` is stored as text (cast via `::text` by assignment triggers), the application must pass the same text form. For UUID keys this means lowercase (`a0000000-...`), which is PostgreSQL's default `uuid::text` output. For integer keys, just the number as a string (`'42'`).

## Scope

The `scope` column in `letter.grants` is a **logical scope name**, not necessarily a table name. It identifies which scope context a grant applies in. The `using_path` column (a `text[]` array of FK column names) describes the physical FK chain from the protected table to the scope table.

A table can have grants with different scope values. The enforcement layer checks each grant's scope independently.

## Write Enforcement

Implemented via BEFORE triggers on tables that have grants.

### Trigger Lifecycle

- `letter.grant()` checks if the target table already has enforcement triggers. If not, it installs them.
- `letter.revoke()` checks if the target table has any remaining grants. If not, it removes the triggers.
- This means enforcement triggers are always in sync with the grants — no separate enable/disable state.

### BEFORE INSERT

For each non-null column being set:
- Check the user has `insert` on that column (or `*`)

### BEFORE UPDATE

For each column that actually changed (comparing NEW vs OLD):
- If OLD value is NULL → user needs `set` or `update` on that column
- If OLD value is not NULL → user needs `update` on that column
- Columns that did not change are not checked

### BEFORE DELETE

- Check the user has `delete` with `*` column

### Write check logic

1. Read `letter.current_user_id` — deny if not set (unless table owner)
2. Look up the user's roles from `letter.roles`
3. Determine the scope for this row via `using_path` (runtime FK joins)
4. For each required column/privilege, check if any applicable role has a matching grant
5. If any check fails, raise an exception with details of what was denied

## Read Enforcement

Not trigger-based (triggers don't fire on SELECT). Implemented via `letter.read()` function. See `08-read-enforcement.md`.

Key properties:
- Per-row column filtering based on the user's scoped roles and grants
- Columns the user cannot see are returned as NULL
- A `_redacted` text array column distinguishes real NULLs from permission-hidden values
- PK columns are always visible
- Fully runtime, no generated views or policies

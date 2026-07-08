# Letter — Open Questions

## Resolved

### User identity
**Decision:** Transaction-local GUC `letter.current_user_id` set via `SET LOCAL`. Fail closed if not set. Same pattern as PostgREST/Supabase.

### Scope resolution mechanism
**Decision:** Runtime joins by default using the FK chain described in `using_path`. Optional scope index cache with Russian-doll invalidation for deep paths. See `09-scope-resolution.md`.

### Read enforcement approach
**Decision:** Fully runtime, no generated views or policies. Per-row column filtering with `_redacted` array. Roles and grants cached per session. See `08-read-enforcement.md`.

### Performance of scope joins
**Decision:** PK/FK joins are fast (sub-millisecond for 0-1 hops, 1-5ms for 2-3 hops). Acceptable for the default case. Scope index cache available for hot paths.

### using_path syntax
**Decision:** `text[]` array of FK column names. Many-to-one only. Already implemented.

### Read mechanism API
**Decision:** `letter.read()` function first (Phase 3), planner hook later (Phase 5).

### Custom GUC registration
**Decision:** Register `letter.current_user_id` in `_PG_init()`. Straightforward.

### Column detection on UPDATE
**Decision:** Compare `NEW` and `OLD` for each column. Only check columns that actually changed. Skip no-op changes (e.g., `SET name = name`).

### No enable() / disable()
**Decision:** Drop `enable()` and `disable()` entirely. Enforcement is derived from the grants themselves:
- Any table that has grants in `letter.grants` is implicitly "enabled"
- Write enforcement triggers are installed by `letter.grant()` when the first grant is added to a table, and removed by `letter.revoke()` when the last grant is removed
- `letter.read()` checks if grants exist for the table
- No `letter.enabled_tables` metadata table needed
- This eliminates the fragility of having separate enforcement state that can diverge from actual grants

### Multiple scopes per table
**Decision:** Yes. A table can have grants with different scope values. The scope name in a grant is a logical identifier, not necessarily a table name. The `using_path` connects the logical scope to the physical FK chain. The enforcement layer checks each grant's scope independently.

### Scope naming
**Decision:** The `scope` column in `letter.grants` is a logical scope name, not necessarily a table name. It identifies which scope context applies. The `using_path` describes the physical FK chain from the protected table to the scope table. This distinction should be clear in the API and documentation.

### PK visibility
**Decision:** Primary key columns are always visible in read enforcement. A row must be identifiable even when other columns are redacted.

### Superuser / bypass
**Decision:** Still needs thought. Options:
- The table owner bypasses enforcement triggers (check `pg_class.relowner` against `current_user`)
- A `letter.bypass` GUC that disables enforcement when set
- Superusers automatically bypass
- For now: if `letter.current_user_id` is not set AND the current database role is the table owner, allow the operation. This lets migrations and admin operations work without the GUC while still failing closed for app users.

## Still Open

### 1. Superuser / bypass details
The table-owner bypass needs design. Should it check `current_user = table owner`? Should it check for superuser status? Should there be an explicit GUC?

### 2. Session caching implementation
How are roles and grants cached per session? Defer until we have basic enforcement working, then optimise.

### 3. Mid-session grant changes
If roles/grants are cached, changes within a session may not take effect immediately. Defer with caching.

### 4. Rows with zero access
If a user has no `select` grants on any column of a row (for the relevant scope), should the row be excluded or returned fully redacted? **Deferred as a possible future feature.** For now, return the row with all non-PK columns redacted.

### 5. check_fn design
The `check_fn` column in `letter.grants` is intended to be a row-level predicate — an additional condition beyond role/scope that must pass for the grant to apply. It receives the row(s) being operated on and returns boolean.

Open questions:
- **What arguments does it receive?** On read/delete: the existing row. On write: old and new rows. On insert: just the new row. How are these referenced in the expression? (`row`/`old`/`new`, positional, bare column names?)
- **Is it an inline SQL expression or a function name?** Inline is more convenient but harder to validate. A function reference is safer but more ceremony.
- **Scope:** Is check_fn per-grant (shared across all columns in the grant) or per-column? Currently it's per-grant row, meaning one check_fn applies to all columns granted in that call.
- **For `set` privilege:** does check_fn receive old row (with NULL) and new row (with the proposed value)?
- **Validation:** Should `letter.grant()` validate the expression at grant time, or only at enforcement time?

This is deferred — `check_fn` exists in the schema but is not evaluated by enforcement until the design is resolved.

### 6. Trigger installation by grant/revoke
When `letter.grant()` adds the first grant for a table, it needs to install write enforcement triggers. When `letter.revoke()` removes the last grant, it needs to remove them. Design the trigger management logic.

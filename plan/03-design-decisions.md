# Letter — Design Decisions

Changes and improvements over the legacy ElectricSQL implementation.

## Single role_assignments table instead of dynamic per-rule join tables

**Legacy:** Each `assign()` call created a new table (`electric.assignment_<uuid>_join`) with polymorphic foreign keys. This made the schema unpredictable and debugging difficult.

**Letter:** A single `letter.role_assignments` table stores all assignment results. The table has a real FK to `letter.assignments` with ON DELETE CASCADE, plus text columns for source/scope references.

**Tradeoff:** We lose automatic FK cascade cleanup for source and scope rows, but replace it with explicit DELETE triggers on those tables. The benefit is a fully predictable schema — only four tables, ever.

## Cleanup via triggers instead of cascading FKs

The cleanup contract: a role_assignment (and its associated role) is deleted when any of these are removed:

| What is deleted | Mechanism |
|---|---|
| Assignment rule | FK CASCADE from `assignments` → `role_assignments` |
| Source row | DELETE trigger on source table |
| Scope row | DELETE trigger on scope table |
| User | Transitive — source table's FK to users should CASCADE, deleting the source row, which fires our trigger |

In all cases, the `role_assignment_cleanup` trigger on `role_assignments` deletes the orphaned `letter.roles` row.

## C implementation with SPI

**Legacy:** Pure PL/pgSQL with heavy use of `EXECUTE format(...)` for dynamic DDL.

**Letter:** Core functions (`grant`, `revoke`, `assign`, `unassign`, `role_cleanup`) are implemented in C using PostgreSQL's SPI (Server Programming Interface). Dynamic SQL is still needed for trigger creation and catalog introspection, but the orchestration logic is in C.

## Per-assignment trigger functions (not generic)

Each assignment rule gets its own trigger functions with column references baked in (e.g., `NEW.user_id`, `NEW.project_id`). This is necessary because PL/pgSQL trigger functions cannot dynamically reference columns by name from `NEW`/`OLD` without `EXECUTE`.

An alternative would be fully generic trigger functions that use `EXECUTE format(...)` internally, but per-assignment functions are more straightforward and avoid the overhead of dynamic SQL on every row operation.

## Sentinel `*` for column wildcards

`column_name = '*'` in the grants table means "all columns." This matches PostgreSQL's own semantics where `GRANT SELECT ON table` covers all columns including ones added later. The alternative — expanding `*` to all current columns at grant time — would miss columns added after the grant.

## CHECK constraint on assignments

The `role_name_or_column` CHECK constraint enforces that exactly one of `role_name` (fixed string) or `role_column` (column reference) is provided. The legacy code used `__none__` sentinel values; the CHECK constraint is cleaner and catches errors at insert time.

## Nullable scope_table in assignments

**Legacy:** Used `__none__` sentinel string for unscoped assignments.

**Letter:** `scope_table` is nullable. NULL means unscoped. This is more idiomatic and avoids sentinel value comparisons.

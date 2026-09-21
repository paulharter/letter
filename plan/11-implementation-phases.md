# Letter — Implementation Phases and TODO

Single source of truth for implementation status. Each phase has high-level scope and a detailed checklist. "Issues to Resolve" captures design decisions made (or pending) between phases.

> **Before Phase 5:** see `14-enforcement-gaps.md` for a structural review of enforcement gaps and data-leak vectors. As of 2026-07-08 the foundational holes are closed (bypass is SUSET, trust boundary documented, runtime injection paths parameterized, UPDATE checks OLD+NEW scope, multi-hop resolves for real, backend-local cache invalidation on role/grant writes — tests in `test/sql/hardening.sql` and `test/sql/multihop.sql`). Still open: §1 predicate/join leak (**gates Phase 5**, design in `15-join-enforcement.md`), §4.1 cross-backend cache incoherence, §4.3 stringified read.
>
> **Join/predicate enforcement design:** see `15-join-enforcement.md` for the chosen direction — source-redaction via per-table barrier subqueries (Option B), targeted result-relation redaction on the write path (quals, SET RHS, RETURNING, ON CONFLICT/MERGE — §8), per-hop conjunctive gating on transient join steps, and the decision to stay bounded (no recursion / many-to-many). Write privileges remain trigger-enforced: triggers decide writability, the hook decides visibility. Reframes item 2.4.4 (multi-hop) as the prerequisite. D2 is decided: per-hop gating is opt-in via an explicit `enforce_path_visibility` flag on the grant (§7.4). Remaining open decisions: plan-cache keying (reframed — `16` §7), `_redacted` under transparent reads.
>
> **Scope resolution direction (2026-09-21):** see `16-scope-resolution-direction.md`. Read cost must scale with the user's scope set, not candidate rows → the hook generates B2 joins directly (no B1 function), in the "join up once, test in `WHERE` and every `CASE`" form, reading the user's scopes from `letter.roles` at execution time (generic plans; closes `14` §4.1 for reads). Non-authoritative / per-backend / per-user expansion caches are rejected (stale-allow). Phase 4 is redefined as intermediate-table materialisation. Sequencing: `16` §9. **Done 2026-09-21:** the EXPLAIN experiment (5.0 — `bench/barrier/RESULTS.md`), walker performance (2.7) and the FK-index warning (1.7); 11 regression tests green. **Next: the planner hook (5.1–5.6), generating the `IN (SELECT …)` / `UNION ALL` form the experiment selected.**

## Phase 1: Core Tables and Functions (COMPLETE)

The metadata layer that stores permissions.

- [x] `letter.roles` table
- [x] `letter.grants` table
- [x] `letter.assignments` table
- [x] `letter.role_assignments` table with cleanup trigger
- [x] `letter.grant()` / `letter.revoke()` functions
- [x] `letter.assign()` / `letter.unassign()` functions
- [x] `letter.list_grants()` / `letter.user_permissions()` info functions
- [x] Schema-qualified table names (`public.tasks` format) enforced everywhere
- [x] `using_path` changed to `text[]`
- [x] Scope convention: `''` for unscoped grants
- [x] Regression tests for all of the above

### Phase 1 Additions (metadata layer)

Items that build on the completed Phase 1 but don't require enforcement.

- [x] **1.1** Update `plan/02-schema.md` to reflect `using_path` as `text[]` and scope convention (`''` for unscoped)
- [x] **1.2** Update `plan/04-functions.md` to document `list_grants()`, `user_permissions()`, and `read()`
- [x] **1.3** Add indexes on `roles(user_id)` and `roles(role)` for enforcement query performance
- [x] **1.4** Add index on `grants(on_table, role)` for enforcement query performance
- [x] **1.5** Validate in `letter.grant()` that `using_path` FK columns actually exist (query `pg_constraint`) — error at grant time rather than enforcement time. Skipped silently when the target table doesn't exist yet (preserves the ability to declare grants before their target table, per item 2.3.3).
- [ ] **1.6** Consider: should `letter.grant()` validate that the `on_table` exists? Decision: no — by design `letter.grant()` tolerates missing tables (item 2.3.3) so grants can be declared before their target table is created. Close as won't-do.
- [x] **1.7** `letter.grant()` raises a `WARNING` (with a `CREATE INDEX` hint) when a `using_path` column or the inferred final-hop FK column has no usable btree index — reads cannot be driven from the scope side without it (`16` §3.4). Warning, not error; **`select` grants only** (the write path never needs the index). "Usable" = valid, non-partial btree with the column leading. Done 2026-09-21 (`warn_if_unindexed`); tests: `test/sql/index_warning.sql`. Existing tests now show the warning wherever their schemas lack FK indexes.

## Issues to Resolve Before Phase 2

### A. Schema-qualified table names — RESOLVED
**Decision:** Always require `'schema.table'` format (e.g., `'public.tasks'`). Verbose but explicit. Applies to `on_table` in grants, `table_name` in assignments, and all function arguments that take table names. Implemented via `split_table_name()` in all four functions, with scope resolution consuming schema-qualified names throughout. All tests updated.

### B. INSERT column enforcement — DEFERRED to Phase 5
**Decision:** Current implementation is **row-level only** — the BEFORE INSERT trigger checks that the user has any `insert` grant on the table, not per-column. The `column_name` value in insert grants is stored but not consulted at enforcement time.

**Why row-level only:** Column-level INSERT cannot be done cleanly in a row-level trigger. By the time `letter_enforce_insert` fires, DEFAULTs have already been substituted into `NEW`, so user-supplied values are indistinguishable from defaults. Approaches considered:
- **`pg_attrdef` introspection** — rejected as leaky. Can't handle non-deterministic defaults (`gen_random_uuid()`, `now()`), can't distinguish explicit NULL from omitted column, any user value that happens to equal the default becomes a false negative.
- **`post_parse_analyze_hook`** — correct solution. Hook inspects the parsed `InsertStmt`, extracts the explicit column list, stashes it keyed by command ID for the row trigger to read.
- **Accept row-level, document** — pragmatic, but we want the real fix.

**Why Phase 5:** Phase 5 already introduces parse/plan-hook infrastructure (hook registration, version-compatibility testing, backend-local state management) for transparent read enforcement. The INSERT column hook piggybacks on that work at low marginal cost. See items 5.11–5.19.

### C. Trigger ordering with assign() — NOTED
Enforcement BEFORE triggers fire before assignment AFTER triggers. If enforcement is on an assignment source table (e.g., `team_members`), inserts could be denied before roles are created. **This is by design** — assignment source tables are typically managed by the application, not by end users subject to enforcement. Don't add enforcement grants on assignment source tables unless the app user should be directly modifying assignments.

**TODO:** Document this interaction clearly in the plan and in any future user documentation.

### D. Extension drop / cleanup — DEFERRED
See **Phase 6: Cleanup and Lifecycle** below.

### E. letter.read() return type — RESOLVED
**Decision:** Return JSONB rows for Phase 3. Each row is a JSONB object with column names as keys, plus a `_redacted` key containing an array of redacted column names. The planner hook (Phase 5) will provide native SQL types.

## Phase 2: Write Enforcement (COMPLETE)

BEFORE triggers on tables with grants, installed/removed automatically by grant/revoke.

### 2.1 GUC Registration
- [x] **2.1.1** Register `letter.current_user_id` as a custom string GUC in `_PG_init()` with empty string default
- [x] **2.1.2** Register `letter.bypass` as a custom bool GUC
- [x] **2.1.3** Test: GUC works

### 2.2 Enforcement Trigger Functions (C)
These are generic C trigger functions installed on protected tables. They read grants at runtime.

- [x] **2.2.1** `letter_enforce_insert()` — BEFORE INSERT trigger (row-level check)
- [x] **2.2.2** `letter_enforce_update()` — BEFORE UPDATE trigger (per-column, set vs update)
- [x] **2.2.3** `letter_enforce_delete()` — BEFORE DELETE trigger
- [x] **2.2.4** Bypass via `letter.bypass` GUC (replaced table owner check)
- [x] **2.2.5** Fail closed when `letter.current_user_id` is not set

### 2.3 Automatic Trigger Management
- [x] **2.3.1** `letter.grant()` auto-installs enforcement triggers on first grant to a table
- [x] **2.3.2** `letter.revoke()` auto-removes enforcement triggers when last grant is removed
- [x] **2.3.3** Graceful when table doesn't exist yet (stores grant, skips trigger install)

### 2.4 Scope Resolution for Write Enforcement
- [x] **2.4.1** Scope resolution for direct FK (0 hops) and table-is-scope cases
- [x] **2.4.2** Unscoped grants (`scope = ''`) always apply
- [x] **2.4.3** Multiple scopes handled — each grant's scope checked independently
- [x] **2.4.4** Multi-hop `using_path` resolution via the shared path-walker (`walk_scope_path`), used by both write triggers and `letter.read()` (D5). Explicit final hop supported (path may land on the scope table); inferred final hop requires exactly one FK, errors on zero or ambiguous (closes `14` §3.2). NULL along the chain → grant does not apply (D4); misconfiguration fails loudly at grant *and* enforcement time — the fail-open fallback is gone (`14` §3.1). "Table is scope" fallback now fires only when the table *is* the scope table (`14` §3.3). Grant-time validation extended to the final hop, the direct case, and rejects `using_path` on unscoped grants (`13` issue 3). Tests: `test/sql/multihop.sql`.

### 2.5a Session Cache
- [x] **2.5a.1** C-level session cache for roles and grants
- [x] **2.5a.2** Cache keyed by user_id, repopulated on change
- [x] **2.5a.3** Invalidated by grant/revoke calls

### 2.5 Tests
- [x] **2.5.1** Test: INSERT allowed/denied
- [x] **2.5.2** Test: INSERT denied when `letter.current_user_id` not set
- [x] **2.5.3** Test: UPDATE allowed with `update` grant
- [x] **2.5.4** Test: UPDATE denied on column without grant
- [x] **2.5.5** Test: SET allowed when OLD is NULL
- [x] **2.5.6** Test: SET denied when OLD is not NULL
- [x] **2.5.7** Test: DELETE allowed/denied
- [x] **2.5.8** Test: Scoped grants — user can update in their scope but not another
- [x] **2.5.9** Test: Unscoped grants work
- [x] **2.5.10** Test: Triggers auto-installed on first grant, auto-removed on last revoke
- [ ] **2.5.11** Test: Multiple roles — user with multiple roles gets union of permissions
- [ ] **2.5.12** Test: Enforcement triggers don't interfere with assignment triggers on same table

### 2.6 Known Gaps
- [ ] **2.6.1** INSERT column-level enforcement — deferred to Phase 5 (see Issue B and items 5.11–5.19)

### 2.7 Path-Walker Performance (`16` §6) (COMPLETE 2026-09-21)
No change to what is enforced. Independent of Phase 5. Tests: `test/sql/walker_cache.sql`.

- [x] **2.7.1** Saved plans (`SPI_prepare` + `SPI_keepplan`) for each fetched hop — previously every hop re-parsed and re-planned its query for every row
- [x] **2.7.2** Each distinct `(table, scope, using_path)` compiled once per backend into a hop list (`get_compiled_scope_path`) — no `pg_constraint` lookups per row. Keyed by path content, so grants sharing a path share the compiled form. Dropped wholesale on any relcache invalidation (flush deferred to the next lookup, never mid-walk). One behavioural tightening: misconfiguration errors now surface at compile time, i.e. before a NULL first hop could short-circuit the walk — stricter fail-loud, no test depended on the old order.
- [x] **2.7.3** Statement-local memo `(compiled path, first-hop key) → scope_id | does-not-apply`, shared across rows and across grants with the same path. Discarded when the command id changes, at (sub)transaction end, and above 8192 entries. Safe because the walker's fetches run `read_only` under the statement's snapshot.
- [x] **2.7.4** Benchmark (`bench/walker/`): 10k-row bulk insert through a 2-hop path **9.85 s → 46 ms**; `letter.read()` over 20k rows **39.1 s → 23 ms**; single-row insert 1.05 ms → 0.12 ms.

## Phase 3: Read Enforcement via Function (COMPLETE)

A `letter.read()` function that performs enforced reads, returning JSONB.

### 3.1 letter.read() Function
- [x] **3.1.1** `letter.read(table_name, condition)` returns `SETOF jsonb`
- [x] **3.1.2** Dynamic SELECT with per-row per-column grant checking
- [x] **3.1.3** PK always visible
- [x] **3.1.4** Scope resolution per row (same as write enforcement)
- [x] **3.1.5** `_redacted` key in JSONB output: array of column names that were NULLed
- [x] **3.1.6** Columns without `select` permission returned as NULL
- [x] **3.1.7** Scope-aware: grant's role must match a scoped role with the correct scope_id (fixed cross-role scope leakage bug)

### 3.2 Caching
- [x] **3.2.1** Uses the same C-level session cache as write enforcement
- [x] **3.2.2** Cache shared across `letter.read()` and write triggers — no extra SPI cost

### 3.3 Tests
- [x] **3.3.1** Test: columns with `select` grant are visible
- [x] **3.3.2** Test: columns without `select` grant return NULL with `_redacted`
- [x] **3.3.3** Test: genuine NULL vs redacted NULL distinguishable
- [x] **3.3.4** Test: PK columns always visible
- [x] **3.3.5** Test: `*` wildcard grant shows all columns
- [x] **3.3.6** Test: scoped grants — mixed visibility per row
- [x] **3.3.7** Test: user with no roles sees only PK columns
- [x] **3.3.8** Test: fails closed when `letter.current_user_id` not set

## Phase 4: Intermediate-Table Materialisation (Optional, after Phase 5a)

Redefined 2026-09-21 — see `16-scope-resolution-direction.md` §5. Replaces the leaf-keyed, lazily-populated `letter.scope_index` of `09-scope-resolution.md` (superseded: database-sized, amplifies every leaf write, and lazy population means the read path writes). Build only if the 5.0 / 5a measurements ask for it, and only for chains with ≥ 2 hops above the leaf's parent.

- [ ] **4.1** `letter.row_scopes (table_name, row_id, scope_table, scope_id)` + index `(scope_table, scope_id, table_name)`
- [ ] **4.2** `letter.materialize('schema.table')` / `letter.dematerialize()` — opt-in, **intermediate tables only**; reject (or warn loudly) for a table that is only ever a leaf
- [ ] **4.3** Eager trigger maintenance in the writing transaction: insert/delete of the table's rows, and re-parenting of the row or any ancestor (no lazy population — stale-allow is not acceptable, `16` §4)
- [ ] **4.4** Generator uses the closure when present; grants with `enforce_path_visibility` ignore it (`16` §5)
- [ ] **4.5** Tests: result-equivalence with and without materialisation; re-parent an intermediate node mid-transaction; concurrent re-parent vs read

## Phase 5: Parse/Plan Hooks

Extension hooks that operate on the parse tree and plan tree. Two related workstreams that share hook-registration and version-compatibility infrastructure: transparent read enforcement (replacing `letter.read()`) and column-level INSERT enforcement (resolving Issue B). See `10-query-hooks.md` for the read-path design.

### 5a. Transparent Read Enforcement via Planner Hook

Replace `letter.read()` with invisible enforcement on normal SELECT queries.

**Implementation plan: `17-planner-hook-implementation.md`** — steps H0 (spike) → H1 (infrastructure: 5.1, 5.2, 5.8) → H2 (SQL generator: 5.3, 5.5, 5.6) → H3 (substitution, nested from day one: 5.3, 5.7) → H4 (plan/cache invalidation: 5.6) → H5 (behavioural tests, flip `letter.enforce_reads` on) → H6 (`COPY TO` side door, `letter.read()` fate: 5.10). Key simplifications: convert the RTE *in place* like view expansion (no Var fix-up), and generate the barrier as SQL text parsed by the real parser. Decided 2026-09-21: unset user id → reads return zero rows (D2); composite PKs rejected at grant time for scope/hop tables, allowed on leaves (D4). `letter.read()`/`_redacted` (D3) deferred to H6.

- [x] **5.0** **Experiment before any hook code (`16` §8 Q1)** — done 2026-09-21, harness + write-up in `bench/barrier/` (`RESULTS.md`). Planner does drive from the scope side inside the barrier (0.6 ms vs 4.6 s for a B1-style function, 698 of 1M rows). Chosen form: `IN (SELECT … FROM letter.roles)` for `WHERE` (semijoin) and each `CASE` (hashed SubPlan) — **no arrays**; `OR`-shaped visibility must be generated as mutually exclusive `UNION ALL` branches.
- [ ] **5.1** Register planner hook in `_PG_init()`
- [ ] **5.2** Detect queries targeting tables that have grants
- [ ] **5.3** Replace each protected RTE with a redacting barrier subquery (`15` Option B) — per-column `CASE` expressions testing the exposed scope-id column(s), plus Var fix-up
- [ ] **5.4** Add `_redacted` column to query target list (open — `15` §9 decision 3)
- [ ] **5.5** Scope resolution as `LEFT JOIN`s up the FK chain inside the barrier; one `UNION ALL` branch per distinct `(scope, using_path)` group with a strict `IN (SELECT …)` row-visibility test, plus a `One-Time Filter`-gated branch for unscoped grants; role-side cast to the PK type (`16` §3.2 rules 1, 4, 5)
- [ ] **5.6** User's scope sets read from `letter.roles` at execution time — nothing user-specific in the rewritten tree (`16` §3.2 rule 3, §7 option a). Test asserts it. Cached plans reset when `letter.grants` changes. Injected `letter.roles` RTE must not require the caller to hold `SELECT` on it.
- [ ] **5.7** Handle: SELECT *, subqueries, CTEs, joins across enforced/non-enforced tables
- [ ] **5.8** Fast early exit for queries not touching tables with grants
- [ ] **5.9** Version compatibility testing (PG16, PG17)
- [ ] **5.10** Deprecate `letter.read()` or keep as explicit alternative — if kept, it must be rebuilt on the hook's barrier-subquery machinery; it cannot survive unchanged. Once the planner hook lands, `letter.read()` is the leakier path (raw-interpolated `condition` + sink redaction = injection + predicate oracle). See `15-join-enforcement.md` §9 decision 3.

### 5b. INSERT Column-Level Enforcement via post_parse_analyze_hook

Captures the explicit INSERT column list at parse time so the row trigger can enforce per-column `insert` grants. Resolves Issue B.

- [ ] **5.11** Register `post_parse_analyze_hook` in `_PG_init()`
- [ ] **5.12** For `Query` with `commandType == CMD_INSERT` targeting a letter-enforced table, extract the explicit column list from `targetList` (reading `resjunk`/`resname` to distinguish user-supplied columns from filler) and stash it in a backend-local slot keyed by the running statement
- [ ] **5.13** Update `letter_enforce_insert` to consult the stashed list — only check columns the user actually named, skip defaults
- [ ] **5.14** Stash must be a stack (not a single slot) to handle nested INSERTs triggered from other triggers
- [ ] **5.15** Handle `INSERT ... SELECT` — column list is in the parse tree, same mechanism applies
- [ ] **5.16** Handle prepared statements — stash must be populated at execute time, not just parse time, so it survives plan caching
- [ ] **5.17** Handle partitioned tables — key the stash on the root relation, not the routed leaf partition
- [ ] **5.18** Decide: handle `COPY FROM` via `ProcessUtility_hook`, or document as out-of-scope. Document interaction with rules / INSTEAD OF triggers.
- [ ] **5.19** Tests: explicit column list enforced; DEFAULT-filled columns not checked; nested INSERT; `INSERT ... SELECT`; prepared statement; partitioned table; interaction with assignment source tables

## Phase 6: Cleanup and Lifecycle

Ensuring that letter cleans up properly when grants are removed, tables are dropped, or the extension is uninstalled. This is critical for production use — dangling triggers or orphaned state can break user tables.

### 6.1 Extension Drop
When `DROP EXTENSION letter` runs, enforcement trigger functions in the `letter` schema are destroyed. Triggers on user tables that reference these functions become dangling and will error on any subsequent write to those tables.

- [ ] **6.1.1** Investigate: does `DROP EXTENSION letter CASCADE` automatically clean up triggers on user tables that reference letter's functions? (It may, via pg_depend entries.)
- [ ] **6.1.2** If not automatic: implement cleanup. Options:
  - An event trigger (`sql_drop`) that fires on extension drop and removes enforcement triggers from all tables that have them
  - A `letter.cleanup()` function that users call before dropping the extension
  - Register proper pg_depend entries when triggers are created so CASCADE handles them
- [ ] **6.1.3** Test: `DROP EXTENSION letter CASCADE` leaves user tables in a clean state with no dangling triggers

### 6.2 Table Drop
When a user drops a table that has enforcement triggers and grants:

- [ ] **6.2.1** Investigate: does PostgreSQL automatically clean up the grants in `letter.grants` when the table is dropped? (No — grants are just data rows, they won't cascade.)
- [ ] **6.2.2** Options:
  - An event trigger on `DROP TABLE` that cleans up `letter.grants` rows for the dropped table
  - Accept orphaned grant rows — they're harmless data but messy
  - A `letter.cleanup_orphans()` maintenance function
- [ ] **6.2.3** Test: dropping a table with grants doesn't leave broken state

### 6.3 Grant/Revoke Trigger Lifecycle
Already partially covered in Phase 2, but edge cases:

- [ ] **6.3.1** Test: granting on a table, revoking all grants, then granting again — triggers should be reinstalled cleanly
- [ ] **6.3.2** Test: concurrent grant/revoke calls (if applicable)
- [ ] **6.3.3** Test: revoking a grant while enforcement triggers are actively being used in another transaction

### 6.4 Assignment Cleanup
When `letter.unassign()` is called, it drops triggers and functions. Edge cases:

- [ ] **6.4.1** Test: unassign while rows exist that have active roles — roles should be cleaned up
- [ ] **6.4.2** Test: dropping an assignment source table while assignments exist
- [ ] **6.4.3** Test: dropping the extension cleans up assignment triggers on user tables

### 6.5 Consistency Checks
A maintenance function to verify the system is in a consistent state:

- [ ] **6.5.1** `letter.check_health()` — reports:
  - Grants referencing tables that don't exist
  - Enforcement triggers missing for tables that have grants
  - Enforcement triggers present for tables that have no grants
  - Assignment triggers referencing dropped functions
  - Roles referencing assignments that no longer exist
  - `using_path` FK columns that no longer exist

# Letter — Structural Enforcement Gaps

A review of the permission model's structural gaps and data-leak vectors, captured
before committing to the Phase 5 planner-hook integration. Findings are against the
shipped code in `letter.c` (not just the design docs — several issues are live in the
implementation). Cross-references: `06-enforcement.md` (enforcement overview),
`08-read-enforcement.md` (read path), `09-scope-resolution.md` (scope design),
`10-query-hooks.md` (Phase 5 hook design), `13-multihop-issues.md` (multi-hop).

The headline: **redaction only covers the output projection, never predicates or
joins.** This is the most important issue to settle before the planner hook, because
the hook inherits and widens it.

## 1. Predicate / join leaks (projection-only redaction)

> **FIXED for the read path 2026-09-22 (`17` H3–H5):** the planner hook redacts at the source (a `security_barrier` subquery per protected table), so predicates, joins, ordering and aggregates over hidden columns see NULL and cannot distinguish "no match" from "can't see" — `hook_read.sql` §2. `letter.read()`'s raw `condition` remains the leaky path until `17` D3 is decided.

Both `letter.read()` today and the Phase 5 planner-hook design filter the *output
columns*. Neither touches `WHERE`, `ORDER BY`, `JOIN`, `GROUP BY`, or aggregates.
Those evaluate against the true row values *before* redaction, so a hidden value is
recoverable as an oracle.

- **WHERE leak:** `letter.read('public.projects', 'budget > 1000000')` returns the
  row iff `budget > 1000000`, even though `budget` comes back redacted. The condition
  is interpolated raw into `SELECT * FROM … WHERE …` (`letter.c:1744-1746`).
  Binary-search the predicate → read the column exactly.
- **ORDER BY leak:** ordering by a redacted column leaks its relative ordering.
- **Phase 5 widens it:** once the planner hook intercepts real `SELECT`s,
  `SELECT max(budget)`, `GROUP BY budget`, and `JOIN … ON a.budget = b.x` all leak the
  value or its distribution. `10-query-hooks.md` only rewrites the *target list* into
  `CASE/NULL`; predicates and joins are untouched by design.
- **Scope-resolution joins:** multi-hop scope resolution wants to add JOINs through
  intermediate tables. A join through a table the user can't see can leak existence /
  cardinality of rows in it.

This is the standard reason cell-level security cannot live in the projection alone.
The Postgres-native tool that filters at the *predicate* level is Row Security Policies
(RLS), which letter deliberately avoids ("no generated policies"). That is a defensible
choice — but it creates an obligation: predicates referencing columns the user cannot
read must be rejected (or the rows pre-filtered) before results are produced. There is
currently no plan for this. **Decide the approach before writing the planner hook**,
because the hook is the enforcement point for it.

## 2. Foundational enforcement holes

### 2.1 `letter.bypass` is user-settable — **FIXED (2026-07-08)**
Now `PGC_SUSET`: only superusers (or roles explicitly granted
`GRANT SET ON PARAMETER letter.bypass`) can bypass enforcement. Tested in
`test/sql/hardening.sql`.

### 2.2 `letter.current_user_id` trust boundary — **RESOLVED (documented, 2026-07-08)**
The GUC stays `PGC_USERSET` *by design* — the application sets it per transaction on
behalf of end users. The trust boundary is now stated explicitly (in
`06-enforcement.md` and at the GUC definition in `letter.c`): **letter assumes end
users never hold a raw SQL connection; the application layer that sets the GUC is the
enforcement perimeter** (the PostgREST/Supabase model). Anyone with raw SQL access can
impersonate any user — that is outside letter's threat model.

### 2.3 SQL injection via the user-id GUC — **FIXED for runtime paths (2026-07-08)**
`populate_cache` now parameterizes the user id and passes role names as a
`text[]` parameter (`role = ANY($1)`) — role names originate in application table
data via `role_column` assignments, so they were a genuine runtime vector. The
catalog helpers used at enforcement time (`table_exists`, `lookup_fk_target`,
`lookup_fk_to_table`, `lookup_pk_column`) are parameterized; row fetches in the
path-walker use SPI parameters and `quote_identifier`. `letter.read()` quotes the
table identifiers. Tested in `test/sql/hardening.sql`.
**Remaining, accepted:** `letter.read()`'s `condition` is a raw SQL fragment *by
design* (trusted, app-supplied — and independently the predicate oracle of §1; both
resolve at Phase 5 step 2 when `read()` is rebuilt or deprecated). The admin-path
functions (`grant`/`revoke`/`assign`/`unassign` DDL generation) still interpolate
their config arguments — admin-supplied, lower severity; sweep opportunistically.

### 2.4 Scope migration on UPDATE checked against NEW only — **FIXED (2026-07-08)**
The update trigger now resolves scope against **both** tuples: rights in OLD to move
a row out, rights in NEW to move it in. A row whose OLD scope cannot be resolved
(NULL chain) cannot be updated by a scoped grant — fail closed. Tested in
`test/sql/hardening.sql` (both directions).

## 3. Scope resolution correctness

### 3.1 Multi-hop fails open — **FIXED (2026-07-08)**
`resolve_scope_id` returned NULL for any non-empty `using_path`, which `check_grant`
treated permissively. Replaced by the shared path-walker `walk_scope_path`: multi-hop
paths are walked for real; unresolvable configurations error at grant time *and*
enforcement time; NULL along the chain denies (D4). Full analysis in
`13-multihop-issues.md`; tests in `test/sql/multihop.sql`.

### 3.2 Two FKs to the same scope → arbitrary resolution (0-hop) — **FIXED (2026-07-08)**
The direct-FK lookup ended in `LIMIT 1` with no ordering. The walker's final-hop
lookup now errors on zero or more-than-one candidate FK ("extend using_path to name
the final hop column"), and `letter.grant()` rejects the ambiguity at grant time.

### 3.3 "Table is scope" fallback is unverified — **FIXED (2026-07-08)**
The row's-own-PK fallback now fires only when the protected table *is* the scope
table; any other table with no FK path to its scope is a loud error.

## 4. Cache coherence and correctness

### 4.1 Cache is incoherent across backends

> **Closed 2026-09-22 (`17` H4):** grants and roles writes raise relcache invalidations (`letter.grants`, `letter.roles_epoch`) that reach every backend at commit; `hook_cache.sql` demonstrates it with a second connection.
`invalidate_cache()` is only called inside `grant()`/`revoke()` (`letter.c:190, 292`)
and clears only the *local* backend's cache. A grant/revoke on connection A leaves
connection B's cache stale until B's `user_id` changes — on a pooled, long-lived
connection, effectively forever. No cross-backend signal (no `pg_notify`, no
catalog-xmin check). `07-open-questions.md` files this under "mid-session grant changes,
deferred," which undersells it: it is cross-session and unbounded.

**Partial route to closure (2026-09-21):** the planner-hook read path will read the
user's scope sets from `letter.roles` inside the rewritten query, under MVCC, not from
the backend cache (`16-scope-resolution-direction.md` §3.2 rule 3) — so *role*
staleness closes for reads when Phase 5a lands. Still open: the trigger (write) path,
and *grant* staleness (the rewrite's shape and the trigger cache both derive from
`letter.grants`).

### 4.2 Role changes never invalidate the cache — **FIXED (backend-local, 2026-07-08)**
Statement-level C triggers (`letter.cache_inval`) on `letter.roles` and
`letter.grants` invalidate the backend's session cache on any write — including the
assignment triggers' writes and direct DML. A role gained or lost mid-session takes
effect on the next check. Tested in `test/sql/hardening.sql`. Cross-backend staleness
(§4.1) remains open.

### 4.3 Everything is stringified in `read()`
Every value goes through `SPI_getvalue` into `jbvString` (`letter.c:1836-1843`), so
numbers, booleans, and timestamps come back as JSON strings. Beyond surprising
consumers, the Phase 5 planner hook returns native types — so the two read paths will
**behave differently**, exactly the trigger/hook divergence `13-multihop-issues.md` §6
warns about. The `_redacted` array is also silently capped at 64 columns
(`letter.c:1791, 1859`).

## 5. Implications for Phase 5 sequencing

The plan treats the planner hook as the "better integration" to move toward. Three
things should be settled *before* duplicating check logic into a hook:

1. **The predicate/join leak (§1)** is a hook-layer problem and needs a designed answer
   (reject predicates over unreadable columns, or move to RLS-style row filtering)
   before the rewrite is written.
2. **The GUC hardening (§2.1, §2.2) and injection fixes (§2.3)** are small, independent,
   and sit under everything — land them first. *(Done 2026-07-08.)*
3. **Trigger/hook duality:** the trigger and hook will both walk scope and check grants.
   `13-multihop-issues.md` §6 already asks "one shared helper or two paths?" — decide now,
   because the OLD/NEW scope rule (§2.4), the two-FK ambiguity (§3.2), and multi-hop
   (§3.1) must behave identically in both.

## Priority summary

| # | Issue | Severity | Effort | Independent of Phase 5? |
|---|---|---|---|---|
| ~~2.1~~ | ~~`letter.bypass` USERSET~~ **FIXED** — now `PGC_SUSET` | — | — | — |
| ~~2.2~~ | ~~`current_user_id` trust boundary~~ **RESOLVED** — documented as explicit precondition | — | — | — |
| ~~2.3~~ | ~~SQL injection via GUC~~ **FIXED (runtime paths)** — parameterized; admin-path sweep remains | — | — | — |
| 1 | Predicate / join leak | High | Design | **No — gates Phase 5** |
| ~~2.4~~ | ~~UPDATE scope migration (NEW only)~~ **FIXED** — OLD and NEW scope both checked | — | — | — |
| ~~3.1~~ | ~~Multi-hop fails open~~ **FIXED** — real multi-hop via shared path-walker | — | — | — |
| ~~4.2~~ | ~~Role changes don't invalidate cache~~ **FIXED (backend-local)** — cache_inval triggers | — | — | — |
| 4.1 | Cross-backend cache incoherence | Medium | Design | Partly |
| ~~3.2~~ | ~~Two-FK arbitrary scope~~ **FIXED** — errors on ambiguity, grant + enforcement time | — | — | — |
| ~~3.3~~ | ~~Unverified "table is scope" fallback~~ **FIXED** — fallback requires table == scope | — | — | — |
| 4.3 | Stringified read / 64-col cap | Low | Small | Partly |

# Letter — Planner Hook Implementation Plan

Implementation plan for checklist items **5.1–5.6** (Phase 5a, transparent read
enforcement): a `planner_hook` that replaces every reference to a protected table with
a redacting `security_barrier` subquery.

- **What it enforces** is settled in `15-join-enforcement.md` §2–§4 (Option B, redact at
  the source) — not reopened here.
- **What it generates** is settled in `16-scope-resolution-direction.md` §3 and by the
  experiment in `bench/barrier/RESULTS.md` ("form E" + `UNION ALL` branches).
- **This doc** settles *how it is built*, in what order, how each step is proven, and
  where to stop and ask.

Supersedes the mechanics in `10-query-hooks.md` (Strategy A's per-Var `CASE` wrapping
with a `letter_check_column()` call is the B1/Option-A shape both later docs rejected).

Out of scope, each a later step of `16` §9: per-hop gating (`15` §7.4), write-path
redaction of the result relation (`15` §8), the `_redacted` companion (`15` §9.3),
INSERT column enforcement (5b), materialisation (Phase 4).

---

## 1. The three ideas that keep this small

### 1.1 Convert the RTE in place — almost no Var fix-up

`15` §4 priced Option B at "Var fix-up after swapping `RTE_RELATION` → `RTE_SUBQUERY`".
That cost is avoidable by doing exactly what the rewriter does when it expands a view
(`ApplyRetrieveRule`): **mutate the existing RTE in place, at the same range-table
index**, into an `RTE_SUBQUERY` whose target list has one entry per table attribute,
with `resno == attnum`. Every outer `Var (varno, varattno)` then still points at the
right thing, untouched.

PG16+ explicitly supports the shape we need — `parsenodes.h`: *"relid, relkind,
rellockmode, and perminfoindex can also be set (nonzero) in an RTE_SUBQUERY RTE. This
occurs when we convert an RTE_RELATION RTE naming a view into an RTE_SUBQUERY"*. So:

| Field on the converted RTE | Value | Why |
|---|---|---|
| `rtekind` | `RTE_SUBQUERY` | |
| `subquery` | the generated barrier `Query` | §1.2 |
| `security_barrier` | `true` | user quals must not be pushed below redaction |
| `relid`, `relkind`, `rellockmode`, `perminfoindex` | **kept** | the caller's ordinary SQL privilege check on the table (incl. column-level `selectedCols`) still happens, unchanged |
| `inh` | `false` | inheritance is handled by the inner base RTE |
| `tablesample`, `securityQuals` | must be empty — else error (§4) | |

What is *not* free, and must be handled explicitly:

- **Dropped columns.** Attribute numbers have holes. The generated target list emits a
  typed `NULL` placeholder at each dropped `attnum` so `resno == attnum` holds.
- **Whole-row Vars** (`varattno = 0`, e.g. `SELECT c FROM comments c`, `row_to_json(c)`).
  Works for converted views; must be tested here, with a dropped column present.
- **System columns** (`varattno < 0`: `ctid`, `xmin`, `tableoid`). A subquery has none.
  Fail closed: error (§4). `tableoid` can be added later if partitioned use needs it.

### 1.2 Generate SQL text and parse it — don't build node trees by hand

The barrier subquery is built as a **SQL string** from `letter.grants` + catalog
metadata, then turned into a `Query` with `pg_parse_query()` +
`parse_analyze_fixedparams()`. Hand-assembling `JoinExpr`/`SubLink`/`CaseExpr`/
`SetOperationStmt` nodes is the fragile, version-sensitive surgery `15` §4 warned
about; the parser is the stable interface. It also makes the generator testable as
text (§3 H2) and is *literally* the artifact the experiment validated.

Costs: a parse + analyse per protected RTE per planning (~0.1 ms). Accept for now.
Caching the analysed `Query` per relation (copy on use, `AcquireRewriteLocks()` on the
copy to re-take locks) is a later optimisation, not part of this plan.

Everything interpolated is an identifier or a type name from the catalogs or from
`letter.grants` — always through `quote_identifier()` / `quote_literal_cstr()`. Role
names and scope-table names are *application data* (`14` §2.3): they are emitted as
quoted literals, never raw.

### 1.3 Nothing user-specific in the tree — and the two GUCs that are

Per `16` §3.2 rule 3 / §7(a): the user id is `current_setting('letter.current_user_id')`
inside the generated SQL and the user's scopes are read from `letter.roles` at
execution. The rewrite depends only on `letter.grants` + schema, so cached plans are
safe across users by construction.

Two session settings *do* change whether/what we rewrite, and cached plans must not
straddle a change:

- `letter.bypass` (exists, `PGC_SUSET`): hook skips rewriting entirely when on.
- `letter.enforce_reads` (**new**, `PGC_SUSET`, bool): master switch for the hook.
  Default **off** until H5 is green, then flipped to on (§5 D1).

Both get a GUC **assign hook that calls `ResetPlanCache()`**. Assign hooks also fire on
`SET LOCAL` revert, transaction abort and function-`SET` exit, so a plan built under
one value is never reused under the other.

---

## 2. Generated SQL — the contract

For a protected table `T` (has ≥ 1 `select` grant), with select grants grouped by
`(scope, using_path)` into chains `G1…Gn`, plus an optional unscoped group `U`:

```sql
-- branch U: unscoped select grants (only if any exist)
SELECT <cols(U)>
FROM   S.T b
[LEFT JOIN … the same chain joins as below, only if some column's CASE needs them]
WHERE  (SELECT EXISTS (SELECT 1 FROM letter.roles r
                       WHERE r.user_id = current_setting('letter.current_user_id')
                         AND r.role IN (<roles(U)>)
                         AND r.scope_table IS NULL ))           -- D11; run-time constant → One-Time Filter

UNION ALL
-- branch G1
SELECT <cols(G1)>
FROM   S.T b
LEFT JOIN S1.H1 h1 ON h1.<pk> = b.<fk0>          -- one LEFT JOIN per fetched hop
LEFT JOIN …
WHERE  <scope_expr(G1)> IN (SELECT r.scope_id::<pk_type> FROM letter.roles r
                            WHERE r.user_id = current_setting('letter.current_user_id')
                              AND r.role IN (<roles(G1)>) AND r.scope_table = <scope(G1)>)
  AND  NOT <U's test>                               -- mutually exclusive with earlier branches
UNION ALL
-- branch G2 … AND (<G1's test>) IS NOT TRUE
```

`<cols(G)>` — one output per attribute, `resno == attnum`:

| Attribute | Expression |
|---|---|
| primary key column(s) | `b.col` (PK always visible — existing `letter.read()` semantics) |
| dropped column | `NULL::<something harmless>` placeholder |
| any other column `c` | `CASE WHEN <test for each grant group covering c, OR-ed> THEN b.c END` — where a group's test is its `IN (SELECT …)` restricted to the roles whose grants cover `c` (or `*`). If no select grant anywhere covers `c`: constant `NULL::<type>`. |

Rules the generator must obey (each is a `16` §3.2 rule or an experiment finding):
sub-selects stay **uncorrelated and hashable**; **cast the role side** to the PK type;
hops are `LEFT JOIN`s onto PKs; each branch's visibility predicate is a **single strict
test**; branches are mutually exclusive so no de-duplication. A column's `CASE` inside
branch `Gi` may reference other groups' tests (a row visible via G1 may have a column
readable only via a G2 role) — so **every branch joins every chain**; only its `WHERE`
differs. That is the honest cost of multiple chains on one table; note it, don't
optimise it yet.

`letter.roles` and the hop tables are *trusted plumbing*: their inner RTEs get
`requiredPerms = 0` (no privilege needed by the caller) and are **never themselves
substituted**, even when the hop table is protected (`15` §7: intermediate tables are
anchors, not data being read). The inner base RTE `b` also gets `requiredPerms = 0` —
the kept outer `perminfoindex` already performs the caller's check on `T`.

---

## 3. Steps

Each step ends green on `make installcheck`. Steps H0–H2 cannot affect existing
behaviour (the switch is off / no hook is installed).

### H0 — Spike: prove §1.1 on one hard-coded table *(throwaway code, ≤ 1 day)* — ✅ DONE 2026-09-21, findings in §7
Minimal `planner_hook` that, for one table name from a GUC, converts the RTE in place
to `SELECT * FROM t WHERE false`-style fixed SQL via §1.2. Verify by hand:
- outer Vars need no fix-up (`SELECT a, b FROM t WHERE …`, joins, aliases, `t.*`);
- whole-row Var; table with a **dropped column**; system column → behaviour noted;
- the caller still needs SQL `SELECT` on `t` (kept `perminfoindex`), and does **not**
  need it on a table referenced only inside the generated subquery (`requiredPerms=0`);
- `EXPLAIN` equals the equivalent `security_barrier` view's plan.
**Exit:** a short "findings" note appended to this doc (§7). **STOP and discuss** if
in-place conversion needs Var rewriting after all, or whole-row Vars break — that
changes the cost of everything below.

### H1 — Hook infrastructure *(5.1, 5.2, 5.8)* — ✅ DONE 2026-09-21, notes in §7
- Register `planner_hook` in `_PG_init()`, chaining to any previous hook, else
  `standard_planner`.
- `letter.enforce_reads` GUC; `ResetPlanCache()` assign hooks on it and on
  `letter.bypass`.
- **Protected-relation set**: backend-local hash of relation OIDs that have ≥ 1
  `select` grant *(D8 briefly made this names; `18` D1 made it OIDs again — see `18`)*. Built lazily from `letter.grants` (one SPI query, under the internal
  guard), invalidated by the H4 signal. Not per-user.
- **Fast exit** before any allocation: switch off, bypass on, `InNoForceRLSOperation()`
  (RI-trigger queries — they must see the truth, and they carry row marks), internal
  guard set, `commandType == CMD_UTILITY`, or no RTE in the tree is in the set.
- **Internal guard**: a depth counter set only around letter's *own* SPI calls (walker
  fetches, cache population, `letter.read()`'s scan, catalog lookups). The hook does
  nothing while it is > 0. Keep the guarded regions narrow: user-supplied functions
  (`check_fn`, `if_fn`) must never run inside one — a query planned inside the guard is
  cached *unrewritten*.
- Tests: hook on + no grants = identical plans (`EXPLAIN (COSTS OFF)` before/after);
  existing 11 tests still pass with the switch off.

### H2 — The generator *(5.3, 5.5, 5.6 — no hook involvement yet)* — ✅ DONE 2026-09-21, notes in §7
- `build_barrier_sql(relid) → char *` implementing §2. Reuses `get_compiled_scope_path`
  for hop/PK metadata (extend the compiled hop with the PK type name and target table,
  which it already looks up).
- SQL-callable debug function **`letter.barrier_sql(regclass) → text`** exposing it.
- Tests (`test/sql/barrier_sql.sql`) are **golden-text + executable**: for each
  fixture the test prints the SQL *and* runs it via a `security_barrier` view, comparing
  rows/redaction with `letter.read()` on the same data for two users. Fixtures: direct
  FK; one hop; two hops inferred final; explicit final hop; two roles with different
  columns on one chain; `*` grant; unscoped grant; unscoped + scoped; two chains;
  table-is-scope; NULL mid-chain; dropped column; composite-PK leaf (allowed — all PK
  columns visible) and composite-PK scope/hop table (rejected at grant time) per D4;
  quoted/mixed-case identifiers; a role name containing a quote.
- **Entry-criterion test (`16` §7):** generate with `letter.current_user_id` set to a
  sentinel; assert the SQL text does not contain it, nor any `scope_id` value.

### H3 — Substitution *(5.3, 5.7 pulled forward)* — ✅ DONE 2026-09-22 incl. D14, notes in §7
- Walk the **whole** query tree once (`query_tree_walker` / `range_table_walker`:
  subqueries in FROM, CTEs, sublinks, set-operation arms, already-expanded views). For
  each `RTE_RELATION` in the protected set → §1.1 conversion using H2's SQL parsed per
  §1.2. Collect first, then substitute; never descend into a subquery we generated.
  *(`15`/`16` sequenced "top-level first, nested later". With a generic walker the nested
  case is the same code, and doing top-level only would ship a known leak — so it is
  pulled forward. Hardening the odd shapes remains 5.7.)*
- **Skip**: the statement's own result relation (`query->resultRelation`) — triggers
  own writability, and `15` §8 (write-path redaction) owns its visibility. *Known,
  documented gap until then*: quals/`RETURNING`/SET-RHS on the target table still see
  true values. Other RTEs of the same UPDATE/DELETE/INSERT…SELECT *are* substituted.
- **Fail closed** (§4) for shapes we cannot rewrite.
- **D14, the universal gate** *(added 2026-09-22)*: during the same walk, an
  `RTE_RELATION` in a non-exempt namespace that is **not** in the set (no `select`
  grant) → `ERROR: letter: no grants on "s.t"`; the statement's result relation without
  a grant of the statement's privilege → the same error at plan time. Exempt:
  `pg_catalog`, `information_schema`, `pg_toast`, own `pg_temp_N`, schema `letter`. The
  set becomes `Oid → privilege bitmask`. RI-trigger queries, the internal guard and
  bypass keep their fast exits, so cascades and letter's own plumbing are unaffected.

### H4 — Plan and cache invalidation *(5.6)* — ✅ DONE 2026-09-22, notes in §7
- In `letter_cache_inval` (the existing statement trigger), when fired for
  `letter.grants`: `CacheInvalidateRelcacheByRelid(<letter.grants oid>)`. This is
  transactional and **cross-backend**. Because every rewritten plan lists
  `letter.grants` in `relationOids`, the plancache invalidates exactly those plans, in
  every backend, at commit; replanning re-runs the hook against the new grants.
- The same signal clears the protected-relation set (H1) via a relcache callback.
- **Bonus, small, closes `14` §4.1 for the write path too:** register a relcache
  callback that drops `LetterCache` when `letter.grants` — or a new empty signal table
  `letter.roles_epoch`, poked by the roles trigger — is invalidated. (A separate signal
  relation for roles so that role churn does not also invalidate every rewritten
  *plan*, which legitimately does not depend on role rows.) Do this only if it stays
  ≤ ~40 lines; otherwise split it out.

### H5 — Behavioural tests, then flip the default — ✅ DONE 2026-09-22 (H5.9 bench comparison not run), notes in §7
`test/sql/hook_read.sql` (+ `hook_cache.sql`), switch on:
1. Parity: `SELECT *` matches `letter.read()` row/column visibility for two users
   (same fixtures as `read.sql` / `multihop.sql`), native types preserved.
2. **The leak is closed** (`14` §1): `WHERE hidden > x`, `ORDER BY hidden`,
   `GROUP BY hidden`, `max(hidden)`, `JOIN … ON a.hidden = b.x`, `hidden IS NULL`
   cannot distinguish "no match" from "can't see".
3. Shapes: join of two protected tables; protected + unprotected; subquery in FROM;
   CTE; sublink; `UNION`; plain view over a protected table; `security_invoker` view;
   SQL function body; whole-row Var; `INSERT … SELECT` and `UPDATE … FROM` reading a
   protected table.
4. Generic-plan safety: `PREPARE` once, `EXECUTE` as alice, switch
   `letter.current_user_id`, `EXECUTE` as bob (with `plan_cache_mode =
   force_generic_plan`) — results differ correctly. Same through a PL/pgSQL function.
5. Invalidation: prepared statement, then `letter.grant()`/`revoke()` from the same
   *and from another* session (second connection via `dblink` if available, else a
   documented manual check) → next `EXECUTE` reflects it.
6. Switches: `letter.bypass` on → raw rows, off → redacted, inside one transaction,
   with a prepared statement; unset `letter.current_user_id` → zero rows, no error (D2).
7. Fail-closed cases of §4 each raise the documented error.
7a. **D14:** an ungranted table in `public` → read errors, insert/update/delete error
    at plan time, even with a user id set; catalog, `information_schema`, own temp
    tables and `letter.*` unaffected; a table with only an `insert` grant is readable
    by nobody and insertable by the granted role; `letter.read()` on an ungranted table
    errors like a plain `SELECT`.
8. RI still works: FK insert/delete against a protected parent the user cannot see.
9. Plan shape: on the `bench/barrier` data, the hook's plan for Q1/Q5 matches the
   hand-written `v_hashed` view's plan (bench script, not a regression test).

Then: default `letter.enforce_reads = on`; update the ~11 raw `SELECT`s in existing
tests that verify state while a user id is set (wrap in `letter.bypass` from a
superuser, or accept redacted output where that is the point).

### H6 — Close the side doors, settle `letter.read()` *(5.10)* — ✅ DONE 2026-09-22 (D3: `read()` deprecated, `visible_columns()` added)
- **`COPY protected_table TO`** does not go through the planner → true values. Add a
  `ProcessUtility_hook` that, unless bypassed, rejects it with a hint to use
  `COPY (SELECT …) TO` (which *is* rewritten). The same hook applies D14 to `COPY … FROM`
  and `TRUNCATE` on ungranted tables (granted tables already have the TRUNCATE trigger). Document `pg_dump` → run with
  `PGOPTIONS='-c letter.bypass=on'` as a superuser.
- `letter.read()`: per `15` §9.3 it cannot survive unchanged. Recommended: reimplement
  as a thin wrapper that runs `SELECT to_jsonb(t) … FROM <table> t` *through the hook*
  and computes `_redacted` by comparing against the column-visibility tests — **or**
  deprecate if `_redacted` is not needed. Needs the `15` §9.3 decision → D3.
- Update `10-query-hooks.md` (superseded banner), `11` (tick 5.1–5.8, 5.10),
  `14` §1 → FIXED for the read path, README.

---

## 4. Fail-closed cases

A protected table the hook cannot faithfully redact must **error, never pass through**.
Message form: `letter: <what> is not supported on letter-protected table "s.t"`.

| Shape | Why | Later? |
|---|---|---|
| System column reference (`ctid`, `xmin`, `tableoid`, …) | not present on a subquery | `tableoid` maybe |
| `TABLESAMPLE` | samples the base heap | unlikely |
| Row marks on the protected RTE (`SELECT … FOR UPDATE/SHARE`) | needs the rewriter's push-down of the mark into the subquery (`markQueryForLocking`) | yes — common in apps; own small step after H5 |
| RLS enabled on the table (`securityQuals` present) | two row-security systems on one RTE; letter's stance is non-RLS | probably never |
| `ONLY`/inheritance child queried directly where only the parent has grants | child is simply unprotected — not an error, **document** | — |
| Foreign tables, `relkind` other than `r`/`p` | untested | later |

Not errors, by design: the result relation of a write (§3 H3); queries under RI
triggers; queries inside letter's own guard; superusers (no implicit bypass — the GUC
is the only bypass, per `07`).

---

## 5. Decisions

Settled here (argue before starting, not during):

- **D1 — rollout switch.** `letter.enforce_reads`, `PGC_SUSET`, off until H5 is green,
  then default on. It is a deployment switch, not a per-request toggle.
- **D5 — nested references from day one** (H3), not "top-level first".
- **D6 — `requiredPerms = 0`** on all RTEs inside the generated subquery; the kept outer
  `perminfoindex` is the caller's privilege check.
- **D7 — no caching of generated `Query` trees** in this plan.
- **D2 — `letter.current_user_id` unset → reads return zero rows.** *(Decided
  2026-09-21.)* The generated SQL yields this naturally (no role row matches `''`); no
  extra gate or function call. Deliberately asymmetric with writes, where the triggers
  *error*: a denied write must be loud, an unidentified read is simply entitled to
  nothing — leak-free, and friendlier to tooling and health checks. Document the
  asymmetry. A `letter.require_user` GUC that errors instead can be added later if
  wanted.
- **D4 — composite primary keys.** *(Decided 2026-09-21.)* Rejected at `letter.grant()`
  time for **scope tables and hop tables** (the walker and `roles.scope_id` assume a
  single PK column); **allowed on leaf tables**, where the PK is only used for "PK
  always visible" — all PK columns are emitted unredacted. Implement the grant-time
  check in H2 alongside the generator; test in `barrier_sql.sql`.
- **D8 — the protected-relation set is keyed by qualified name, not OID.** *(Decided
  2026-09-21; resolves stop S1. **Superseded 2026-09-22 by `18` D1** — tables are
  identified by OID throughout, so the set becomes an OID hash.)* H1's set holds `schema.table` names that have ≥ 1
  `select` grant; the hook resolves each `RTE_RELATION`'s qualified name per query
  (`get_rel_namespace`/`get_namespace_name` + `get_rel_name` — two syscache lookups per
  RTE) and looks that up. A table dropped and recreated under the same name — its
  grant rows survive the drop — is therefore protected from its first query: the set
  cannot go stale with respect to DDL, only with respect to grants, which the H4 signal
  covers. Matches how grants, triggers and the walker already treat names as identity.
  Supersedes "hash of relation OIDs" in H1. *(The other route to a stale OID — a grant
  declared before its table exists — is closed at the source by D10.)*
- **D9 — `ResetPlanCache()` when the internal guard returns to zero after
  `letter.read()`.** *(Decided 2026-09-21; resolves stop S2.)* `read()`'s raw
  `condition` may run user functions inside the guard, whose plans would be cached
  unrewritten and reused later outside it. Dropping all cached plans as `read()` leaves
  the guard removes them. Heavy-handed but correct; `read()` is the legacy path and D3
  stays deferred to H6. Applies to `letter.read()` only — letter's other guarded
  regions run no user-supplied SQL.
- **D10 — `letter.grant()` fails on a table that does not exist.** *(Decided
  2026-09-21, raised by Paul during H1; reverses `11` items 1.6 and 2.3.3.)* A grant
  stored ahead of its table left that table, once created, with **no enforcement
  triggers**, an unvalidated scope path and no FK-index warning — a write-path
  fail-open, the twin of S1. Now `ERRCODE_UNDEFINED_TABLE` for every privilege, scoped
  or not; migrations create the table first. `letter.revoke()` is unchanged (it must
  keep working after a table is dropped). A missing *scope* table is still tolerated
  at grant time (enforcement then fails loudly, never open) — not part of this ruling.
  Complements D8 rather than replacing it. Done 2026-09-21; `grant_revoke.sql` now
  creates its tables.
- **D11 — an unscoped role is a role in the global scope.** *(Decided 2026-09-22;
  resolves stop S6.)* An unscoped grant (`scope = ''`) is satisfied only by a role row
  with `scope_table IS NULL`; a scoped role of the same name never satisfies it, however
  many scopes it is held in. Symmetric with the existing rule that a global role never
  satisfies a scoped grant — global is simply another scope. Changes: `check_grant` and
  `row_has_any_select_grant` (require `!has_scope`), the generator's unscoped test and
  its `NOT …` exclusion (`AND r.scope_table IS NULL`, as `16` §3.2 rule 5 already says),
  §2 of this doc, tests on both paths. Small; done as a pre-H3 step.
- **D12 — the library must be preloaded.** *(Decided 2026-09-22; resolves stop S3,
  option a.)* Read enforcement needs the planner hook in every session, so `letter`
  must be in `shared_preload_libraries` (or `session_preload_libraries`). `_PG_init()`
  raises a WARNING when loaded any other way (`process_shared_preload_libraries_in_progress`
  false and not via session preload) and documentation states the requirement.
  Belongs with H5 (before the default flip).
- **D13 — `letter.assign()` and `letter.unassign()` require `letter.bypass = on`.**
  *(Decided 2026-09-22; resolves stop S4.)* `assign()`'s backfill reads the source
  table and must see the truth; rather than carve an exception into the hook, it errors
  unless bypass is on — unconditionally, not only while `letter.enforce_reads` is on, so
  behaviour does not change with the switch. `unassign()` matches, for symmetry: both
  are admin operations. *Done 2026-09-22 in `18` I1.*
  Cost: every existing test that calls `assign()` gains a `SET letter.bypass = on`.
  **Deployment model, to document with H6:** enforcement is a property of the
  connecting PG role — `ALTER ROLE <admin/migration role> SET letter.bypass = on`
  (applied at login; the application role never gets it). Superusers are *not*
  implicitly bypassed (`07`); the same one-liner opts them in. This replaces the
  `PGOPTIONS` advice for `pg_dump` in H6.
- **D14 — default-deny across the whole database.** *(Decided 2026-09-22; amends `06`
  §2, which scoped enforcement to "tables with grants".)* Without `letter.bypass`, only
  what a grant allows is allowed — on every table, not only those letter has been told
  about. The planner hook is the universal gate, at the cost of one OID hash probe per
  RTE (a probe the H3 walk already makes):
  - **Reads:** an `RTE_RELATION` in a non-exempt namespace with no `select` grant →
    **ERROR** `letter: no grants on "s.t"` — not zero rows. A missing grant is a
    configuration mistake and must be loud; a missing *role* is an authorization
    outcome and yields zero rows (D2). Also makes `letter.read()` consistent (it returned
    zero rows for an ungranted table).
  - **Writes:** a statement's result relation with no grant of that privilege
    (`insert`/`update`/`delete`) → **ERROR at plan time**. Row-level enforcement on granted
    tables stays with the triggers; ungranted tables need no triggers.
  - **Utility paths** that skip the planner (`COPY … FROM`, `TRUNCATE`) are gated by
    H6's `ProcessUtility` hook, same rule.
  - **Exempt namespaces:** `pg_catalog`, `information_schema`, `pg_toast`, the session's
    own `pg_temp_N`, and **schema `letter`** — its SQL-language API functions read
    `letter.*` as the caller and the assignment trigger functions write `letter.roles`.
    Hand edits of `letter.*` are kept out by ordinary SQL privileges (`REVOKE ALL ON ALL
    TABLES IN SCHEMA letter FROM <app role>`); `check_health` reports if `PUBLIC` still
    has write access.
  - **Scope and hop tables are simply tables**: readable directly only with a grant, and
    readable *through a path* exactly as much as the path's author decided. Inside the
    barrier no hop column is ever output; the only information carried is reachability
    ("this row's chain leads to a scope I hold"), which is the sentence the grant author
    wrote when choosing the `using_path` — an authored disclosure, and the minimum that
    makes the policy work. A hop table's own grants are not consulted (`15` §7:
    intermediate rows are anchors; per-hop gating `15` §7.4 remains a later option).
    `EXPLAIN ANALYZE` reveals hop-scan row counts, as RLS subquery policies do — a
    PostgreSQL-level fact, noted, not closed.
  - The protected set therefore records a **privilege bitmask per OID**, not just "has
    a select grant".

Deferred:

- **D3 — `letter.read()` and `_redacted`** — `15` §9.3. **Decided 2026-09-22:
  deprecate `letter.read()`; plain `SELECT` is the enforced read. A hidden column is
  NULL, indistinguishable from a NULL one in-band; the distinction is available on
  request through `letter.visible_columns(rel regclass, pk anyelement) → text[]`, the
  columns of that row the current user may read (NULL if the row is not visible), built
  from the barrier's own tests in a single indexed lookup. `read()` stays for now as the
  reference in the parity tests, marked deprecated in the extension script and README;
  its raw `condition` remains a predicate oracle until it is removed.*

---

## 6. Stop-and-discuss triggers

Halt and raise, rather than work around, if any of these occur:

1. H0 shows in-place conversion needs outer Var rewriting, or whole-row Vars over a
   table with dropped columns misbehave.
2. The hook's plan for a fixture differs materially from the equivalent hand-written
   `security_barrier` view's plan (it should be identical — if not, the RTE differs
   from what the rewriter builds, and the experiment no longer vouches for it).
3. Any existing regression test changes output **with the switch off**.
4. The parity test (H5.1) disagrees with `letter.read()` in a way not explained by
   `14` §4.3 (stringification) — that is a semantics divergence between trigger/walker
   and hook, exactly what D5 of `15` forbids.
5. Anything requires reading `letter.current_user_id`, the backend role cache, or a
   role's `scope_id` at *rewrite* time.
6. A needed internal API is not exported on PG16 (target: PG16 and PG17, item 5.9).

---

## 0. Status — resume here

**As of 2026-09-22 (night). H0–H6 ✅ — this plan is complete.** Plan `18` complete;
17 tests green. `letter.enforce_reads` defaults to on; `letter.read()` is deprecated
(D3) and `letter.visible_columns()` added. Left over, none blocking: PG16 build (`11`
5.9), the `bench` plan-shape comparison (H5.9), the result-relation gap (`15` §8),
`MERGE`, `18` R1 (dump/restore) and U1. Possible next: `15` §8 write-path redaction,
or R1.

### S6 — what an *unscoped* grant requires of the user's role row — ✅ RESOLVED 2026-09-22 → D11
`16` §3.2 rule 5 and the barrier experiment (`bench/barrier/views_or.sql`) gate the
unscoped branch on `r.role = … AND r.scope_table IS NULL` — the user must hold the role
**unscoped**. §2 of this doc omits `scope_table IS NULL`, and so does the existing
enforcement code (`check_grant`, `row_has_any_select_grant`, the trigger path): an
unscoped grant applies to anyone holding a role **of that name under any scope**. So
"editor on project Alpha" also satisfies an unscoped grant to `editor`, everywhere.
H2 implements §2 as written — which is what `letter.read()` and the write triggers do,
so parity holds (stop trigger 4) — but the two design docs disagree, and the stricter
reading looks like the intended one. Options: (1) keep today's semantics and correct
`16`; (2) adopt `scope_table IS NULL` — then it must change in `check_grant` /
`row_has_any_select_grant` **and** the generator together (one line each), with tests
on both paths. *Claude's lean: (2)* — a scoped role silently satisfying an unscoped
grant is surprising, and nothing in the docs argues for it. User-visible security
semantics → Paul's call.

### S3 — the hook only exists once `letter`'s library is loaded — ✅ RESOLVED 2026-09-22 → D12 (option a)
`planner_hook` is installed by `_PG_init()`, and nothing loads `letter.dylib` in a
session until that session first calls a letter C function. Writes are safe — the
enforcement triggers *are* letter C functions, so the first write loads the library.
Reads are not: a fresh session that only runs `SELECT … FROM protected_table` never
loads the library, never gets the hook, and reads **unredacted** — whatever
`letter.enforce_reads` says. (The regression tests don't see this: `CREATE EXTENSION`
loads the library into the test session.) No plan doc mentions preloading. Options:
- **(a)** Require `shared_preload_libraries = 'letter'` (or `session_preload_libraries`)
  — document it, and have `_PG_init()` complain (WARNING, or refuse to enable
  `letter.enforce_reads`) when loaded any other way.
- **(b)** (a) plus a visible self-check, e.g. `letter.status()` reporting whether the
  hook is live in this session.
- *Claude's lean: (a) with a loud WARNING* — it is how every hook-based extension
  deploys (pg_stat_statements, pgaudit…). Deployment semantics → Paul's call.

### S4 — `letter.assign()`'s backfill reads the source table through the hook — ✅ RESOLVED 2026-09-22 → D13 (require bypass)
`letter.assign()` step 8 backfills with `INSERT … SELECT … FROM <source_table> [WHERE
<if_fn>]`. Once H3 substitutes, that `SELECT` is rewritten like any other: an admin
running `assign()` with `letter.current_user_id` unset would backfill from **zero
rows** (D2), silently creating no roles. It cannot simply go under the internal guard,
because `if_fn` is user-supplied SQL (the H1 rule, and the reason for D9). Options:
(1) require `letter.bypass = on` for `assign()` when the source table is protected —
error otherwise; (2) guard it and `ResetPlanCache()` afterwards, as D9 does for
`read()`; (3) leave it and document. *Claude's lean: (2)* — `assign()` is admin DDL,
rare, and must see the truth. The per-row assignment trigger functions are unaffected
(they read only `NEW` and `letter.*` tables).

### S5 — renaming a protected table orphans its grants: reads fail open — ⏩ SUPERSEDED 2026-09-22 by `18` (OID identity + lifecycle contract)
Grants are keyed by name. `ALTER TABLE … RENAME` / `SET SCHEMA` leaves the grant rows
under the old name. Writes fail **closed** (the triggers travel with the table and
find no grants); hooked reads fail **open** (the new name is not in the protected set)
— under name *or* OID keying. Same family: `DROP TABLE` leaves grant rows behind
(harmless for reads thanks to D8, but a recreated table has **no write triggers**
until the next `grant()`). Both belong to the unbuilt DDL event-trigger item (`11`
Phase 7, "event trigger on `DROP TABLE`"); options are an event trigger that rewrites
/ removes grant rows, or one that refuses the DDL while grants exist. Not H1–H4 work,
but it should be closed before `letter.enforce_reads` defaults to on.

### S1 — the protected-relation set can fail open — ✅ RESOLVED 2026-09-21 → D8 (option b)
H1 specifies the set of protected relation **OIDs** as "built lazily from
`letter.grants`, invalidated by the H4 signal" — and the H4 signal fires only when
*grants* change. But letter deliberately allows a grant to be declared before its table
exists (checklist 2.3.3). Create the table afterwards — or drop and recreate one — and
no grant changes, the set never learns the new OID, and reads of that table go
**unredacted** until something else flushes the set. Options:
- **(a)** also flush the set on *any* relcache invalidation (that callback is already
  registered for compiled scope paths). Cost: an SPI rebuild of the set after DDL /
  autovacuum activity.
- **(b)** key the set by qualified **name** instead of OID and resolve each
  `RTE_RELATION`'s name per query (two syscache lookups per RTE). Never stale with
  respect to DDL; matches how letter already treats names as identity (grants, triggers
  and the walker are all name-keyed).
- *Claude's lean: (b).* It removes the failure mode rather than narrowing its window.
  Either way this is a security semantic → Paul's call.

### S2 — the internal guard vs `letter.read()`'s `condition` — ✅ RESOLVED 2026-09-21 → D9 (option 1)
H1 puts `letter.read()`'s scan under the internal guard (so the hook does not rewrite
it) and also says user-supplied functions must never run inside a guarded region,
because a query planned inside the guard is cached **unrewritten**. `letter.read()`'s
`condition` argument is a raw SQL fragment that may call user functions: a PL/pgSQL
function first executed there caches unrewritten plans and reuses them later in
ordinary, unguarded queries — a leak that outlives the `read()` call. D3 (the fate of
`letter.read()`) is deferred to H6, but this bites as soon as the hook is switched on.
Options:
1. `ResetPlanCache()` whenever the guard drops back to zero after a `letter.read()`
   call — heavy-handed but correct; `read()` is the legacy path. (~3 lines.)
2. While `letter.enforce_reads` is on, reject `condition`s containing function calls or
   sub-selects.
3. Pull part of D3 forward now.
- *Claude's lean: option 1* — keeps D3 deferred, no semantic change to `read()`.

### Also waiting on Paul (not blocking)
- Commit what came after `cb78573`: the H0 findings and this status section in
  `plan/17`, the status line in `plan/11`, and `spike/h0/` (throwaway — commit it for
  the record or delete it; its findings are in §7 either way).
- Housekeeping, all safe to remove: `letter_spike.dylib` in the PG lib dir (inert unless
  `LOAD`ed), scratch databases `letter_bench`, `letter_walker_bench`, `letter_spike`.
  Keep `letter_bench` if H5.9's plan-shape comparison will reuse it.
- Tracked build artefacts (`letter.o`, `results/*.out`) keep showing as modified —
  consider gitignoring.

---

## 7. Findings log

*(Append H0 spike findings and any mid-implementation discoveries here, dated.)*

### 2026-09-21 — H0 spike (`spike/h0/`, throwaway module `letter_spike`)

A standalone `planner_hook` module that converts one GUC-named table's RTEs in place
to a `security_barrier` subquery parsed from GUC-supplied SQL. Fixture: a table with a
dropped column, a lookup table referenced only inside the subquery, three roles with
different SQL privileges. PG 17.9. **No stop trigger fired; §1.1 and §1.2 hold.**

Confirmed:
1. **No Var fix-up.** Plain columns, `SELECT *`, aliases, joins, quals and aggregates
   over a redacted column all work against the in-place-converted RTE untouched. The
   predicate leak is closed (`WHERE b = 'b1'` on a redacted row finds nothing).
2. **Dropped columns**: a typed `NULL` placeholder at the dropped `attnum` keeps
   `resno == attnum`; the column after it reads correctly.
3. **Whole-row Vars work**, with the dropped column present: `SELECT t FROM t`,
   `row_to_json(t)`, `(t).d` — all redacted correctly.
4. **Plans are identical** to the equivalent hand-written `security_barrier` view
   (`EXPLAIN (COSTS OFF)`, filter above the barrier and join cases) — so
   `bench/barrier/RESULTS.md` vouches for the hook's plans (stop trigger 2 not hit).
5. **Privileges behave as D6 intends**: a role with `SELECT` on `t` but none on the
   table referenced only inside the subquery reads through it, and is still refused on
   that table directly; a role with no privilege on `t` is refused; a role with
   `SELECT (a)` only can read `a` and is refused `b` — the kept `perminfoindex`
   preserves the caller's table- *and column*-level check.
6. **Nested references** (subquery in FROM, CTE, sublink, `UNION ALL` arms, a plain
   view over `t`, a SQL function body, `INSERT … SELECT`) are all rewritten by one
   collect-then-convert walk using `query_tree_walker` — D5 costs what it claimed.
   Note `INSERT … SELECT` and `UPDATE … FROM` reach the table through a *nested*
   subquery RTE / a non-result RTE, so they need the full walk, not just the top level.
7. The statement's own result relation is skipped; `UPDATE t … RETURNING` still shows
   true values — the documented `15` §8 gap, as expected.

Refinements the implementation must carry (consistent with the plan, sharper than it):
- **D6 needs a recursive walk.** `requiredPerms = 0` must be applied to *every* `Query`
  nested in the generated subquery — each sublink and subquery has its own
  `rteperminfos`. Zeroing only the top level leaves form E's `IN (SELECT … FROM
  letter.roles)` sublinks demanding `SELECT` on `letter.roles` from the caller.
- **§4's system-column check is a safety requirement, not a nicety.** After conversion,
  a system-column Var on the RTE is undefined behaviour: `SELECT ctid FROM t`
  **crashed the backend**, `tableoid` returned garbage, `xmin` raised an internal
  error, `WHERE ctid IS NOT NULL` silently "worked". (Stock PG rejects these on a view
  at parse time; we run after the parser.) H3 must find every Var with `varattno < 0`
  that references a target RTE — at the right `varlevelsup`, anywhere in the tree,
  including join alias Vars — **before** converting, and error. A missed case is a
  user-triggerable server crash. Give it its own tests.
- **§4's row-mark and `TABLESAMPLE` entries are confirmed as silent-wrong, not loud**:
  `FOR UPDATE`/`FOR SHARE` return rows but lock nothing (the mark degrades to a copy
  mark on a subquery); `TABLESAMPLE` is ignored. Both must be detected and errored.
- **H4 is necessary, as assumed**: a generic prepared plan kept using the old subquery
  after the generating SQL changed.
- Trivia: a GUC cannot be named `….table` (`SET x.table` is a syntax error).

### 2026-09-21 — H1 hook infrastructure (`letter.c`, `test/sql/hook_infra.sql`)

Built as planned, with D8/D9. No stop trigger fired: the 11 pre-existing tests are
unchanged with the switch off (trigger 3), bar `grant_revoke`, rewritten for D10.

- **Guard.** `letter_guard_depth`, held by `guarded_spi_execute[_with_args]()`
  (PG_TRY/PG_FINALLY — an error must never leave the hook disabled) around: the
  catalog-lookup helpers, `populate_cache()`'s two queries, the protected-set build,
  `letter.read()`'s scan, and the walker's hop-fetch loop. Deliberately **not** guarded:
  `grant()`/`revoke()`/`assign()` DML on letter's own tables, and `assign()`'s backfill
  (→ S4).
- **Saved hop-fetch plans are planned lazily**, at `SPI_execute_plan` (and re-planned
  there after invalidation), not at `SPI_prepare` — so the guard sits around the walk,
  not around path compilation.
- **Protected set.** `SELECT DISTINCT on_table FROM letter.grants WHERE privilege =
  'select'`, name-keyed. Until H4's cross-backend signal it is invalidated by
  `letter_cache_inval` (any write to grants *or roles* — coarser than needed) and on
  any (sub)transaction **abort**, which may have rolled a grant/revoke back; H4's
  transactional relcache inval should replace both. If `letter.grants` does not exist
  (library loaded without the extension, or mid-`CREATE EXTENSION`) nothing is
  protected and that answer is not cached.
- **D9 is conditional on `letter.enforce_reads`**: with the switch off no plan is ever
  rewritten, and switching it on resets the plan cache anyway — so today's `read()`
  users pay nothing. It runs on the error path too. Mutation-checked: with the reset
  removed, `hook_infra` Test 6 fails (the function first run inside `read()`'s
  condition keeps its unrewritten plan).
- **Observability.** H1 reports each protected reference at `DEBUG1`; that is what
  `hook_infra.sql` asserts on. H3 replaces the message with the substitution, and the
  test's detection cases should move to behavioural assertions then.
- The H1 walk does not yet skip the statement's result relation — that is H3's rule.

### 2026-09-21 — H2 the generator (`letter.c`, `test/sql/barrier_sql.sql`)

`build_barrier_sql(relid)` + `letter.barrier_sql(regclass)`; grant-time composite-PK
check (D4). Every fixture H2 lists is in `barrier_sql.sql` as golden text **and** as an
executable `security_barrier` view compared with `letter.read()`: parity is 0/0 for
every user on every fixture where it is asserted. No stop trigger fired; one plan
inconsistency raised as **S6**.

- **One source of truth for the chain.** `get_compiled_scope_path` now also records
  each fetched hop's PK column and the scope table's PK type; the generator renders its
  `LEFT JOIN`s from the same compiled hops the walker executes. The compiled path is
  consumed immediately and never held across another compile (a relcache inval can
  flush it).
- **Text shape.** Base alias `b`; hop aliases `g<group>h<hop>`; groups ordered by
  `(scope, using_path)` in "C" collation, which puts the unscoped group first. The
  target list is identical in every branch. A branch joins its own chain, the chains of
  the earlier branches it excludes, and any chain a column `CASE` tests — so the
  unscoped branch joins only what §2 says it must.
- **`pg_catalog.current_setting`**, schema-qualified, where §2 writes
  `current_setting` — the text is parsed under the caller's `search_path`. Operators
  are not qualified (the trust boundary excludes raw SQL from end users).
- **Inferred and explicit final hops generate the same SQL** (fixtures 3 and 4), as
  they should.
- **Mutual exclusion verified with a real overlap**: a comment bob reaches through
  both chains appears once, carrying the columns of both grants.
- **Native types and typmods survive** (`varchar(10)` through both `CASE` and the
  `NULL::type` constant) — checked against `pg_attribute`.
- **FK columns are redacted like any other column** unless granted (same as `read()`).
  Worth knowing for H5: `JOIN … ON a.task_id = b.id` from outside sees NULL there.
- **D4**: `reject_composite_pk()` in `validate_scope_path` — every table reached along
  the path, the scope table, and a table that is its own scope; all privileges. Leaf
  composite PKs generate `b.<col>` for every PK column.

Incidental findings (not acted on):
- **`letter.read()` shows only the *first* PK column** of a composite key
  (`lookup_pk_column … LIMIT 1`); the generator shows all, per D4. Parity is therefore
  not asserted for the composite-leaf fixture. Falls to D3/H6.
- **`letter.grant()` cannot target a table whose name needs quoting** (mixed case,
  spaces): `install_enforcement_triggers` interpolates the raw `schema.table` into
  `'…'::regclass` / `CREATE TRIGGER … ON …` → "invalid name syntax". Pre-existing. The
  generator, walker and validation all quote correctly — hop and scope tables with odd
  names work (fixture 9) — so only the trigger helpers need `quote_identifier`.
- **A role row with `user_id = ''`** would match sessions where
  `letter.current_user_id` is unset, defeating D2's "unidentified reads get nothing".
  `letter.roles.user_id` is `NOT NULL` but not `<> ''`. A `CHECK` would close it.
- `letter.barrier_sql()` is executable by `PUBLIC` like the other info functions; it
  reveals role names and grant structure, no data.

### 2026-09-22 — H3 substitution + D14 (`letter.c`, `test/sql/hook_infra.sql`)

Built as §1.1/§1.2 and the H0 spike laid out; 15 tests green (twice). Only
`hook_infra`, `lifecycle`, `read` and `hardening` outputs changed, all for D14 or the
DEBUG message text.

- **One walk does everything.** `collect_walker` visits every `Query`, iterates its
  `rtable` with the index (to know the result relation), applies the gate and the §4
  checks, and collects targets; conversion happens afterwards so the walk never enters
  a generated subquery. `syscol_walker` then hunts system-column Vars per target at the
  right `varlevelsup` before converting (H0's crash case — five shapes tested).
- **Protected set = `Oid → privilege bitmask`** (`protected_privs()`); `letter.grants`'
  OID is remembered for `PlannedStmt->relationOids`, appended whenever a plan was
  rewritten (H4 hooks into that).
- **D14 gate.** Read of a non-exempt relation without a `select` grant → `no grants on`
  / `no select grant on`; the result relation of INSERT/UPDATE/DELETE without the
  matching grant (UPDATE accepts `update` or `set`) → `no <priv> grant on`, at plan
  time, before the triggers ever run. Exempt: `IsCatalogNamespace`, `IsToastNamespace`,
  `isTempNamespace` (own), `information_schema`, `letter`. `letter.read()` applies the
  same check so an ungranted table errors there too (was: zero rows).
- **`MERGE`** on a protected result relation → "not supported" (§4 addition): its
  actions mix privileges; gate it properly when someone needs it.
- **Relkinds**: tables, partitioned tables and materialized views are substituted;
  anything else (foreign tables, …) → "not supported".
- **RLS** (`securityQuals` present) is refused as §4 says, but is untestable in the
  regression suite: superusers and owners bypass RLS, so the quals never appear.
- The `hook_infra` H1 test "hook on + no grants = identical plans" is gone — under D14
  that query errors. Plan-shape parity against a hand-written view is H5.9.
- `hook_infra` Test 9 shows the documented `15` §8 gap: `UPDATE … RETURNING secret`
  returns the true value (the result relation is not substituted).

### 2026-09-22 — H4 plan and cache invalidation (`letter.c`, `sql/letter--0.1.sql`, `test/sql/hook_cache.sql`)

Exactly as planned, including the bonus: 16 tests green (twice).
- `letter.cache_inval()` (the statement trigger) now also raises
  `CacheInvalidateRelcacheByRelid` — on `letter.grants` for a grants write, on the new
  empty signal table **`letter.roles_epoch`** for a roles write. `letter_relcache_callback`
  (registered in `_PG_init`) drops the protected set and the session cache on the grants
  signal, the session cache alone on the roles signal, and both on a whole-relcache
  flush (`relid == InvalidOid`).
- `hook_cache.sql` proves it with a real second backend (`dblink`, available here): a
  grant/revoke in the other session replans this session's prepared statement at its
  next `EXECUTE` (down to "no grants" under D14 after the last revoke); a role inserted
  in the other session is seen by this session's write trigger with no local roles
  write, and the cached read plan is *reused* (no "substituting"), yet already shows the
  new role's rows — the roles are read at execution.
- `14` §4.1 (cross-backend staleness) is closed for both paths.
- Test-writing note: `dblink_exec` refuses statements that return rows; use `dblink()`
  with a row type (`RETURNING 'ok'` for DML).

### 2026-09-22 — H5 behavioural tests and the default flip (`test/sql/hook_read.sql`)

17 tests green (twice). `hook_read.sql` covers H5 items 1–4, 6 and 8 (5 is
`hook_cache.sql`, 7 is `hook_infra.sql` Test 8); H5.9, the plan-shape comparison on
the `bench/barrier` data, was not run — the H0 spike already showed identical plans
for the same RTE shape, and the `bench` harness is a manual script.

- **Parity is exact**: for every user on every fixture, a plain `SELECT` through the
  hook and `letter.read()` produce the same rows and the same redaction (0/0), with
  native types (`integer`, `uuid`) rather than `read()`'s strings — `14` §4.3's
  stringification is `read()`'s problem, not the hook's.
- **The leak is closed** for `WHERE`, `IS NULL`, `ORDER BY`, `GROUP BY`, `max()`,
  `min()`, a `JOIN … ON` against a hidden column and `LIKE` — all indistinguishable
  from "no match".
- **Shapes**: two protected tables, protected + temp table, subquery, CTE, sublink,
  `UNION`, plain and `security_invoker` views, SQL and PL/pgSQL function bodies,
  whole-row Var, `INSERT … SELECT`, `UPDATE … FROM` — all through the same subquery.
- **Generic plans** (`force_generic_plan`) and PL/pgSQL's cached plans give each user
  their own rows from one plan; `SET LOCAL letter.bypass` inside a transaction flips a
  prepared statement both ways; an empty user id yields zero rows (D2).
- **RI sees the truth**: a `logger` inserts a task into a project she cannot read; a
  bad FK still fails.
- **A usability fact to document (README, done):** an FK column used in a join must
  itself be granted — otherwise it is NULL inside the barrier and the join matches
  nothing (`projects ⋈ tasks` returned zero rows for alice until `project_id` is
  granted). Same for `id IN (SELECT project_id FROM tasks)`.
- **The flip.** `letter.enforce_reads` defaults to **on**. The plan expected "~11 raw
  SELECTs" to need wrapping; under D14 every read of an ungranted table in every test
  would error, so instead the thirteen suites that test other components set
  `letter.enforce_reads = off` after `CREATE EXTENSION` (they are about the write path,
  the generator, the lifecycle, the API), and the three hook suites run their fixtures
  under `letter.bypass`. `lifecycle` §1 keeps a section with the hook on.
- **D12**: `_PG_init` warns (`letter: library loaded on demand, not preloaded`, with
  DETAIL and HINT) unless loading during `shared_preload_libraries` processing or
  named in `session_preload_libraries`. In the regression suite it appears once per
  test at `CREATE EXTENSION`, which is where the library gets loaded.

### 2026-09-22 — H6 utility hook and doc sweep

- `letter_process_utility` (chained `ProcessUtility_hook`): `COPY table TO` → refused
  with a hint to `COPY (SELECT …) TO` (which is planned, hence enforced — shown
  redacting); `COPY table FROM` → needs an insert grant (row triggers apply after);
  `TRUNCATE` on any non-exempt table → requires bypass (uniform with the TRUNCATE
  trigger on granted tables); same fast exits and D14 exemptions as the planner hook.
  `hook_infra.sql` Test 10.
- Doc sweep: `10` already carried its superseded banner; `14` §1 marked FIXED for the
  read path; `11` 5.1–5.8 ticked, 5.10 waits for D3; README updated (default on,
  preload warning, known gaps). `pg_dump` advice: with D13's deployment model the dump
  role simply has `letter.bypass = on` by default — no `PGOPTIONS` needed.
- Not done: `MERGE` (refused), the result-relation gap (`15` §8), PG16 build (5.9),
  `bench` plan-shape comparison (H5.9).

### 2026-09-22 — H6 D3: `letter.visible_columns()`, `letter.read()` deprecated

- `build_barrier_sql_ext(relid, visibility, …)`: the generator's second mode emits
  `SELECT array_remove(ARRAY[<'pk'>, CASE WHEN <tests> THEN 'col' END, …], NULL) FROM t
  b <all chain joins> WHERE (<g1 test>) OR (<g2 test>) …` — the same column tests as the
  barrier, OR-ed rather than branched (one indexed row, strictness is irrelevant), plus
  the caller's `AND b.<pk> = CAST($1 AS <pk type>)`. Composite or missing PK → error.
- `letter_visible_columns` takes `anyelement` (rendered through the type's output
  function and cast back in SQL), applies the D14 gate, runs under the guard (it *is*
  letter's enforcement), returns NULL for an invisible or missing row, and under bypass
  returns every column of an existing row.
- `hook_read.sql` §6: alice/bob/dora on Alpha/Beta/Gamma, a missing row, an ungranted
  table (error), bypass.
- `letter.read()` is marked DEPRECATED in the extension script and README; kept as the
  parity reference (`barrier_sql.sql`, `hook_read.sql`).

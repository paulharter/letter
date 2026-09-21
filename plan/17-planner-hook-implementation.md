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
                         AND r.role IN (<roles(U)>) ))          -- run-time constant → One-Time Filter

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

### H0 — Spike: prove §1.1 on one hard-coded table *(throwaway code, ≤ 1 day)*
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

### H1 — Hook infrastructure *(5.1, 5.2, 5.8)*
- Register `planner_hook` in `_PG_init()`, chaining to any previous hook, else
  `standard_planner`.
- `letter.enforce_reads` GUC; `ResetPlanCache()` assign hooks on it and on
  `letter.bypass`.
- **Protected-relation set**: backend-local hash of relation OIDs that have ≥ 1
  `select` grant. Built lazily from `letter.grants` (one SPI query, under the internal
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

### H2 — The generator *(5.3, 5.5, 5.6 — no hook involvement yet)*
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

### H3 — Substitution *(5.3, 5.7 pulled forward)*
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
- After `standard_planner` returns: append `letter.grants`' OID to
  `PlannedStmt->relationOids` (H4).

### H4 — Plan and cache invalidation *(5.6)*
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

### H5 — Behavioural tests, then flip the default
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
8. RI still works: FK insert/delete against a protected parent the user cannot see.
9. Plan shape: on the `bench/barrier` data, the hook's plan for Q1/Q5 matches the
   hand-written `v_hashed` view's plan (bench script, not a regression test).

Then: default `letter.enforce_reads = on`; update the ~11 raw `SELECT`s in existing
tests that verify state while a user id is set (wrap in `letter.bypass` from a
superuser, or accept redacted output where that is the point).

### H6 — Close the side doors, settle `letter.read()` *(5.10)*
- **`COPY protected_table TO`** does not go through the planner → true values. Add a
  `ProcessUtility_hook` that, unless bypassed, rejects it with a hint to use
  `COPY (SELECT …) TO` (which *is* rewritten). Document `pg_dump` → run with
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

Deferred:

- **D3 — `letter.read()` and `_redacted`** — `15` §9.3. *(2026-09-21: deferred until
  H6 is reached; nothing before H6 depends on it.)* Until then `letter.read()` keeps
  working unchanged — it runs under the internal guard, so the hook never rewrites its
  scan.

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

## 7. Findings log

*(Append H0 spike findings and any mid-implementation discoveries here, dated.)*

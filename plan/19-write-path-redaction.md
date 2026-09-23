# Letter — Write-Path Redaction of the Result Relation

Implements `15` §8: closes the last read leak, the **result relation** of
`INSERT`/`UPDATE`/`DELETE`. `17` H3 substitutes every *source* reference to a protected
table, but the table a statement writes to must stay a real relation for the executor,
so its hidden columns are still readable through the statement's own qual, its `SET`
right-hand sides, `RETURNING`, and `ON CONFLICT … WHERE`/`SET`. Today (2026-09-22):

```sql
UPDATE projects SET name = name WHERE secret LIKE 'a%';      -- row count is an oracle
UPDATE projects SET name = secret;                           -- copies a hidden value
UPDATE projects SET name = name RETURNING secret;            -- returns it outright
UPDATE projects SET name = name WHERE id = '<guess>';        -- error vs 0 rows reveals a hidden row
```

Any user with an `update` or `delete` grant on the table can do the first three;
the fourth needs no grant at all beyond the D14 gate. `15` §8 already decided the
shape — **triggers decide writability; the hook decides visibility** — and chose
targeted Var substitution over anything cleverer. This doc settles how it is built.

Not here: `MERGE` (stays refused, `17` §4), column-level `INSERT` enforcement (5b),
`letter.read()` (deprecated, `17` D3).

---

## 1. Mechanism — two things, both borrowed from RLS

PostgreSQL's row-level security has exactly this problem and solves it in two parts.
Letter does the same, at `planner_hook` time, on the result relation's RTE.

### 1.1 Row visibility: a security qual on the result RTE

Rows the user cannot see must not be updated or deleted — and not *loudly* not, since
an error is itself an oracle. RLS attaches its policy quals to `rte->securityQuals`;
the planner's `expand_security_quals()` then wraps the relation in a security-barrier
subquery scan while keeping it a writable result relation (the code path exists for
precisely this case). We append **one qual: the OR of every grant group's
row-visibility test** — the same tests the barrier's `WHERE` uses (`17` §2), except
that hop chains are rendered as *correlated scalar sublinks* rather than joins, since
a qual can only reference the result relation's own Vars:

```sql
(SELECT h1.project_id FROM public.tasks h1 WHERE h1.id = b.task_id)
    IN (SELECT r.scope_id::uuid FROM letter.roles r
        WHERE r.user_id = current_setting('letter.current_user_id')
          AND r.role IN ('editor') AND r.scope_table = <oid>)
OR (SELECT EXISTS (… unscoped …))
```

Strictness does not matter here (there is no scope-driven plan to protect: the rows
are already the statement's own), so a plain `OR` is fine.

The slot is free: `17` §4 refuses tables that already carry RLS quals.

### 1.2 Column visibility: targeted Var substitution

Every `Var` of the result relation, at the right `varlevelsup`, in **the qual, the
`SET` right-hand sides (`targetList`, non-junk entries only), `RETURNING`, `ON CONFLICT
DO UPDATE … SET` and `… WHERE`**, whose column is not always-visible (PK) becomes

```
CASE WHEN <column test, OR-ed over the groups covering it> THEN Var END
```

— the barrier's per-column `CASE`, with the same correlated-sublink rendering of hops.
A hidden column therefore reads as NULL wherever the statement reads it: the qual
cannot match on it (NULL is not true), `SET a = hidden` writes NULL, `RETURNING hidden`
returns NULL. Identical to the read path.

Not touched: junk `ctid`/whole-row Vars the executor uses to locate the row (system
columns, `varattno ≤ 0`), Vars of other RTEs (`UPDATE … FROM src` — `src` is already
substituted by H3), `EXCLUDED` in `ON CONFLICT` (the user's own values).

### 1.3 What the generator adds

A third mode of `build_barrier_sql_ext` — **correlated** — returns, for a relation, the
row-visibility qual and the per-column test as SQL *expressions* over alias `b`. They
are turned into expression trees by parsing `SELECT 1 FROM <table> b WHERE <expr>` and
lifting the qual out; `ChangeVarNodes(expr, 1, <result rti>, 0)` then repoints `b`'s
Vars at the result relation, sublinks included.

---

## 2. Steps

Each ends green on `make installcheck`.

### W1 — Correlated mode of the generator *(small)* — ✅ DONE 2026-09-22
`build_barrier_sql_ext(relid, BARRIER_CORRELATED, …)` → the row qual and an array of
per-column tests (NULL for PK and for never-visible columns, whose Var becomes a typed
NULL constant). Hop chains as nested scalar sublinks on the PK. Exposed for tests as
`letter.barrier_write_sql(regclass) → text` (the qual, then one line per column).
Golden-text test in `barrier_sql.sql`, plus execution: `UPDATE … WHERE <qual>` on a
view-free copy of the fixture must touch exactly the rows `letter.read()` shows.

### W2 — Hook: the security qual and the Var mutator *(½ day)* — ✅ DONE 2026-09-22
In `collect_walker`, when `rti == q->resultRelation` and the table is protected
(select bit set — a table with write grants but no select grant: every column is
hidden, the row qual is `false`; that is D14's "no select grant" by construction):
- **`CMD_UPDATE` / `CMD_DELETE`**: append the row qual to `rte->securityQuals`;
  mutate `q->jointree->quals`, `q->targetList` (non-junk), `q->returningList`,
  `q->onConflict` — with a level-tracking mutator like `syscol_walker`.
- **`CMD_INSERT`**: no row qual (the rows do not exist yet); mutate `returningList` and
  `onConflict` (`SET`, `WHERE`) — the tests evaluate against the new row's FK values.
- Whole-row Var (`varattno = 0`) of the result relation anywhere in those places →
  **refuse** (`17` §4 message) — D3 below.
- Count these as substitutions so the plan lists `letter.grants` (H4).
Test `test/sql/hook_write.sql`: each leak above closed; invisible rows skipped, count
0, no error; visible-but-unwritable rows still error from the trigger; `SET a = hidden`
writes NULL; `RETURNING` redacted on UPDATE, DELETE and INSERT; `ON CONFLICT DO UPDATE
… WHERE hidden …`; `UPDATE … FROM protected`; prepared statement across users; parity:
`UPDATE t SET x = x` updates exactly the rows `SELECT` shows.

### W3 — Plan shape *(check, not code)* — ✅ checked 2026-09-22 on the fixture; ✅ bench 2026-09-23: `UPDATE … WHERE id = …` on 1M rows is an `Index Scan using comments_pkey` with the security qual as a filter, 0.17 ms (`bench/barrier/RESULTS.md`)
`EXPLAIN` of `UPDATE … WHERE pk = …` on the `bench/barrier` data: the security qual
must not turn a PK lookup into a scan. If it does, stop (trigger 3).

### W4 — Docs — ✅ DONE 2026-09-22
`15` §8 → implemented; `17` §7/§0 gap note closed; README known gaps; `11` Phase 5.

---

## 3. Decisions

- **D1 — invisible rows are skipped, not refused.** *(Decided 2026-09-22; `15` §8 says
  so for qual matches; extended to all writes.)* `UPDATE`/`DELETE` affect only rows the
  user could `SELECT`; a hidden row is "not there", as on the read path, so neither
  the row count nor an error reveals it. A row the user *can* see but may not change
  still errors from the trigger — that is a writability answer, and loud is right.
  Changes today's behaviour, where the trigger errors on an out-of-scope row.
- **D2 — a hidden column read by a write is NULL.** *(Decided 2026-09-22.)* `SET a = hidden` writes NULL;
  `RETURNING hidden` is NULL. Same as reading it. Not an error: column visibility is
  per row, so it cannot be decided at plan time, and a data-dependent error is an
  oracle.
- **D3 — whole-row references to the result relation are refused** *(decided 2026-09-22)* (`RETURNING t`,
  `row_to_json(t)`): building a redacted `ROW(…)` is possible but not needed yet.
- **D4 — `INSERT … RETURNING` is redacted too.** *(Decided 2026-09-22.)* Defaults and generated columns the
  user did not supply are data, not schema, once the row exists.
- **D5 — `MERGE` stays refused** *(decided 2026-09-22)* until someone needs it.

---

## 4. Stop-and-discuss triggers

1. `expand_security_quals()` does not accept a qual added at `planner_hook` time on a
   result relation (it runs inside `standard_planner`; if it has been moved to the
   rewriter in PG17 the mechanism changes).
2. `ChangeVarNodes` does not repoint Vars inside the correlated sublinks correctly.
3. The security qual turns a PK-keyed `UPDATE` into a scan (W3).
4. Any existing test changes output (all of them run with `letter.enforce_reads = off`
   except the hook suites, so the only expected change is `hook_infra` Test 9's
   `RETURNING secret`).

---

## 0. Status — resume here

> **2026-09-23 — plan `20` (API rework) renamed the surface:** roles → `memberships`, assignments → `membership_rules` / `membership_sources`, `using_path` → `via`, `check_fn` → `if` (now enforced), `set` → `fill`, `letter.grant/revoke` → `grant_global/grant_scoped` and `revoke_*`, `assign/unassign` reshaped, `letter.read` → `letter._read` (test oracle only), `current_user_id` → `letter.user_id`, `barrier_sql` → `read_policy`/`write_policy`. Names in this document are as they were when it was written.

**2026-09-22: COMPLETE.** W1–W4 done; 18 regression tests green (twice). The last
read leak is closed: every location `15` §8 listed is redacted.

---

## 5. Findings log

### 2026-09-22 — W1–W4

- **PG17 applies a result relation's `securityQuals` as a security-ordered `Filter` on
  the scan, not as a subquery** (verified against PG's own RLS on an UPDATE: `Index
  Scan … Filter: (secret < 15)`). Letter's row qual comes out the same way: `Index Scan
  using projects_pkey … Filter: (ANY (id = (hashed SubPlan 1).col1))` — a PK-keyed
  UPDATE stays a PK lookup (W3). Stop trigger 1 did not fire.
- **Two things that bit, both mechanical.** (1) The planner looks for sublinks only in
  a `Query` whose `hasSubLinks` is set — the injected qual and `CASE` tests contain
  them, so every touched `Query` is flagged (nested ones from the mutator). Without it:
  "cannot handle unplanned sub-select" / "unrecognized node type" from the executor.
  (2) `query_tree_mutator` copies every RTE (`range_table_mutator`), so the RTE pointer
  collected before the mutation is stale afterwards — the row qual must be attached to
  `rt_fetch(rti, q->rtable)` *after* mutating. And the mutator walks RTEs'
  `securityQuals`, so the row qual — which must read the true scope columns — is added
  after the mutation, never before. `hasRowSecurity` is not needed.
- **Generator's correlated mode** (`BARRIER_CORRELATED`, `WriteRedaction`): hop chains
  as `(SELECT gNhK.<col> FROM h1 gNh1 JOIN … WHERE gNh1.<pk> = b.<col0>)`; row qual as a
  plain `OR` of group tests. `letter.barrier_write_sql()` shows it, one line per item;
  `barrier_sql.sql` proves the qual selects exactly `letter.read()`'s rows for six
  users on two tables.
- **A table with write grants but no select grant** gets a `false` row qual and all
  columns hidden: nothing can be updated or deleted in it and `RETURNING` shows nothing
  — D14's "no select grant" applied to writes. `hook_infra` Test 9 shows it.
- **Semantics changes visible in the suites** (both D1): a write to a row the user
  cannot see now touches nothing, where the trigger used to error (`hook_cache` §3,
  `hook_infra` Test 9). A write to a row the user *can* see but may not change still
  errors — `hook_write` §2 shows both side by side.
- **The hidden-FK rule applies to writes too**: `UPDATE notes … FROM projects p WHERE
  p.id = notes.project_id` matches nothing unless `project_id` is granted (README).
- `ON CONFLICT DO UPDATE` on a conflicting row the user cannot see: the `WHERE` cannot
  see hidden columns and `SET` cannot read them, but the update itself proceeds to the
  trigger, which may refuse loudly — the same shape as RLS, which errors there too.
  Not changed; noted.
- Not covered: `MERGE` (D5), whole-row `RETURNING` (D3, refused), the `bench` plan
  comparison on 1M rows.

# Letter — Join & Predicate Enforcement

How to make scope/column enforcement reach into the **predicates and joins** of a
query, not just the output projection — using letter's own grants/roles/scope rules
rather than RLS. This doc records the design discussion and the model we landed on
(**per-hop conjunctive gating** within letter's existing bounded, many-to-one path
model, plus **write-path redaction** via targeted result-relation substitution — §8),
the options considered, and the decisions still open.

Reads on from `14-enforcement-gaps.md` §1 (the leak), `09-scope-resolution.md`
(`using_path`), `10-query-hooks.md` (planner-hook design), `13-multihop-issues.md`
(multi-hop `using_path`, item 2.4.4). Gates Phase 5.

> **Amended 2026-09-21 by `16-scope-resolution-direction.md`:** open decision 4 is
> decided (B2 directly, no B1 — `16` §2–§3), decisions 2 and 5 are reframed (`16` §7,
> §3.3), the scope-index cache is replaced by intermediate-table materialisation
> (`16` §5), and the sequencing from step 2 onward is superseded (`16` §9). The
> enforcement model in §2–§8 here is unchanged.

---

## 1. The problem, restated

`letter.read()` redacts at the **sink**: it runs the query, gets the true values, then
NULLs columns on the way out. Every operator that consumes a value *before* the sink —
`WHERE`, `JOIN … ON`, `GROUP BY`, `HAVING`, `ORDER BY`, aggregate arguments, `DISTINCT`,
window frames — sees the truth. So a hidden value is trivially recoverable:

```sql
letter.read('public.projects', 'budget > 1000000')
-- returns the row iff budget > 1000000, even though budget comes back redacted.
-- Binary-search the predicate → read the column exactly.
```

This is a structural property of redacting at the sink, not a bug to patch. The Phase 5
planner-hook design in `10-query-hooks.md` only rewrites the *target list*, so it
inherits the same leak and widens it (`SELECT max(budget)`, `GROUP BY budget`,
`JOIN … ON a.budget = b.x` all leak once real SELECTs are intercepted).

---

## 2. The key insight: redact at the source, not the sink

Move redaction to where the value is *read*, below every operator that consumes it:
replace each protected column reference with an expression that yields the real value
when the user may read it (for that row's scope) and NULL otherwise. Once the value is
redacted at the source, the correct, leak-free semantics fall out of normal query
processing without special-casing any clause:

| Clause | After source redaction | Leak? |
|---|---|---|
| `WHERE budget > 1e6` | unauthorized rows see NULL → `NULL > 1e6` is not-true → row drops | No — can't distinguish "didn't match" from "can't see" |
| `sum(budget)` | NULLs ignored → sum over visible rows only | No |
| `JOIN … ON a.secret = b.x` | NULL never matches → unauthorized rows don't join | No |
| `GROUP BY secret` / `ORDER BY secret` | unauthorized rows collapse/sort as NULL | No |

So the question is **not** "how do I rewrite WHERE and JOIN and GROUP BY individually."
It's "how do I substitute the redacted value early enough that I never think about those
clauses one by one." That is the restructuring.

---

## 3. Three design axes

1. **Unit of rewrite** — substitute every `Var` occurrence, vs. redact once in a
   per-table source view.
2. **Hook location** — `post_parse_analyze_hook` (sees the literal query) vs.
   `planner_hook` (sees the *post-rewrite* query, with views expanded).
3. **Scope evaluation** — a per-row C function call, vs. injected FK joins + a set-based
   grant representation.

**Axis 2 is near-forced: do the rewrite at `planner_hook`, after the rewriter.**
Otherwise a protected table hidden inside a plain view escapes — parse-analyse sees `v`,
not `v`'s body. (The INSERT-column work in 5b genuinely needs parse-analyse for the
literal column list, so letter will likely run both hooks for different jobs.)

---

## 4. The options

### Option A — Consistent `Var` substitution everywhere
Walk the whole `Query` tree; rewrite every `Var` that references a protected column into
the redaction expression, in the target list *and* every qual/clause.

- **Pro:** maximally precise; no extra range-table entries.
- **Con:** you own a recursive rewrite across every node type and query shape
  (subqueries, CTEs, set-ops, LATERAL, windows, `RETURNING`), for *every clause*. Fragile,
  version-sensitive tree surgery. High risk, high maintenance.

### Option B — Per-table redacting barrier subquery  ✅ recommended
Wherever a protected table appears in the range table, swap that RTE for an inline
subquery that projects the same columns but wraps each protected one in a scope-aware
redaction expression, marked `security_barrier`:

```sql
-- the projects RTE becomes (conceptually):
(SELECT id,
        CASE WHEN letter_visible('public.projects','budget', <scope-key>)
             THEN budget ELSE NULL END AS budget,
        name, status, …
 FROM public.projects) /*security_barrier*/ projects
```

Then you do **nothing** to `WHERE`/`JOIN`/`GROUP BY`/aggregates — they reference the
subquery's already-redacted output columns. One substitution per table reference covers
every downstream operator.

This is mechanically how Postgres's own `security_barrier` views and RLS expansion work
(view-inlining + the `security_barrier` flag that stops the planner pushing a user qual
below the redaction) — but the subquery is generated from **`letter.grants`, not
`pg_policy`**. So it keeps letter's own rules mechanism and uses no RLS, while reusing
Postgres infrastructure that is already correct under pushdown/pull-up.

- **Pros:** localizes the rewrite to the range table (one transform per table ref,
  regardless of query complexity); every clause covered for free; same generator however
  deeply nested the reference is; reuses battle-tested PG machinery.
- **Cons:** mechanical cost is **Var fix-up** — after swapping `RTE_RELATION`→
  `RTE_SUBQUERY` you must rewrite outer `Var` references (varno/varattno) to point at the
  subquery (exactly what RLS expansion does — reference implementation exists).
  `security_barrier` blocks some optimizations. Applies only to *source* references —
  the result relation of `UPDATE`/`DELETE`/`INSERT` cannot become a subquery; those
  references get targeted Var redaction instead (see §8).

### Option C — Reject protected columns in predicates (capability denial)
Keep projection redaction; at analysis time, if a protected column appears in
`WHERE`/`JOIN`/`ORDER BY`/`GROUP BY`/`HAVING` and the user lacks an *unscoped* (`scope=''`)
select grant on it, raise an error. Statically decidable from cached grants; no per-row
scope eval in predicates.

- **Pro:** simplest, provably leak-free, zero predicate-rewriting cost.
- **Con:** less expressive — a user with only *scoped* read can't filter even within
  their own scope (scope is per-row, not known at analysis time → all-or-nothing). Does
  not solve projection redaction on its own. **Judged too weak** to be the primary model
  (see §6), but useful as a conservative interim stance for the predicate path.

### Option D — Executor-only tuple filtering  ✗ non-viable
An `ExecutorRun` hook can redact output tuples, but predicates already executed in the
plan. Structurally identical to the sink model we're escaping. Recorded as rejected *for
this problem* so it is not re-proposed.

---

## 5. Tractability: why the join "explosion" is a mirage (mostly)

The fear is an explosion of scope lookups through joins. That explosion is real **only in
the per-row imperative model** — `for each row: walk FK chain, look up, repeat` (what
`letter.read()` and the triggers do today): N rows × K hops × round-trips.

Scope resolution along FK chains *is just joins*, and the engine does joins as set
operations. "Resolve scope for every row of `comments`" becomes one hash/semijoin against
a small set (the user's scoped roles), O(N), with PK/FK index joins:

```sql
… FROM comments JOIN tasks ON tasks.id = comments.task_id
-- visibility: tasks.project_id IN (user's editor-scoped projects)
```

Multiple protected tables in a query add their scope-joins **additively** (sum of path
lengths), not multiplicatively. Five protected tables with 2-hop scopes = ten extra
indexed joins, not a combinatorial blow-up. **Expressed as joins, it does not explode.**
The restructuring in §2–§4 *is* the move from the exploding model to the bounded one.

This holds **only while the relationship model stays bounded**: many-to-one, fixed-depth
FK chains (which `using_path` already enforces — see `09-scope-resolution.md`). The
discipline of holding that line is what keeps the whole thing tractable; the technology is
not the limiting factor, scope creep is.

---

## 6. Where letter sits relative to Zanzibar (and why we stop short)

"Zanzibar-like" conflates two independent axes:

- **Axis 1 — model generality:** arbitrary relationship graph, relationships-as-data,
  userset rewrite/indirection, nested groups, transitive inheritance. Zanzibar's strength.
- **Axis 2 — transparent SQL enforcement:** redacting columns/rows out of live arbitrary
  SQL by per-cell permission. **Zanzibar does not play here** — it answers
  `Check(object#relation@user) → bool`; it never filters a SELECT's columns. This axis is
  letter-specific and, in the SQL-integration dimension, *harder* than Zanzibar.

**What the Phase 4 scope-index cache buys toward Zanzibar:** it is a materialized closure
of a *fixed many-to-one FK path* with path-based ("Russian-doll") invalidation — the same
*technique* as Zanzibar's Leopard index, on a much weaker model. It provides the
**performance substrate**, not model power. Caching accelerates whatever model you have;
it does not generalize it. Its `PRIMARY KEY (table_name, row_id, scope_table)` bakes in
many-to-one; real Zanzibar needs set-valued closure (graph reachability), a different
structure.

**The tension that settles it:** pushing toward Axis-1 generality *sabotages* Axis 2. The
transparent-redaction story works only because scope resolution is a fixed-depth FK join
the planner can absorb. Make scope a recursive/many-to-many reachability set and "inject
scope as joins" becomes "inject a recursive reachability query per protected table per
query" — which is exactly where "doable" tips into "impractical." You can have a rich
relationship model **or** cheap transparent in-SQL cell redaction; the combination is the
impractical zone.

**Decision: letter stays bounded.** No recursion, no many-to-many. The richness we *do*
want is per-hop enforcement along the existing fixed path (§7), which stays entirely
inside the tractable model and needs no closure index to be *capable* (the scope-index
cache remains a pure performance optimization, not an enabler).

---

## 7. The landed model: per-hop conjunctive gating on transient join steps

The goal: enforce scoped filtering on the **transient steps** of a join — the
intermediate tables traversed while resolving scope — not only the terminal scope. Two
readings, which stack:

### 7.1 Reading 1 — joined occurrences are filtered (free under Option B)
When a protected table appears as a *transient* relation inside a join (mid-join, in a
subquery, in a CTE), it must be scope-filtered the same as a top-level `FROM`. Under
Option B this is automatic: the core guarantee is that **every protected RTE becomes a
redacting barrier subquery wherever it appears in the join tree.** Nothing new to build —
but record it as an invariant and test it.

### 7.2 Reading 2 — per-hop gating along the scope path (the real feature)
When scope is resolved by walking `comment_reactions → comments → tasks → projects`,
enforce the user's visibility at *each* transient step (`comments`, `tasks`), not just the
terminal `projects`.

**This inverts letter's current semantics.** Be explicit about it:

- **Today — top-down inheritance:** the leaf's visibility is decided *solely* by the
  terminal scope. Intermediate tables are pure plumbing; transient rows are never gated.
  (This is Zanzibar's `tuple_to_userset` shape, one level deep.)
- **New — conjunctive gating:** the leaf is visible iff the user can see it at *every*
  level — `comment_reactions` visible ⟺ can see the comment AND the task AND the project.

Both are legitimate. Conjunctive gating expresses "you lose access to the reaction the
moment you lose access to its task, even if you still have project access" — a common,
wanted property. It is well-defined precisely *because* the model is many-to-one upward:
each transient step is exactly one parent row, so "is that row visible" is unambiguous.
The constraint we chose (no many-to-many) is what makes the feature clean.

**It composes with the join architecture at near-zero marginal cost.** The
scope-resolution joins you already inject to reach `projects` are the same joins you now
decorate with a per-hop visibility predicate — you are not adding joins, you are adding
`AND <user-can-see-this-intermediate-row>` to joins that already exist. Cost = one
semijoin per *protected* transient table (unprotected ones stay transparent plumbing):
linear in path length, bounded.

```
-- conceptual rewritten visibility for a comment_reactions row:
EXISTS (comment visible to user)        -- comments' own scope check
  AND EXISTS (task visible to user)     -- tasks' own scope check
  AND (project scope role held)         -- terminal anchor (today's check)
```

### 7.3 Design decisions this forces

| # | Decision | Recommendation | Status |
|---|---|---|---|
| D1 | Conjunctive layered on terminal, or replacing it? | Keep terminal scope as the anchor; **add** per-hop gating on top (strict tightening, backward-compatible in spirit) | Recommended |
| D2 | Implicit (any intermediate table with grants is auto-enforced) vs explicit (`enforce_path_visibility` flag on the grant) | **Explicit flag**, at least initially — implicit causes action-at-a-distance ("why did this query stop returning rows" six months later). Can add implicit opt-in later | **DECIDED — explicit (§7.4)** |
| D3 | What privilege gates a hop? | "Is this intermediate row visible at all" (`row_has_any_select_grant`-style on that table's scope), not full column visibility — a transient row is an anchor, not data being read | Recommended |
| D4 | NULL or invisible intermediate step | **Deny** (fail closed). Bonus: resolves the open NULL-along-the-chain question in `13-multihop-issues.md` §2 for free | Recommended |
| D5 | Trigger vs planner-hook duality | **One shared path-walker**: at each hop it (a) resolves the FK and (b) runs the intermediate visibility check. Hook calls it to generate join predicates; trigger calls it to evaluate row-by-row. Closes `13` §6 | Recommended |

### 7.4 D2 decision record — explicit `enforce_path_visibility` flag

**Decided 2026-07-08: explicit.** Per-hop gating is opt-in, per grant.

**Why explicit costs zero security:** §7.1 (Reading 1) already guarantees intermediate
tables never leak *data* — every protected RTE becomes a barrier subquery wherever it
appears, so a transient row's columns are redacted regardless of this flag. Reading 2
gating is a policy-expressiveness feature ("lose the reaction when you lose the task"),
not a leak fix. Opt-in for a security fix would be a smell; opt-in for a policy feature
is correct API design — no hole is left open by defaulting it off.

**Why not implicit:** action-at-a-distance. Under implicit, adding a grant to `tasks`
silently changes which `comment_reactions` rows unrelated users can see — the semantics
of a leaf grant would depend on the evolving global state of grants on *other* tables.
Explicit keeps semantics local (read the grant row, know the behaviour), is
backward-compatible with all existing grants, and implicit can still be layered on
later (global GUC or per-table opt-in) without breaking explicit grants.

**Mechanics:**

- New column: `letter.grants.enforce_path_visibility boolean NOT NULL DEFAULT false`.
  New optional parameter on `letter.grant()` (default false); updated on conflict like
  `using_path` / `check_fn`.
- **When true:** the grant applies to a row only if every intermediate row along
  `using_path` passes the D3 check (row-level visibility — any applicable `select`
  grant for that table/scope for this user). NULL or invisible hop → deny (D4). The
  terminal scope check is unchanged (D1 — gating is added on top of the anchor).
- **Grant-time validation:** error if the flag is set on a grant with no intermediate
  hops (unscoped grant, or direct-FK scope with NULL `using_path`) — a no-op flag on a
  permission rule is a misconfiguration; fail loud, per `13-multihop-issues.md`.
- **Evaluation:** lives in the shared path-walker (D5), so triggers and the planner
  hook gate identically on both read and write paths.

### 7.5 Hard dependency
Per-hop gating **requires building multi-hop resolution (item 2.4.4) properly first** — it
is currently the fail-open stub (`resolve_scope_id` returns NULL for non-empty
`using_path` → matches any scope; see `letter.c:1328-1330` and `14-enforcement-gaps.md`
§3.1). You cannot gate steps on a path you do not walk. Reframe 2.4.4 accordingly: *do
2.4.4 right, with conjunctive gating as the way you do it right* — and it hands you a
principled answer to 2.4.4's open NULL-chain question. Not a separate epic.

---

## 8. Write-path evaluation: the B + targeted-substitution hybrid

Option B covers every *source* reference, but the **result relation** of an
`UPDATE`/`DELETE`/`INSERT` cannot be swapped for a barrier subquery — the executor
needs the real relation to write to. Protected columns of the target table therefore
remain readable through four locations:

| Location | Leak |
|---|---|
| the qual — `UPDATE t SET flag = true WHERE secret > 5` | row count / which rows changed |
| SET expression RHS — `UPDATE t SET public_col = secret_col` | copies a hidden value into a visible column |
| `RETURNING *` | returns true values directly |
| `ON CONFLICT DO UPDATE … WHERE`, `MERGE … WHEN` conditions (PG15+) | same shape as the qual |

**Decision: close these with targeted Var substitution** — the same redaction
expression Option B's generator produces, applied to result-relation Vars in exactly
those locations. This is a small, bounded dose of Option A applied to the places B
cannot reach, and it is the same hybrid PostgreSQL's own RLS uses (policy quals
attached to the target relation's scan rather than RTE substitution) — a reference
implementation exists for the tricky parts.

The semantics come out consistent with the read path: a row whose scope the user
cannot see redacts to NULL in the qual, NULL is not-true, so **you cannot UPDATE or
DELETE rows by filtering on values you are not allowed to read.** Note the row is
*silently skipped*, not errored — an error would itself be an oracle. Same
"can't distinguish didn't-match from can't-see" property as the read path; document
as intentional behaviour.

### 8.1 Layer separation (invariant)

There are two distinct enforcement dimensions on the write path — keep them in
separate layers and do not let them bleed into each other:

- **Writability — triggers.** "May this user change this column"
  (`insert`/`update`/`set`) stays in the BEFORE triggers: they see actual OLD/NEW
  values per row (which `set`-vs-`update` requires) and they catch writes from every
  path — application SQL, functions, other triggers — not just statements the hook
  sees. The hook cannot replace them.
- **Visibility — the hook.** The hook's write-path job is *only* read-redaction of
  quals, SET RHS, `RETURNING`, and ON CONFLICT/MERGE conditions. Do not add
  column-write checks in the hook even though the statement is already being
  rewritten — hook-level checks evaluate against statement shape and cached plans,
  not per-row values, and would recreate exactly the trigger/hook divergence
  `13-multihop-issues.md` §6 warns about.

One rule, everywhere: **triggers decide writability; the hook decides visibility.**

Column-level INSERT enforcement is unaffected — it remains the Phase 5b
`post_parse_analyze_hook` item (capturing the explicit column list), which is a
writability concern and therefore feeds the trigger, per the rule above.

---

## 9. Open decisions (for the next pass)

1. **D2 — explicit `enforce_path_visibility` flag vs implicit-from-grants.**
   **DECIDED — explicit.** See §7.4 for the decision record and mechanics. (Kept in
   place to preserve the numbering of the decisions below.)
2. **Plan-cache keying on `letter.current_user_id`.** Any hook-rewritten plan depends on
   the current user's grants; a cached plan for user A must never be reused for user B.
   Key the plan cache on the user id or mark these plans non-cacheable. Correctness
   landmine — decide up front. (Also flagged in `14-enforcement-gaps.md`.)
   **REFRAMED — see `16` §7:** if the rewritten tree reads the user id and the user's
   scope sets at *execution* time, it contains nothing user-specific and the plan
   depends only on `letter.grants`. Recommended: generic plans, invalidated on grant
   changes; the entry criterion becomes "prove nothing user-specific is in the tree".
3. **`SELECT *` and the `_redacted` companion.** Transparent rewriting can't cleanly append
   a phantom `_redacted` column to arbitrary query shapes. The transparent path likely
   *loses* the NULL-vs-redacted distinction. Options: keep `letter.read()` for callers who
   want `_redacted`; add a `letter.was_redacted(table, col, pk)` companion; or accept the
   ambiguity.
   **Constraint on the "keep it" option:** `letter.read()` may not survive *unchanged*.
   It is currently the most dangerous read path — its `condition` parameter is
   raw-interpolated (injection, `14` §2.3) *and* evaluated against true values (the
   predicate oracle, `14` §1). The moment sequencing step 2 lands, the hook becomes the
   safer path; letting the function linger as "the explicit alternative" would preserve
   the very leak this redesign exists to close. If it survives, it survives **rebuilt on
   the hook's barrier-subquery machinery** (routing its query through the same redacted
   sources, which closes its predicate leak for free), kept only for the `_redacted`
   ergonomics — otherwise deprecate it at step 2.
4. **Scope evaluation build (axis 3): B1 vs B2.** B1 = a C function `letter_visible(...)`
   that resolves scope and checks cached grants — simple, one call per protected column
   per row. B2 = inject FK joins + set-based grant check — planner-optimizable but more
   generation complexity, must be many-to-one/`EXISTS` to avoid row multiplication. ~~Start
   B1, optimize to B2; scope-index cache absorbs deep paths.~~
   **DECIDED 2026-09-21 — B2 directly (`16` §2–§3).** B1 is O(candidate rows) by
   construction and opaque to the planner; it cannot meet the criterion that read cost
   scales with the user's scope set. The generated form is "join up the chain once,
   expose the scope id, test it in `WHERE` and every `CASE`" — not an `EXISTS` per column.
5. **`security_barrier` + injected joins can defeat join reordering** (force nested loops).
   So the scope-index cache is not only a "deep paths" optimization — it is also the
   fallback when the planner picks a bad plan. Treat as load-bearing, not optional.
   **REFRAMED — see `16` §3.3, §5:** the scope predicate sits *inside* the barrier, so
   the barrier should not stop the planner driving from the scope side; to be verified
   by the `16` §8 Q1 experiment before any hook code. Pending that, materialisation is
   an optimisation again, and takes the intermediate-tables-only form of `16` §5.

---

## 10. Recommended direction (summary)

- **Option B** (per-table redacting barrier subquery) at `planner_hook`, scope via **B2**
  joins directly (amended 2026-09-21 — was "B1 function first"; see `16` §2–§3).
- **B + targeted substitution on the write path** (§8): result-relation Vars in quals,
  SET RHS, `RETURNING`, and ON CONFLICT/MERGE conditions get the same redaction
  expression. Write *privileges* stay trigger-enforced — triggers decide writability,
  the hook decides visibility.
- **Per-hop conjunctive gating** (§7) as the model that gives the wanted power while
  staying bounded — terminal anchor + explicit per-hop visibility via the
  `enforce_path_visibility` flag (D2 decided — §7.4).
- **No recursion, no many-to-many.** The scope-index cache stays a performance
  optimization, never a capability enabler.
- **Prerequisite:** build 2.4.4 (multi-hop) correctly via the shared path-walker; the
  defensive "fail loud on multi-hop" fix from `13` lands regardless, immediately.

### Suggested sequencing

> Steps 2–6 below are **superseded by `16` §9** (experiment first, walker performance,
> FK-index warning, then the hook generating the B2 form directly; materialisation
> last and only if measured). Kept for the record.

1. ~~Shared scope/visibility path-walker (also unblocks the write-path multi-hop fix). Make
   multi-hop fail loud until this lands.~~ **DONE (2026-07-08)** — `walk_scope_path` in
   `letter.c`, used by triggers and `letter.read()`; real multi-hop, fail-loud validation
   at grant and enforcement time, NULL-chain denies (D4). The per-hop visibility gate
   (step 3) slots into its hop loop. Tests: `test/sql/multihop.sql`.
2. `planner_hook` RTE→barrier-subquery substitution + Var fix-up for top-level protected
   tables; plan-cache keyed on user (open decision #2 — an entry criterion for this
   step, not a later cleanup). From this point `letter.read()` is the *leakier* read
   path — rebuild it on the barrier machinery or deprecate it (decision #3).
3. Per-hop conjunctive gating decorating the resolution joins (D2 decided: explicit
   flag, §7.4 — includes the `enforce_path_visibility` column and `letter.grant()`
   parameter).
4. Nested cases (views, subqueries, CTEs, set-ops) — same generator, recursive.
5. Write-path evaluation per §8 — targeted result-relation redaction (quals, SET RHS,
   `RETURNING`, ON CONFLICT/MERGE) — and the `_redacted` companion decision.
6. B2 join-based scope + Phase 4 scope-index cache as optimization.

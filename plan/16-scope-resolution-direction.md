# Letter — Scope Resolution Direction

How a row's scope gets resolved, on both the read and write paths, without giving up
the project's original goal: **explicit permission metadata stays bounded by the
user's grants, never by the size of the application's data.** This doc records the
direction settled on 2026-09-21 after two external design reviews of the repo, and the
amendments it makes to `09-scope-resolution.md`, `15-join-enforcement.md` and the
phase checklist.

Reads on from `09-scope-resolution.md` (`using_path`, the scope index), `13` §4
(per-row × per-hop cost), `14` §4.1 (cross-backend cache incoherence) and `15` §5, §9
(tractability, open decisions 2, 4, 5).

---

## 1. The problem, restated

A permission check intersects two things that both relate to a common scope:

```
user ──roles──► (role, scope_table, scope_id)      cheap, bounded, already cached
row  ──FK chain──► scope_id                        the expensive half
```

The user side is small and proportional to the user's grants. The row side is the
missing piece: *knowing an up-to-date scope for a row*. The two obvious ways to make
it cheap — denormalise the scope onto every row, or keep a row → scope index — make
the permission data database-sized and amplify writes. Resolving dynamically keeps the
metadata bounded but costs per row.

**The two directions are different problems and get different answers:**

| Direction | Who needs it | Shape | Answer |
|---|---|---|---|
| **row → scope** (walk *up*) | write triggers — one row at a time | K PK lookups, bounded by chain depth, each row independent | keep the walker, make it cheap (§6) |
| **scope → rows** (expand *down*) | reads — many candidate rows | set operation | compile to joins the planner drives from the user's side (§3) |

Conflating them is what makes caching look attractive where it is unsafe (§4).

---

## 2. The design criterion

> **Read-path cost must scale with the size of the user's scope set, not with the
> number of candidate rows.**

The dynamic lookup is not inherently the problem; *which side drives it* is. A
many-to-one FK chain `documents → projects → organisations` has a natural inverse —
`organisation → its projects → their documents` — that ordinary btree indexes serve.
When the user's few scopes drive, a query over 10M documents touches only the rows
under those scopes.

This criterion settles `15` §9.4. **B1** (a per-row `letter_visible()` C call) can
never satisfy it — it is O(candidate rows) by construction and opaque to the planner.
**B2** (injected FK joins + set-based check) can. So:

**Decision: go to B2 directly.** Do not build B1 as a stepping stone. (Amends `15`
§9.4 and §10.)

---

## 3. Read path: the join-up-once barrier form

`15` Option B replaces each protected RTE with a redacting `security_barrier`
subquery. This section fixes what goes *inside* it.

### 3.1 Shape

Conceptual rewrite of `public.comments`, with two grants scoped to `public.projects`
via `using_path = {task_id}` — `editor` may read `body`, `viewer` may read `author`:

```sql
(SELECT c.id,                                             -- PK always visible
        CASE WHEN t.project_id IN (SELECT r.scope_id::bigint FROM letter.roles r
                  WHERE r.user_id = current_setting('letter.current_user_id')
                    AND r.role = 'editor' AND r.scope_table = 'public.projects')
             THEN c.body END                                        AS body,
        CASE WHEN t.project_id IN (SELECT … r.role = 'viewer' …)
             THEN c.author END                                      AS author,
        …
 FROM public.comments c
 LEFT JOIN public.tasks t ON t.id = c.task_id             -- hop: many-to-one onto a PK
 WHERE t.project_id IN (SELECT r.scope_id::bigint FROM letter.roles r   -- row visibility
           WHERE r.user_id = current_setting('letter.current_user_id')
             AND r.role IN ('editor', 'viewer') AND r.scope_table = 'public.projects')
) /* security_barrier */ comments
```

**This form was chosen by experiment** (2026-09-21, `bench/barrier/RESULTS.md`, "form
E"). The `WHERE` becomes a semijoin the planner drives from `letter.roles`; each
`CASE` test becomes a *hashed* SubPlan, built once per statement and probed O(1) per
row. The first draft of this section represented the user's scope sets as arrays
(`= ANY(ARRAY(SELECT …))`); that lost on two counts — a linear array scan per row per
column (6× slower at 2000 scopes), and row estimates blind to the set's size (1000
estimated vs 200,000 actual). **No arrays.**

### 3.2 Rules

1. **Join up the chain once; test many times.** Each distinct `(scope, using_path)`
   among the table's `select` grants contributes one chain of joins and one exposed
   scope-id column. Row visibility (`WHERE`) and every column's `CASE` test *that
   column* with `<scope id> IN (SELECT r.scope_id::<pk_type> FROM letter.roles …)`.
   The sub-select must stay **uncorrelated and hashable** (a plain `IN` over the user's
   role rows) so it plans as a hashed SubPlan; never re-walk the FK chain inside it.
   *(Corrected after the experiment: the first draft banned sub-selects in the target
   list and used arrays instead — measurably the wrong way round.)* Columns the outer
   query never reads cost nothing: their SubPlans are pruned.
2. **Hops are `LEFT JOIN`s onto primary keys.** Many-to-one onto a PK cannot multiply
   rows. `LEFT`, not `INNER`: a NULL/missing hop must make *this grant* not apply (D4 —
   `NULL = ANY(…)` is not true) without dropping a row that another grant makes visible.
3. **The user's scope sets are read from `letter.roles` at execution time**, not baked
   into the tree from the backend cache. Consequences:
   - roles are read under MVCC → **`14` §4.1 (cross-backend staleness) closes for the
     read path** with no invalidation protocol;
   - the rewritten tree contains no user-specific constants → see §7 for what that does
     to plan-cache keying (`15` §9.2).
4. **Cast the role side, never the row side.** `letter.roles.scope_id` is
   `VARCHAR(256)`. `p.org_id::text = r.scope_id` defeats the index on `projects(org_id)`
   — the exact index that lets the bounded side drive. Generate
   `r.scope_id::<pk_type>`; `lookup_pk_column` already returns the type.
5. **Group grants before generating; one `UNION ALL` branch per group.** Grants sharing
   `(scope, using_path)` share one join chain and their role names are merged into one
   `r.role IN (…)`. The row-visibility predicate of a branch must be a single *strict*
   test: that is what lets the planner reduce the `LEFT JOIN` to an inner join and
   start from the scope side. A single `OR` across different chains, or with an
   unscoped grant, is not strict and measurably falls off a cliff (full scan of the
   leaf: 109 ms vs 0.3 ms on 1M rows). So:
   - each additional chain is its own branch, excluding rows earlier branches already
     produced (`AND (<earlier branch's test>) IS NOT TRUE`) — mutually exclusive, so no
     de-duplication;
   - an **unscoped** select grant is a branch with no joins, gated by the run-time
     constant `(SELECT EXISTS (… user holds the role, scope_table IS NULL))`. The
     planner turns that into a `One-Time Filter`: the branch is *never executed* for
     users without the role, and the scoped branches are never executed for users with
     it (`AND NOT <same test>`).
   Both confirmed in `bench/barrier/RESULTS.md` finding 6. Plans stay user-independent.
6. **Row visibility = any applicable `select` grant** (today's
   `row_has_any_select_grant`), column visibility = the grants covering that column.
   Same semantics as `letter.read()`; PK always visible.
7. **Per-hop gating (`15` §7.4) decorates these same joins.** The intermediate rows are
   already joined, so `enforce_path_visibility` adds a predicate per protected hop and
   no new joins — exactly as `15` §7.2 anticipated.
8. **The injected `letter.roles` reference must not require the querying role to hold
   `SELECT` on `letter.roles`.** The hook sets the permission context of the RTEs it
   injects (as the rewriter does for view bodies).

### 3.3 Interaction with `security_barrier` (`15` §9.5)

The scope predicate lives *inside* the barrier — it is letter's trusted qual, in the
same position an RLS policy qual occupies. `security_barrier` only stops *user* quals
being pushed *below* it; it does not stop the planner choosing join order and index
conditions within the barrier subquery. So the fear in `15` §9.5 — that the barrier
forces a full scan + nested-loop scope check — does not apply to row filtering.
**Verified 2026-09-21** (`bench/barrier/RESULTS.md` finding 1): every strict form plans
as `roles → tasks(project_id) → comments(task_id)`, 0.6 ms for 698 of 1M rows, vs
4.6 s for a B1-style per-row function. What the barrier *does* still cost: a selective
user predicate on the protected table cannot be used as an index condition beneath it
unless leakproof (`id = 165` is pushed down; `body LIKE …` stays above as a filter over
the already-small visible set).

### 3.4 The FK-index requirement

Driving from the scope side needs a btree on every **referencing** column along the
path (`comments.task_id`, `tasks.project_id`). PostgreSQL indexes only the referenced
PK side automatically; nothing guarantees these exist. Without them the plan silently
degrades to scanning the leaf table (measured: 53 ms vs 0.7 ms on 1M rows, and it grows
with the table rather than the user).

**Decision:** `letter.grant()` checks each `using_path` column (and the final hop) for
a usable index and raises a `WARNING` naming the missing one — a warning, not an error,
because it is a performance property and the write path never needs it.
`letter.check_health()` (Phase 6) reports the same.

---

## 4. Caching: what is rejected, and the rule behind it

> **Stale-deny is tolerable; stale-allow is not.** Anything used to *admit* rows must be
> transactionally consistent with the FK data it summarises.

An `org → projects` expansion that is stale on *removal* (a project moved out of the
org) keeps showing the user documents they are no longer entitled to. "The cache need
not be authoritative, revalidate when necessary" does not survive this: revalidating
every admitted row against the FK chain is the uncached cost, and not revalidating is
a leak. Rejected, so they are not re-proposed:

- **Non-authoritative / best-effort expansion caches** on an enforcement path.
- **Per-backend in-memory expansions** (the `LetterCache` shape extended to
  `scope → ids`). Cannot be made transactionally consistent; compounds `14` §4.1; and a
  scope with 100k children is an unbounded array in every backend.
- **Per-user authorization answers** (`Alice → {project ids}`). User × data sized, and
  invalidated by both role changes *and* data changes — the write-amplification problem
  with an extra dimension.
- **Adaptive / lazily-learned caching.** Lazy population means the *read* path writes,
  which the planner-hook path cannot do (read-only transactions, hot standby).

What survives of the idea: **key derived state by relationship, never by user.** A
one-level expansion `org → projects` already exists in exactly that form — it is the
btree on `projects(org_id)`, maintained transactionally by the engine. §3 is "the index
is the cache". Anything more is §5.

---

## 5. Materialisation: intermediate tables only

When joins are not enough — deep chains, large intermediate sets — letter may
materialise ancestors. The two proposals on the table were *per-row ancestors*
(`row → scope`; this is `09`'s `scope_index`) and *per-scope descendants*
(`org → projects`). **They are the same table at different levels of the chain:** the
ancestor rows of `projects` *are* the `org → projects` expansion, indexed from the
other end. The only real choice is **which tables get materialised**, and that choice
decides the write amplification:

| | No materialisation (§3) | Ancestors of **intermediate** tables | Ancestors of **leaf** tables (`09` scope_index) |
|---|---|---|---|
| Size | 0 | ∝ intermediate rows × depth | ∝ leaf rows × depth (database-sized) |
| Leaf insert/update | free | **free** | one extra write per row |
| Re-parent an intermediate node | free | rewrites that node's *intermediate* descendants | rewrites every leaf beneath it |
| Read | K joins | leaf's own FK join + one equality | one equality |
| Bounded-metadata goal | kept | kept in spirit (schema-mid-sized, derived) | lost |

**Decision: materialise ancestors for intermediate tables, never for leaf tables.**
The leaf always joins through its own FK to its parent; the parent's ancestors come
from the closure. This keeps leaf writes free and confines amplification to re-parenting
intermediate nodes, which is rare and whose cost is bounded by the intermediate tables.

```sql
letter.row_scopes (
    table_name  text NOT NULL,     -- the materialised (intermediate) table
    row_id      text NOT NULL,
    scope_table text NOT NULL,
    scope_id    text NOT NULL,
    PRIMARY KEY (table_name, row_id, scope_table)
)   -- + index (scope_table, scope_id, table_name) for driving from the scope side
```

- **Opt-in, per table:** `letter.materialize('public.projects')`. Same grant semantics,
  different physical plan; the generator uses the closure when present.
- **Trigger-maintained, eagerly, in the writing transaction** — an ordinary table:
  MVCC-consistent, shared across backends, dumpable. Not lazy (§4).
- **Only pays when the chain above the leaf's parent is ≥ 2 hops.** For one hop the
  closure *is* the parent's FK column and adds nothing — do not build it for that case.
- **Conflict with per-hop gating.** A closure skips exactly the intermediate rows that
  `enforce_path_visibility` must check. A grant with the flag set either ignores the
  closure (uses the §3 joins) or requires every gated hop's table to be materialised
  too. Start with "ignores the closure".

This **replaces Phase 4's `scope_index`** (leaf-keyed, lazily populated, invalidated by
path). `15` §9.5 called the scope index "load-bearing, not optional"; with §3.3 that is
downgraded back to an optimisation pending measurement.

---

## 6. Write path: make the walker cheap

The per-row walk is the right shape for triggers (one row, K PK lookups). Its current
cost is mostly overhead, not traversal — so do not benchmark today's walker and conclude
FK-walking is slow:

1. **Every hop re-parses and re-plans its query.** `fetch_row_column` builds a fresh
   string and calls `SPI_execute_with_args`; there is no `SPI_prepare` anywhere in
   `letter.c`. → `SPI_prepare` + `SPI_keepplan` per `(table, column)` hop query, held in
   a backend-local hash. Saved plans are invalidated by the plancache on DDL as usual.
2. **Every hop queries the catalogs.** `lookup_fk_target` / `lookup_fk_to_table` /
   `lookup_pk_column` hit `pg_constraint` per hop per grant per row (`13` §4 already
   notes this is cacheable). → resolve the path once into a compiled form
   (`[(table, fk_col, target, pk_col, pk_type)…]`) stored with the cached grant;
   drop it on the existing cache invalidation and on relcache invalidation of any table
   in the path.
3. **No sharing across rows or grants.** A bulk insert of 10k comments touches a handful
   of tasks, and several grants usually share a path. → a **statement-local memo**
   `(compiled path, first-hop FK value) → scope_id | NULL`. Safe because the walker
   already runs its SPI reads with `read_only = true` (the statement's snapshot, blind
   to the statement's own writes): the memo returns exactly what the unmemoised walk
   would. It must not outlive the statement — key it on the command id or reset it from
   an executor-end hook (triggers have no statement-end callback of their own).

None of this changes semantics; the existing regression suite is the test. It is
independent of Phase 5 and can land first.

**DONE 2026-09-21** (checklist 2.7; `get_compiled_scope_path` + `walk_scope_path` in
`letter.c`; tests in `test/sql/walker_cache.sql`; harness in `bench/walker/`). Measured
on a 2-hop path: 10k-row bulk insert 9.85 s → 46 ms, `letter.read()` over 20k rows
39.1 s → 23 ms, single-row insert 1.05 ms → 0.12 ms. The overhead *was* the cost: the
traversal itself is ~2–4 µs per row. As built, the memo resets on command-id change and
at (sub)transaction end rather than from an executor hook, and compiled paths are keyed
by path content (not per grant) and flushed on any relcache invalidation.

The trigger path still reads roles/grants from the backend cache, so `14` §4.1 remains
open *for writes*. Out of scope here.

---

## 7. Plan-cache keying, revisited (`15` §9.2)

`15` §9.2 assumed a hook-rewritten plan embeds the current user's grants, so plans must
be keyed on `letter.current_user_id`. Under §3.2 rule 3 the tree embeds no user data:
the user id is read by `current_setting()` and the scope sets come from `letter.roles`,
both at execution. What the *shape* of the rewrite depends on is then only
`letter.grants` (and the schema).

| Option | Rewrite depends on | Cached plan reused across users? | Cost |
|---|---|---|---|
| **(a) Generic** | `letter.grants` only | safe by construction | branches for roles the user doesn't hold still appear, but cost ~nothing at run time — empty semijoin (0.02 ms for a user with no roles) or a `One-Time Filter` that never executes the branch (rule 5) |
| (b) Role-signature | grants ∩ role *names* the user holds | only among users with the same role-name set — needs a guard or forced replan on user switch | tighter plans |
| (c) Per-user (`15` §9.2 as written) | user id | never | no plan reuse on pooled connections |

**Recommendation: start with (a).** It makes the correctness landmine disappear instead
of guarding it — the same stance RLS takes with policies that read `current_setting()`.
Invalidate cached plans when `letter.grants` changes (the existing `cache_inval`
statement trigger is the place to call for a plan-cache reset). The experiment found no
case where (a)'s plans are worse once rule 5's `UNION ALL` branches are used — the one
suspected cost (unscoped grants as a run-time `OR`) is gone — so (b) has no remaining
motivation. This turns the step-2 entry
criterion from "key the plan cache on the user" into "prove the rewritten tree contains
nothing user-specific" — a property a test can assert.

---

## 8. Open questions

1. ~~**Does the planner actually drive from the scope side inside the barrier?**~~
   **ANSWERED 2026-09-21 — yes.** Harness and raw plans in `bench/barrier/`; write-up in
   `bench/barrier/RESULTS.md`. Outcomes folded back into this doc: the `IN (SELECT …)`
   form of §3.1, rule 1's correction, the measured costs behind rules 4–5 and §3.4.
   Still untested there: 3+ hop chains, per-hop gating predicates, partitioned leaves,
   the write-path result relation, and a hook-built tree vs a view (should be
   identical — a `security_barrier` view expands to exactly this subquery RTE).
2. ~~**Non-strict row-visibility predicates.**~~ **RESOLVED 2026-09-21** — confirmed as a
   real cliff (one `OR` → full leaf scan) and fixed by generating mutually exclusive
   `UNION ALL` branches, with unscoped grants as a `One-Time Filter`-gated branch. Now
   rule 5 of §3.2. Residual cost: the generator emits an append of subqueries rather
   than one subquery, and Var fix-up must cope with that.
3. **Scope-id typing.** `roles.scope_id` as text forces a cast per generated predicate
   and assumes every role row for a scope table casts cleanly. Fine for now; revisit if
   composite or non-castable PKs appear.
4. **Maintenance triggers for `row_scopes`** on self-referential or very wide
   intermediate tables — deferred until something asks for §5 at all.

---

## 9. Revised sequencing

Supersedes the "Suggested sequencing" tail of `15` §10 from step 2 onward.

0. ~~**Experiment (§8 Q1)** — hand-written barrier view, `EXPLAIN` the three forms. No C.~~
   **DONE 2026-09-21** — `bench/barrier/RESULTS.md`.
1. ~~**Walker performance (§6)** — saved plans, compiled paths, statement memo.~~
   **DONE 2026-09-21.**
2. ~~**FK-index warning at grant time (§3.4).** Small, independent.~~ **DONE 2026-09-21**
   — `select` grants only; `test/sql/index_warning.sql`.
3. **`planner_hook` barrier substitution generating the §3 form directly** (B2), generic
   per §7(a), with the "nothing user-specific in the tree" test as the entry criterion.
   `letter.read()` rebuilt on it or deprecated (`15` §9.3, unchanged).
   **Implementation plan: `17-planner-hook-implementation.md`.**
4. Per-hop gating (`15` §7.4) decorating the §3 joins.
5. Nested cases; write-path redaction (`15` §8). Unchanged.
6. **Intermediate-table materialisation (§5)** — only if step 0/3 measurements ask for it.

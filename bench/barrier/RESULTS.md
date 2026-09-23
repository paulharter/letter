# Barrier-subquery plan experiment — results

The `plan/16-scope-resolution-direction.md` §8 Q1 experiment (checklist item 5.0): do
hand-written `security_barrier` views of the shape the planner hook will generate get
plans driven from the user's scope set? Run 2026-09-21, PostgreSQL 17.9, default
planner settings except `max_parallel_workers_per_gather = 0`, everything cached.

**Data** (`setup.sql`): `comments → tasks → projects`, 1M / 100k / 10k rows; a
`roles` table shaped like `letter.roles` (102k rows, `scope_id` VARCHAR). Users:
`alice` (7 projects → 698 visible comments), `bigshot` (2000 projects → 200k visible),
`nobody`, `root` (unscoped admin). Modelled grants: `editor` → `body`, `viewer` →
`author`, both scoped to projects via `{task_id}`.

**Reproduce:**
```
createdb letter_bench
psql -d letter_bench -f bench/barrier/setup.sql
psql -d letter_bench -f bench/barrier/views.sql   -f bench/barrier/run.sql    > bench/barrier/run.out
psql -d letter_bench -f bench/barrier/views_or.sql -f bench/barrier/run_or.sql > bench/barrier/run_or.out
psql -d letter_bench -f bench/barrier/run_e.sql   > bench/barrier/run_e.out
```
Raw plans are in the `.out` files. All forms return identical rows (checked).

## Forms tested

| | Row visibility (`WHERE`) | Column test (`CASE`) |
|---|---|---|
| A `v_from` | `= ANY(array)` from a single-row FROM item | same arrays |
| B `v_initplan` | `= ANY(ARRAY(SELECT…))` InitPlan | `= ANY(ARRAY(SELECT…))` InitPlan |
| C `v_semi` | `EXISTS` semijoin on roles | `= ANY(ARRAY(SELECT…))` InitPlan |
| D `v_exists_case` | `EXISTS` semijoin | correlated `EXISTS` |
| **E `v_hashed`** | **`IN (SELECT…)` semijoin** | **`IN (SELECT…)` → hashed SubPlan** |
| B1 `v_b1` | opaque per-row plpgsql function | same function |

## Timings (`count(*), count(body), count(author)` unless noted)

| Case | A | B | C | D | **E** | B1 |
|---|---|---|---|---|---|---|
| alice — 698 of 1M rows | 0.87 ms | 0.70 ms | 0.51 ms | 0.72 ms | **0.63 ms** | **4648 ms** |
| bigshot — 200k of 1M rows | 439 ms | 417 ms | 430 ms | 45 ms | **69 ms** | — |
| bigshot, `count(*)` only | — | 25 ms | — | — | 31 ms | — |
| nobody — 0 rows | — | 0.04 ms | 0.03 ms | — | 0.02 ms | — |

| Other cases | Time | Plan |
|---|---|---|
| Leakproof user qual `WHERE id = 165` (B, C) | 0.03 / 0.02 ms | pushed below the barrier → PK index scan |
| Non-leakproof user qual `body LIKE …` (B, C, E) | 0.19 / 0.16 / 0.59 ms | stays above (Subquery Scan filter); barrier still scope-driven |
| Protected view joined to 3 more tables (B) | 1.06 ms | scope-driven |
| **Wrong-side cast** `t.project_id::text = r.scope_id` | 19 ms | Seq Scan on `tasks` — index unusable |
| **No referencing-side FK indexes** (B, C) | 53 ms | Seq Scan on `comments` (1M) + `tasks` |
| **OR-shaped: scoped OR unscoped-admin, as one `OR`** (alice) | 109 ms | Seq Scan 1M, Hash *Left* Join, 999,302 rows filtered |
| same, as gated `UNION ALL` (alice / root) | 0.31 / 131 ms | admin branch `never executed` for alice; scoped branch never executed for root |
| **OR-shaped: two chains as one `OR`** (alice) | 117 ms | Seq Scan 1M |
| same, as mutually exclusive `UNION ALL` (alice) | 0.24 ms | each branch driven from its own scope set |

## Findings

1. **The planner does drive from the scope side inside a `security_barrier`.** In every
   strict form the `LEFT JOIN` is reduced to an inner join and the plan is
   `roles → tasks(project_id) → comments(task_id)`. `plan/15` §9.5's fear does not
   materialise for row filtering. Non-leakproof user quals stay above the barrier, as
   intended, and cost only a filter over the already-small visible set.
2. **B1 is dead.** 4.6 s vs 0.6 ms — ~7,000× — for the same 698 rows, and it scales with
   the table, not the user. Confirms `plan/16` §2.
3. **Arrays are the wrong representation of the user's scope set.** Two independent
   problems:
   - `= ANY(<array Param>)` is a *linear* array scan per row per column (only constant
     arrays get hashed). At 2000 scopes × 200k rows it is ~85% of the run time
     (417 ms vs 69 ms).
   - The planner cannot see an InitPlan array's size: form B estimates 1000 rows
     whether the truth is 698 or 200,000. The semijoin forms estimate 499 and 207,468.
     A 200× underestimate will wreck join choices in the *outer* query.
4. **`IN (SELECT …)` in a `CASE` becomes a hashed SubPlan** — built once per statement
   (`loops=1`), O(1) probe per row. This corrects `plan/16` §3.2 rule 1 as first
   written, which warned against sub-selects in the target list: the thing to avoid is
   a *non-hashable* correlated subquery, not a sub-select as such. Form D's correlated
   `EXISTS` happened to be converted to a hashed subplan too, but its cost estimate was
   absurd (108M); form E's explicit `IN` gets the hashed plan with a sane cost (29k).
5. **Unreferenced protected columns cost nothing** — the SubPlans for columns the outer
   query doesn't read are pruned (31 ms vs 69 ms).
6. **`OR`-shaped visibility is a real cliff** (~150–500×, and O(table)): one non-strict
   `OR` blocks outer-join reduction and forces a full scan. **Fix confirmed:** generate
   a `UNION ALL` of branches, each with a strict predicate — an unscoped grant becomes
   a branch gated by a run-time-constant `One-Time Filter` (never executed for users
   without the role), and each additional chain's branch excludes rows earlier branches
   already produced (`… IS NOT TRUE`), so no de-duplication is needed. Plans stay
   user-independent. Leakproof user quals still push into every branch.
7. **The FK-index warning (§3.4) and the cast rule (§3.2 rule 4) are both justified** —
   75× and 27× slower respectively, and both degrade to O(table).
8. At 20% selectivity the planner keeps the nested loop into `comments` even with good
   estimates; a hash join would likely win. That is ordinary cost-model tuning
   (`random_page_cost` on cached data), not something letter should fight.

## Recommendation

Generate **form E**: `<scope-id column> IN (SELECT r.scope_id::<pk_type> FROM
letter.roles r WHERE r.user_id = <current user> AND r.role IN (…) AND r.scope_table =
…)` for both the `WHERE` and each column `CASE`; one `UNION ALL` branch per distinct
`(scope, using_path)` group plus a gated branch for unscoped grants. No arrays.

Not yet tested: 3+ hop chains, per-hop gating predicates on the joins, partitioned
leaf tables, the result-relation (write-path) case, and whether the hook-built tree
(as opposed to a view) plans identically — it should, since a `security_barrier` view
is expanded into exactly this subquery RTE.

## 2026-09-23 — the hook itself (plan/17 H5.9, plan/19 W3)

The same data under letter proper: `letter_setup.sql` loads `lx.roles` into
`letter.memberships` and makes the modelled grants for real (editor → body, viewer →
author, scoped via `{task_id}`; admin `*` unscoped; editor on tasks/projects for the
join; editor update on body for the write path). `letter_run.sql` runs the plain
queries against `lx.comments` with `letter.enforce_reads` on — the planner hook does the
rest. Warm cache, second run, PostgreSQL 17.9. Raw plans: `letter_run.out`,
`letter_run_if.out`.

| Case | hand-written form E | the hook | plan |
|---|---|---|---|
| Q1 alice, `count(*), count(body), count(author)` | 0.63 ms | **0.35 ms** | scope-driven: memberships → tasks(project_id) → comments(task_id); admin branch `never executed` |
| Q2 alice, `WHERE id = 1650` | 0.03 ms (B/C) | **0.08 ms** | PK index scan below the barrier, semijoin on memberships |
| Q3 alice, `WHERE body LIKE …` | 0.59 ms | **0.23 ms** | filter stays above the barrier (on the CASE) |
| Q4 alice, comments ⋈ tasks ⋈ projects, all three protected | — | **0.31 ms** | every table scope-driven |
| Q5 bigshot, 200k rows, three counts | 69 ms | **64 ms** | hash join tasks × 2000 scopes, hashed SubPlans for the columns |
| Q5b bigshot, `count(*)` only | 31 ms | **47 ms** | see gap 1 |
| Q6 nobody | 0.02 ms | **0.04 ms** | everything `never executed` |
| Q7 root, unscoped admin, `count(*), count(body)` | 131 ms (`v_or_union`) | **205 ms** | see gap 2 |
| W3 `UPDATE … SET body = body WHERE id = 1650` (in scope) | — | **0.17 ms** | `Index Scan using comments_pkey`, security qual as a filter — no scan |
| W3b the same, row out of scope | — | **0.02 ms** | PK scan, 0 rows, silent |
| Q1 with `if := 'author <> ''author 0'''` on the editor rule | — | 0.91 ms | see gap 3 |
| Q5 with the same `if` | — | 122 ms | see gap 3 |

Planning time: 2–3 ms per statement for this two-group table (the hook builds,
parses and analyses the barrier text on every plan; the view was pre-parsed at
0.1–0.3 ms). Prepared statements amortise it.

**Verdict.** The hook's plans are the form E plans: driven from the user's scope set,
PK lookups preserved (read and write), non-leakproof quals above the barrier, no scan
of the wrong side anywhere. Three constant-factor gaps, none structural:

1. **Unreferenced columns are not free under `UNION ALL`** (contradicts finding 5 above,
   which was measured on a single-branch view). With two groups the barrier is an
   `Append` of set-op branches, which PostgreSQL does not prune: each branch's `Result`
   node computes every CASE column (hashed SubPlan probes) even for `count(*)`, and the
   `Result` / `Subquery Scan` / `Append` nodes each add per-row overhead. 47 ms vs 31 ms
   at 200k rows; nothing at alice's scale. A one-group table has no `Append` and
   matches the view exactly (Q1).
2. **The admin branch joins the scoped groups' chains it does not need.** In branch *i*
   the generator emits the joins of every group some column tests, and the CASEs
   still say `admin OR project_id IN (…)`. For root that is a hash left join of 1M
   comments to 100k tasks (94 ms of the 205) to evaluate a test the branch's own WHERE
   already made true. Fix (generator only): in branch *i*, group *i*'s test is TRUE —
   columns covered by group *i* are plain `b.col`, and other groups' joins are added
   only for columns group *i* does not cover. For an unscoped `*` grant that is exactly
   `v_or_union`'s admin branch: `SELECT … FROM comments b WHERE <gate>`.
3. **`if` costs a correlated SubPlan per row, evaluated up to twice.** The derived-table
   form `(SELECT (<if>) FROM (SELECT b.*) AS comments)` is not pulled up: it runs as
   `Filter: (SubPlan N)` on the scan (row test) and again inside the column CASE. At
   200k rows: 64 → 122 ms; at 698 rows: 0.35 → 0.91 ms. Fix (generator only): analyse
   the expression against the table and deparse it with the row aliased `b`
   (`b.author <> 'author 0'`, whole-row as `b.*`) so it is an ordinary expression, and
   evaluate it once by folding it into the branch WHERE when the group is the branch's
   own (as in gap 2).

### After D17 (same day): fixes 2 and 3 applied

The generator now (a) deparses a rule's `if` as a plain expression over `b`
(`b.author <> 'author 0'`, whole row `b.*`), (b) treats branch *i*'s own test as TRUE
inside branch *i* — covered columns plain, other chains joined only where a column of
that branch still tests them — and (c) renders each distinct (scope, via) chain once,
shared by the groups that differ only in `if` or roles. Same data, same queries, warm:

| Case | before D17 | after D17 | form E |
|---|---|---|---|
| Q1 alice | 0.35 ms | 0.32 ms | 0.63 ms |
| Q5 bigshot | 64 ms | 66 ms | 69 ms |
| Q5b bigshot `count(*)` | 47 ms | 48 ms | 31 ms (gap 1, stays) |
| Q7 root, unscoped admin | 205 ms | **137 ms** | 131 ms |
| Q1 with `if` | 0.91 ms | **0.28 ms** | — |
| Q5 with `if` | 122 ms | **58 ms** | — |
| W3 UPDATE by PK | 0.17 ms | 0.20 ms | — |

The `if` is now `Filter: (author <> 'author 0')` on the comments index scan — no
SubPlan — and the admin branch is `SELECT b.* FROM comments b WHERE <gate>`, no join.
Gap 1 remains PostgreSQL's: an `Append` of set-op branches is not pruned.

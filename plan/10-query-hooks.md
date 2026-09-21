# Letter — Query Hooks for Read Enforcement

> **SUPERSEDED (2026-09-21).** Kept for the record of how the idea started. The hook
> location (`planner_hook`) stands; the mechanics below do not. Strategy A's per-column
> `CASE … letter_check_column(…)` wrapping redacts at the sink and leaks through
> predicates (`14` §1), and a per-row function cannot scale with the user's scope set
> (`16` §2). Current design: `15-join-enforcement.md` (what is enforced),
> `16-scope-resolution-direction.md` §3 (what is generated),
> `17-planner-hook-implementation.md` (how it is built).

## Goal

`SELECT * FROM tasks` on a table with grants should transparently enforce column-level permissions. The app doesn't call special functions or query special views — it queries tables normally and letter handles enforcement invisibly.

## PostgreSQL Hook Points

PostgreSQL's C extension API provides several hook points that can intercept queries:

### post_parse_analyze_hook
Fires after SQL is parsed into a query tree. Can inspect and modify the parsed query. Too early — we don't have plan info yet, but could tag queries that touch table with grantss.

### planner_hook
Fires when the planner converts a parsed query into an execution plan. Can replace or modify the plan. Could rewrite column references here.

### ExecutorStart_hook / ExecutorRun_hook / ExecutorEnd_hook
Fire during query execution. Can intercept results as they flow through the executor. This is where we could filter/redact column values on the fly.

### ProcessUtility_hook
Fires for utility statements (DDL, etc). Not relevant for SELECT enforcement.

## Recommended Approach: ExecutorRun or planner_hook

Two viable strategies:

### Strategy A: Planner Hook — Query Rewriting

Intercept the query at planning time. If the query targets a table with grants:

1. Look up the current user's roles and grants (cached)
2. For each column in the target list:
   - If the user has `select` on that column for all possible scopes: leave it alone
   - If the user might lack access depending on scope: wrap it in a CASE expression that evaluates scope at runtime
   - If the user definitely cannot see it: replace with NULL
3. Add the `_redacted` column to the target list

The rewritten query looks something like:

```sql
-- Original
SELECT id, name, budget FROM tasks WHERE project_id = 42

-- Rewritten
SELECT
    id,
    name,
    CASE WHEN letter_check_column('tasks', 'budget', project_id)
         THEN budget ELSE NULL END AS budget,
    array_remove(ARRAY[
        CASE WHEN NOT letter_check_column('tasks', 'budget', project_id)
             THEN 'budget' END
    ], NULL) AS _redacted
FROM tasks WHERE project_id = 42
```

**Pros:** The planner sees the full rewritten query and can optimise it. Standard PostgreSQL execution.
**Cons:** Complex tree manipulation. Must handle subqueries, CTEs, joins involving table with grantss, `SELECT *` expansion.

### Strategy B: Executor Hook — Result Filtering

Let the query plan and execute normally. In the ExecutorRun hook, intercept each result tuple before it's returned to the client:

1. Check if the result comes from a table with grants
2. For each column, check grants for the resolved scope
3. Replace denied columns with NULL
4. Append the `_redacted` array

**Pros:** Simpler — no query tree manipulation, works with any query shape.
**Cons:** The executor has already done all the work (including reading columns we'll throw away). Can't optimise away redacted columns. Harder to add the `_redacted` column since the tuple descriptor is already set.

### Recommendation

**Strategy A (planner hook)** is harder to implement but produces better results:
- The planner can optimise around the redaction
- The `_redacted` column is part of the query from the start
- It's the approach used by production-grade security extensions

Strategy B could work as a simpler first pass if needed.

## Scope Resolution in the Hook

The rewritten query needs access to the scope_id for each row. This is where `using_path` comes in:

- For direct scope (`tasks.project_id`): the column is already in the row, reference it directly
- For one-hop scope: the rewrite adds a JOIN to resolve the scope
- For multi-hop: the rewrite adds multiple JOINs (or uses the scope index cache if enabled)

The planner hook has full access to the query tree and can add joins.

## Caching Within the Hook

The hook fires per-query. For efficiency:

1. **First query in transaction:** look up the user's roles and grants, store in a transaction-local cache (C-level memory context)
2. **Subsequent queries:** reuse the cache
3. **Cache invalidation:** clear on transaction end, or when `letter.grant()`/`letter.revoke()` are called

The cache is small (typically dozens of rows across roles + grants) and lives in backend-local memory.

## Handling SELECT *

When the parser expands `SELECT *`, it becomes a list of all columns. The planner hook sees this expanded list and can wrap each column individually. No special handling needed.

## Handling Joins and Subqueries

If a query joins multiple tables and some are enabled:

- Each table with grants's columns get the redaction treatment
- Non-table with grantss pass through unchanged
- The `_redacted` column would need to be per-table or merged

This needs more design thought for complex queries.

## What enable() Does for Reads

`letter.grant()` (adding grants to a table) records the table in a metadata table (`letter.grants`) that the hook checks. The hook needs a fast way to determine if a table in the query has grants — a hash lookup against the grants set, cached in backend memory.

## Complexity and Risks

This is the most complex part of letter. Risks include:

- **Query tree manipulation is fragile** — PostgreSQL's internal query representation changes between major versions
- **Performance of the hook itself** — must be fast for queries that don't touch table with grantss (early exit)
- **Edge cases** — prepared statements, cursors, COPY, foreign tables, partitioned tables
- **Interaction with other extensions** — other hooks in the chain

These are solvable but require careful implementation and thorough testing.

## Phased Approach

1. **Phase 1:** Write enforcement only (triggers) — already partially built
2. **Phase 2:** Read enforcement via a `letter.read()` function as a stopgap
3. **Phase 3:** Planner hook for transparent read enforcement
4. **Phase 4:** Scope index cache optimisation

Phase 2 gives users something that works while phase 3 is developed. The function approach can be deprecated once the hook is ready.

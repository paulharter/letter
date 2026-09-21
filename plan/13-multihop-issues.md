# Letter — Multi-hop Scope Resolution: Issues Analysis

> **RESOLVED (2026-07-08).** Item 2.4.4 is implemented as the shared path-walker
> (`walk_scope_path` in `letter.c`), per D5. Decisions taken: the final FK hop may be
> named explicitly in `using_path` (issue 1 — the path may land on the scope table);
> the inferred final hop requires exactly one candidate FK and errors otherwise;
> NULL along the chain denies, per D4 (issue 2); grant-time validation walks the full
> chain including the final hop (issue 3); triggers and `letter.read()` share the one
> walker (issue 6), which the Phase 5 planner hook will also call. Per-row × per-hop
> SPI cost (issue 4) is accepted for the trigger path — the planner hook expresses the
> same walk as joins, and Phase 4's scope-index cache remains the deep-path fallback.
> Kept for the analysis record; tests in `test/sql/multihop.sql`.
>
> **Update 2026-09-21:** issue 4's cost on the trigger path is now scheduled work, not
> just accepted — saved plans, compiled paths and a statement-local memo
> (`16-scope-resolution-direction.md` §6, checklist 2.7). The scope-index fallback is
> replaced by intermediate-table materialisation (`16` §5).

Analysis of the issues blocking implementation of item 2.4.4 (multi-hop `using_path` resolution). Captured as a record before committing to implementation work. See `09-scope-resolution.md` for the original design, `11-implementation-phases.md` §2.4.4 for the phase status.

## The fallthrough is a bug, not a gap

The most urgent thing is that 2.4.4 isn't just a missing feature — the current fallback is **silently permissive**.

In `resolve_scope_id` at `letter.c:1241`, the multi-hop branch does `return NULL`. In `check_grant`, a NULL scope_id means "match any scope" — so a user writing:

```sql
SELECT letter.grant('select', 'public.comments', 'editor', ARRAY['body'],
    'public.projects', ARRAY['task_id'], NULL);
```

gets a grant that *looks* scoped but enforces as unscoped. The 1.5 validation confirms the FK columns exist at grant time but doesn't catch the enforcement-time fall-through.

Before implementing multi-hop properly, we should at minimum **fail loudly** at grant time or enforcement time when a multi-hop path is declared — better to error than silently bypass.

## Design issues to resolve before code

### 1. Final-hop ambiguity

`09-scope-resolution.md` says the final FK (from last chain table to scope table) is *inferred*. Fine if there's exactly one path — but if `tasks` has both `owner_project_id` and `source_project_id` pointing to `projects`, the design has no way to disambiguate.

Fix is probably to extend `using_path` to include the final FK column explicitly. That's a semantics change worth making now rather than wedging in later.

### 2. NULL along the chain

If `comment.task_id IS NULL` mid-chain, what's the scope? Three defensible answers, each with different security implications:

- NULL scope (matches unscoped roles only)
- Deny outright
- Treat as a distinct "orphan" state

Needs an explicit decision.

### 3. Grant-time validation is incomplete

What we added in 1.5 walks each hop's FK but doesn't verify the last table has a path to the scope table. A multi-hop grant can validate OK and still fail at enforcement. Full validation means walking the chain *and* resolving the final hop.

## Implementation issues

### 4. Per-row × per-hop SPI round-trips

In a trigger you can't JOIN your way to the scope — you walk the chain with SPI queries. For K hops you need:

- K `pg_constraint` lookups (what's the next table)
- K FK-value fetches (what's the key in the next row)

The `pg_constraint` side is cacheable (metadata doesn't change mid-transaction). The value fetches are per-row. Manageable in triggers; expensive in `letter.read()` on large result sets. Phase 4's scope index cache exists precisely to address this.


### 6. Trigger vs planner-hook duality

Phase 5 rewrites SELECT queries into JOIN-based plans — that's the natural way to express multi-hop for reads. If we implement multi-hop imperatively in triggers first, and declaratively in the planner hook later, we'll have two implementations with potentially divergent edge-case behaviour.

Decide now: are they one shared C helper walking `using_path`, or two parallel code paths?

### 7. Minor defensive stuff

- Self-referential FKs (`comments.parent_id → comments.id`) can cycle — need a max-depth cap.
- Schema drift between grant time and enforcement time (FK dropped) — currently no detection, `check_health()` in Phase 6 would catch it.

## Recommendation

Before any implementation work on 2.4.4:

1. **Short-term defensive fix**: make multi-hop paths fail loudly at grant time (not silent permissive at enforcement time). Very small change, closes the security bug until 2.4.4 lands.
2. **Update `09-scope-resolution.md`** with decisions on:
   - Explicit final-hop FK column in `using_path`
   - NULL handling along the chain
   - Shared helper vs split trigger/planner paths
3. **Then** implement 2.4.4.

Steps 1 and 2 are probably an hour of work each. Step 3 is a real piece of work.

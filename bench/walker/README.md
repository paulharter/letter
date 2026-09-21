# Path-walker micro-benchmark

Checklist item 2.7.4 (`plan/16-scope-resolution-direction.md` §6). A two-hop path
(`reactions → comments → tasks → projects`, final hop inferred), two grants sharing
it, 10k-row bulk inserts and a 20k-row `letter.read()`.

```
createdb letter_walker_bench
psql -d letter_walker_bench -f bench/walker/bench.sql
```

Results, 2026-09-21, PostgreSQL 17.9, Apple silicon, everything cached. "Before" is
`letter.c` at commit f94eff5 (per-row catalog lookups, every hop re-planned); "after"
adds compiled paths, saved plans and the statement-local memo.

| | Before | After |
|---|---|---|
| Bulk insert, 10k rows over 1000 comments | 9850 ms | 46 ms |
| Bulk insert, 10k rows over 10 comments | 9681 ms | 26 ms |
| `letter.read()`, 20k rows | 39116 ms | 23 ms |
| Single-row insert (one statement) | 1.05 ms | 0.12 ms |

The "before" numbers barely move between 1000 and 10 distinct parents — the cost was
parse/plan and `pg_constraint` lookups per hop per grant per row, not the traversal.

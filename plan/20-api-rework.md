# Letter — API Rework: names, the grant split, and `if`

The UX pass of 2026-09-23, gathered into one change so the external surface moves
once. Nothing here changes enforcement semantics except the last item (`when`, which
enforces a column that was stored but never evaluated). Pre-release: no compatibility
layer, the `0.1` script is rewritten in place.

Decisions already taken elsewhere and carried in: `17` D15 (a grant's identity is the
whole rule), `17` D16 (a scoped select grant discloses its own path column), `17` D2 as
amended (an unset user errors on reads too), `18` D7 (`forget_user`).

---

## 1. Names

One convention: **no underscore = API, underscore = plumbing.** One vocabulary: a
**membership** is a user holding a role in a scope; **the global scope** contains
everything ("unscoped" is retired from the docs).

| Was | Becomes | Why |
|---|---|---|
| `letter.roles` | **`letter.memberships`** | the PostgreSQL-roles collision; a row *is* a membership |
| `letter.assignments` | **`letter.membership_rules`** | says what it is |
| `letter.role_assignments` | **`letter.membership_sources`** | (rule, source row) → membership |
| `letter.roles_epoch` | `letter._membership_signal` | plumbing |
| `letter.grant` | **`letter.grant_global`, `letter.grant_scoped`** | §2 |
| `letter.revoke` | **`letter.revoke_global`, `letter.revoke_scoped`** | mirrors the split |
| `letter.assign` / `unassign` | unchanged | Paul's call 2026-09-23: the verbs are fine once the tables say *membership* |
| `using_path` | **`via`** | reads as prose |
| `check_fn`, `if_fn` | **`if`** | one word for one idea; it is a predicate, not a function. (*`when`* was chosen first and is a reserved word — S1, 2026-09-23) |
| `role_name` / `role_column` | `role` / `role_column` | the constant is the common case |
| privilege `set` | **`fill`** | "update only while NULL" is what *fill* says |
| `letter.current_user_id` (GUC) | **`letter.user_id`** | pairs with the function |
| `letter.current_user()` | **`letter.user_id()`** | SQL's `current_user` is the *database* role |
| `letter.require_user()` | `letter._user_id()` | plumbing (what barriers call) |
| `letter.barrier_sql`, `barrier_write_sql` | **`letter.read_policy`, `letter.write_policy`** | shows the policy enforced for a table; "barrier" is jargon |
| `letter.read` | **`letter._read`** — plumbing, test-only, undocumented | it is the only read-side consumer of the walker: the walker-vs-generator parity oracle (`15` D5) needs it (S2, 2026-09-23) |
| `letter.enforce_reads` | unchanged | documented as "the query hook: reads, and the plan-time gate on writes" |
| `cache_inval`, `role_cleanup`, `enforce_*`, `on_sql_drop`, `on_ddl_command_end`, `_problems`, `_qualname` | `_`-prefixed | plumbing |
| generated `letter_insert_<uuid>` …, `source_upsert_<uuid>` … | `letter_rule_<id8>_insert` …, `letter._rule_<id8>_upsert` … | visible in `\d`; 8-char id |
| `list_grants`, `user_permissions`, `check_health`, `visible_columns`, `forget_user`, `bypass`, `scope`, `columns`, `on_table`, `select/insert/update/delete` | unchanged | |

Column `letter.grants.using_path` → `via`, `check_fn` → `if`. Error messages: one
voice, `letter: …` (the error-voice item of the UX pass is folded in here).

## 2. The API

```sql
letter.grant_global(privilege text, on_table regclass, role text, columns text[],
                    if text DEFAULT NULL) → boolean
letter.grant_scoped(privilege text, on_table regclass, role text, columns text[],
                    scope regclass, via text[] DEFAULT NULL, if text DEFAULT NULL) → boolean
letter.revoke_global(privilege text, on_table regclass, role text, columns text[]) → boolean
letter.revoke_scoped(privilege text, on_table regclass, role text, columns text[],
                     scope regclass) → boolean

letter.assign  (source_table regclass, user_column text,
                role text DEFAULT NULL, role_column text DEFAULT NULL,
                scope regclass DEFAULT NULL, if text DEFAULT NULL) → boolean
letter.unassign(source_table regclass, user_column text,
                role text DEFAULT NULL, role_column text DEFAULT NULL,
                scope regclass DEFAULT NULL) → boolean

letter.forget_user(user_id text) → bigint
letter.user_id() → text                      -- NULL when unset
letter.visible_columns(rel regclass, pk anyelement) → text[]
letter.read_policy(rel regclass) → text
letter.write_policy(rel regclass) → text
letter.list_grants(role text DEFAULT NULL), letter.user_permissions(user_id text),
letter.check_health()
```

- `columns` defaults to `'{*}'` for `insert` and `delete` (row-level privileges: the
  column list is noise there); required for `select`, `update`, `fill`.
- `revoke_*` removes every rule under its key (`17` D15).
- `assign` / `unassign` require `letter.bypass` (`17` D13).
- The grants table keeps one row per (rule, column); `if` and `via` are rule
  attributes, part of the identity (D15).

## 3. `if` — enforced

A boolean SQL expression over **the row's own columns**, evaluated by the same engine
in both enforcement paths (`15` D5):

- **In the barrier** (`select` grants — reads, and the write path's visibility of
  `19`): the grant group's row test and each of its column tests gain
  `AND (SELECT (<if>) FROM (SELECT b.*) AS <table>)`. Inside that subquery only the
  row's columns are in scope (unqualified names cannot be ambiguous with hop tables)
  and the row is nameable as the table (`can_edit(projects)` is just an expression).
- **In the triggers** (`insert`/`update`/`delete`/`fill` grants): one prepared plan per
  rule, `SELECT (<if>) FROM (SELECT ($1).*) AS <table>`, the tuple passed as a
  composite. For `update`/`fill` there are two forms, told apart at grant time by
  preparation:
  - **single-row** (mentions neither `old` nor `new`): evaluated on OLD and on NEW,
    **both must pass** — the strict default, mirroring scope for updates ("editors may
    edit drafts" checked on NEW alone would let a published row be edited by first
    turning it back into a draft);
  - **transition** (names `old`/`new`): `… FROM (SELECT ($1).*) AS old, (SELECT ($2).*)
    AS new`, evaluated once.
  A `select`/`insert`/`delete` rule naming `old`/`new` is refused: those operations have
  one row.
- **Row contents only** (the boundary we can extend later): no sublinks
  (`hasSubLinks` of the prepared expression); user-defined functions must be
  `IMMUTABLE`; `pg_catalog` functions and `letter.user_id()` are allowed — so
  `owner_id = letter.user_id()::uuid` is the authorship rule. Refused at grant time with
  a message saying why.
- **Validation** at grant time is preparation of the expression in the right context;
  **revalidation** by the lifecycle machinery is the same (a renamed column is refused
  under `ALTER`, a dropped one removes the rule with a `NOTICE`).
- `assign(… if := …)` keeps its meaning (the source row must satisfy it to
  confer a membership) and gets the same validation.
- **Strictness** (`16` §3.2 rule 5) holds: the row test is `<scope test> AND <if>`,
  still a single strict predicate; the check is a filter after the semijoin.
- Cached plans: the text is user-independent; the user is read at execution.

## 4. Steps

Each ends green on `make installcheck`, on PG17, and on PG16 at the end.

### N1 — Renames *(½ day, mechanical)* — ✅ DONE 2026-09-23 (S1 → `if`, S2 → `letter._read`)
Tables, columns, functions, GUC, trigger/function name patterns, error-message voice;
every test call site; README and the plan docs' status lines (historical text stays).
`letter.read` removed — its parity duty in `barrier_sql.sql`/`hook_read.sql` passes to
`visible_columns()` plus a plain-`SELECT`-vs-write-path check.

### N2 — The split *(small)* ✅ 2026-09-23
`grant_global`/`grant_scoped`, `revoke_*`, the reshaped `assign`/`unassign`
as thin SQL wrappers over the existing C entry points; `columns` defaults; `fill`.

### N3 — `if`, read path *(½ day)* ✅ 2026-09-23
Generator: the `if` term in all three modes (subquery, visibility, correlated).
Validation at grant time (`_if_prepare`), the row-only checks, revalidation.
Tests: `barrier_sql.sql` fixtures with `if` on select grants; parity with
`visible_columns()`; refused shapes.

### N4 — `if`, write path *(½ day)* ✅ 2026-09-23
Trigger evaluation with prepared plans (cached alongside the compiled paths, flushed
with them); single-row vs transition forms; `assign(… if)`. Tests:
`enforce_write.sql` (authorship, transitions, both-must-pass), `hook_write.sql`
(select-grant `if` in the write-path visibility).

### N5 — Docs ✅ 2026-09-23
README rewritten around the vocabulary (membership, global scope, `via`, `if`,
`fill`); `11` ticks; `17`/`18`/`19` status lines.

## 5. Decisions

- **D1 — the vocabulary and renames of §1.** *(Decided 2026-09-23.)*
- **D2 — the split and defaults of §2.** *(Decided 2026-09-23.)*
- **D3 — `if` as an inline row predicate, enforced as §3.** *(Decided 2026-09-23.)*
  Single-row form on `update`/`fill` requires both OLD and NEW to pass; transition form
  names `old`/`new`; row contents only — no sublinks, user functions `IMMUTABLE`,
  `letter.user_id()` allowed.
- **D4 — `letter.enforce_reads` keeps its name**, documented as the query hook.

## 6. Stop-and-discuss triggers

1. Preparing `if` in the trigger path needs something the existing prepared-plan
   cache cannot hold (composite-typed parameters of the table's row type across
   `ALTER TABLE`).
2. An `if` on a `select` grant measurably breaks the scope-driven plan (W3-style
   check on the bench data).
3. Any existing behavioural test changes for a reason other than a rename.

## 0. Status — resume here

**2026-09-23: COMPLETE — N1–N5 ✅; 18 tests green (twice) on PostgreSQL 16.15 and 17.9.**
N4 landed: `if_holds()` in `grant_applies()` — the row test is `<scope> AND <if>` in the
triggers as in the barrier; one prepared plan per (table, form, text), `SELECT (<if>)
FROM (SELECT ($1).*) AS <table>` (row form, the tuple as a composite) or `… AS old,
(SELECT ($2).*) AS new` (transition), cached in the compiled-path context and flushed
with it (relcache invalidation), the form found by preparing (row first, transition
only for update/fill). The update trigger already checks OLD and NEW separately, which
is the single-row "both must pass" rule; a transition rule sees both tuples in either
call. `letter._read()` evaluates `if` too now (same `grant_applies`), so the walker
oracle matches the barrier again. `assign(… if)`: validated in the row form over the
source table; the condition is rendered as `(SELECT (<if>) FROM (SELECT (NEW).*) AS
<source>)` in the rule's trigger function and `… (SELECT s.*) …` in the backfill, so
unqualified names bind to the source row in both (before, the trigger form needed
`NEW.col` and the backfill did not — and a quote in the text broke the INSERT into
membership_rules; now `quote_literal`). Membership rules are revalidated with their
`if` (dropping a named column removes the rule with a NOTICE). Error messages name
both forms when both were tried. Tests: enforce_write 12 (single-row both-must-pass,
transition, authorship on insert/delete/fill, NULL if fails, refused shapes),
hook_write 9 (a select-grant `if` in the write path: hidden rows skipped, RETURNING
of a row that just became hidden is redacted), assign 6 (backfill, insert, change,
validation, column drop). N5: README rewritten (memberships, membership rules, `if`,
`fill`, the split API, examples); `11`, `17`, `18`, `19` carry a pointer to this plan.
**Left over (not in this plan):** the `CONTEXT: PL/pgSQL function letter.grant_scoped…`
line under grant-time errors is noise from the SQL wrappers; `if` evaluation in the
update trigger runs one SPI plan per applicable rule per check (up to four checks per
changed column) — fine for the rule counts in view, measurable later if it matters.
N3 landed: `validate_if_expr()` (grant time and revalidation) — the text must be one
expression (`raw_parser` in `RAW_PARSE_PLPGSQL_EXPR` mode, then the SelectStmt must
have nothing but one target), analysed as `SELECT (<if>) FROM (SELECT * FROM t) AS t`
(row form) or `… AS old, … AS new` (transition form, update/fill only, tried second);
must be boolean; no sublinks/aggregates/window/SRFs; every function pg_catalog,
IMMUTABLE, or `letter.user_id()`. Generator: groups keyed by (scope, via, if); the
test becomes `(<scope test> AND (SELECT (\n<if>\n) FROM (SELECT b.*) AS <table>))`
in all three modes — the derived table binds unqualified names to the row before
anything outside it, the row IS nameable as the table (`is_public(notes)` works:
verified), and the planner flattens it to a Result node. Tests: barrier_sql fixture 10
(three rules incl. authorship via `letter.user_id()`, parity against
`visible_columns()`, the correlated form, ten refused shapes, rename refused / drop
removes), hook_read case 8 (through the hook, the predicate leak stays closed),
grant_revoke's placeholder `is_active()` replaced by a real expression (it is
validated now). Findings: `letter._read()` does not evaluate `if` (the walker is a
test oracle only — fixture 10 uses `visible_columns()` for parity); a rule whose `if`
calls a user function that reads a dropped column survives revalidation (letter
cannot see inside function bodies) and fails at execution.
N2 landed: C entry points exposed as `letter._grant/_revoke/_assign/_unassign`; SQL
wrappers `grant_global` (no scope/via), `grant_scoped` (scope required — NULL raises),
`revoke_global` (`columns` defaults to `'{*}'`), `revoke_scoped`, `assign`/`unassign`
reshaped (`role`, `role_column`, `scope`, `if` all named, scope no longer positional);
`_columns_or_default` supplies `'{*}'` for insert/delete and raises for the rest. All
test call sites rewritten mechanically; the normalised diff of expected vs results showed
only the echoed statements, result headers, an error-position offset in grant_revoke, and
multihop test 10 (an unscoped grant with a `via` is no longer expressible, so it now
exercises `grant_scoped` with a NULL scope). README API block and example updated.
Landed: `memberships` / `membership_rules` / `membership_sources` / `_membership_signal`;
`via`; `role`; `fill`; GUC `letter.user_id`; `letter.user_id()`; `_user_id()`;
`read_policy` / `write_policy`; every plumbing function `_`-prefixed; generated objects
`letter._rule_<id8>_upsert|delete|scope_delete` and triggers `letter_rule_<id8>_insert|
update|delete|scope_delete`; one error voice (`letter: …`, warnings too).

### S1 — `when` is a reserved word — ✅ RESOLVED 2026-09-23 → `if` (Paul)
`WHEN` is `RESERVED_KEYWORD` in `kwlist.h`: it cannot be a column or a parameter name
without double quotes at every use, including `"when" := …` in calls. Verified: `CREATE
TABLE t (when text)` and `CREATE FUNCTION f(when text)` are syntax errors. `IF` is an
unreserved keyword and works bare (`f(x, if := 'a')`); `via` and `fill` are not keywords.
Options: **`if`** ("editors may update status *if* …" — reads as well as *when*, and
`assign(… if := …)` matches its old `if_fn`), `only_if`, `condition`, `rule`.
*Claude's lean: `if`.* D1 named `when`; needs Paul.

### S2 — removing `letter.read` loses the walker-vs-generator parity oracle — ✅ RESOLVED 2026-09-23 → kept as `letter._read`, test-only (Paul)
D1 removes `letter.read`, handing its parity duty to `visible_columns()` plus a
select-vs-write-path check. But `visible_columns()` is built by the same generator the
barrier is — it cannot catch a generator bug. `letter.read()` is the only remaining
consumer of the *walker* on the read side, and `barrier_sql.sql` / `hook_read.sql`
compare walker against generator on every fixture (`15` D5: "the trigger/walker and the
hook must agree"). Options: **(a)** keep it as plumbing, `letter._read(table, condition)`,
test-only, undocumented — the oracle survives, the public API loses the name; **(b)**
remove it and accept that D5 is then checked only on the write path (`hook_write`
parity: rows updatable = rows selectable). *Claude's lean: (a).* Needs Paul.


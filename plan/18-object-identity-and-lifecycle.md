# Letter — Object Identity and Lifecycle

Reopens how letter identifies the tables it protects (`17` D8, S5) and settles, in one
place, what happens to letter's state when the objects it depends on are renamed,
altered or dropped — and what happens to a table's protection when its grants, roles or
assignments go away. Subsumes `11` Phase 6 (Cleanup and Lifecycle).

**Sequencing:** runs *before* `17` H3. H3/H4 build the hook around the identity model,
so changing it afterwards would mean rebuilding them; changing it now costs a mechanical
rewrite of Phase 1–2 code that is already covered by tests.

Raised 2026-09-22 by Paul: (1) tracking renames through name-keyed state (`17` S5) is
open-ended — reconsider OIDs; (2) as in the original DDLX design, every deletion should
clean up after itself by cascade; (3) audit deletion/mutation robustness for *every*
object letter touches, not just tables.

---

## 1. Identity

**Tables are identified by OID; columns by name.**

| | Today | After |
|---|---|---|
| protected table, scope table | `'schema.table'` text | `regclass` (OID) |
| assignment source/scope | text | `regclass` |
| `roles.scope_table`, `role_assignments.*_table` | text | `regclass` |
| unscoped sentinel | `scope = ''` | `scope = 0` (`InvalidOid`) |
| columns (`column_name`, `using_path`) | names | names (unchanged — §1.2) |
| scope ids | PK values as text | unchanged |

### 1.1 What OID identity buys and costs

Buys: `ALTER TABLE … RENAME` / `SET SCHEMA` need no tracking — every reference follows
the table. The protected-relation set is a plain OID hash and the hook compares
`rte->relid` directly (`17` D8 is superseded). Drop-and-recreate becomes *consistent*: the
new table is a new table, unprotected like any other, with no grants and no triggers —
today it is protected for reads but not for writes. `regclass` parameters resolve and
quote names correctly (fixes the `"Mixed Leaf"` bug, `17` §7) and refuse a missing table
(`17` D10 for free).

Costs: a dropped table leaves rows holding a dead OID — closed by the `sql_drop` handler
(§3). Dump/restore needs the columns typed `regclass`, not `oid`, and letter's tables
registered for dumping — which they are not today (§4). `pg_upgrade` preserves relation
OIDs from PG 15 (fine for the PG16/17 target). Logical replication or copying
`letter.*` rows between databases carries the wrong OIDs — documented, not solved.

### 1.2 Why columns stay names for now

A renamed column fails **closed** everywhere: a `select` grant on it stops covering
anything (the column reads NULL), a write grant stops permitting anything, a
`using_path` through it makes the walker error loudly. So column renames are an
operational problem, not a leak — and §3 turns them from silent to refused. Attribute
numbers would follow renames but not drop-and-re-add; not worth it yet.

### 1.3 The generated SQL

Table names in the barrier SQL and in the generated trigger functions are rendered from
the catalogs at generation time, as now. Two places must embed the **OID**, not a name
that would be re-resolved at run time: the scope test `r.scope_table = <oid>` in the
barrier, and the `source_table` / `scope_table` values written by the generated
assignment trigger functions.

---

## 2. Schema

- `letter.grants.on_table regclass NOT NULL`, `scope regclass NOT NULL` (0 = unscoped);
  PK unchanged in shape; `grants_on_table_role_idx` unchanged.
- `letter.assignments.table_name regclass`, `scope_table regclass`.
- `letter.roles.scope_table regclass` (NULL = global, `17` D11);
  `role_assignments.source_table regclass`, `scope_table regclass`.
- `letter.roles.user_id`: add `CHECK (user_id <> '')` — an empty user id would match
  sessions with `letter.current_user_id` unset, defeating `17` D2 (`17` §7).
- API: `grant`/`revoke`/`assign`/`unassign` take `regclass` where they take a table
  name today; `list_grants` / `user_permissions` render `regclass` as text. Existing
  callers passing `'public.projects'` literals keep working (implicit cast); tests
  that `SELECT … FROM letter.grants` directly change output (OIDs unless cast).
- `SELECT pg_catalog.pg_extension_config_dump('letter.grants', '')` etc. for the four
  tables — see §4 before deciding which.

---

## 3. Lifecycle contract

**Principle.** *Dropping* something letter depends on removes the letter state that
depended on it, with a `NOTICE` per row removed. *Altering* something so that existing
letter state no longer makes sense is **refused**, with the same message grant time
would have given. Removing letter state (revoke, unassign, drop of the last grant)
removes the enforcement it installed. Nothing is ever left half-protected.

Mechanism: one `sql_drop` event trigger (cascade) and one `ddl_command_end` event
trigger (revalidation: re-run `validate_scope_path` + column-existence checks for every
grant and assignment touching an altered table; error on failure, which rolls the DDL
back). Both live in the extension script and call C helpers already present.

### 3.1 Mutation matrix

The audit Paul asked for. Every row is a test in `lifecycle.sql` unless marked *doc*.

| Object | Mutation | Required behaviour | Mechanism |
|---|---|---|---|
| protected table | rename / set schema | protection follows; grants, triggers, hook unchanged | OID (§1) |
| protected table | drop | grants on it removed; assignments using it as source/scope removed (→ role_assignments → roles); roles scoped to it removed; NOTICE | `sql_drop` |
| protected table | drop + recreate | new table is unprotected; nothing claims otherwise | OID; `hook_infra` 5a inverted |
| protected table | `TRUNCATE` | **gap today**: row triggers don't fire. Install a `BEFORE TRUNCATE` trigger with the others: error unless `letter.bypass` | trigger |
| protected table | drop column | grants on that column removed; grants whose `using_path` passes through it removed; NOTICE | `sql_drop` (reports `table column`) |
| protected table | rename column | refused while a grant / `using_path` / assignment references the old name | `ddl_command_end` revalidation |
| protected table | alter column type | allowed; barrier regenerates from catalogs; scope-id casts follow the new PK type | revalidation passes |
| protected / hop / scope table | drop or change PK | refused if the table is a scope or hop (single-column PK required, `17` D4); allowed on a leaf | revalidation |
| hop / protected table | drop FK on a path | refused ("using_path column … is not a foreign key") | revalidation |
| hop table | add second FK making an inferred final hop ambiguous | refused | revalidation |
| hop table | drop | grants whose paths pass through it removed; NOTICE | `sql_drop` + revalidation of remaining grants |
| scope table | drop | grants scoped to it removed; assignments scoped to it removed (their source triggers/functions dropped); roles scoped to it removed; NOTICE | `sql_drop` |
| source table (assignment) | drop | assignment removed with its trigger functions; role_assignments → roles cascade | `sql_drop` |
| source table | rename | follows | OID |
| source table | drop `user_column` / `role_column` / scope FK column | assignment removed, NOTICE | `sql_drop` |
| source table | rename those columns | refused | revalidation |
| index on a path column | drop | allowed; WARNING as at grant time (`16` §3.4); `check_health` reports | `ddl_command_end` |
| source row | delete | role_assignment → role removed | exists |
| source row | update `user_column` / `role_column` / scope FK | role row updated | exists (upsert trigger) |
| scope row | delete | role_assignments → roles removed | exists (`scope_delete` trigger) |
| scope row | PK update | only possible with `ON UPDATE CASCADE` on the FK, which fires the source upsert trigger → role updated; otherwise the FK refuses it | exists — *doc* + test |
| user | "deleted" | letter has no users table: `user_id` is an opaque string. Roles created by assignments follow their source rows; roles the application inserted directly are the application's to delete | *doc* — see open question U1 |
| grant | last one on a table revoked | enforcement triggers (incl. TRUNCATE) removed | exists + extend |
| grant | revoked while another session is mid-statement | that statement finishes under its snapshot; next plan is rebuilt (`17` H4) | *doc* |
| assignment | `unassign()` | triggers, functions, row, cascade | exists; now requires bypass (`17` D13) |
| `letter.grants` / `roles` | direct DML | cache invalidated (exists); **no** trigger install/validation. Rule: manage through the API; `check_health` reports tables with grants but no triggers | *doc* + `check_health` |
| enforcement trigger | `ALTER TABLE … DISABLE TRIGGER` | owner-only; disables write enforcement. `check_health` reports | *doc* + `check_health` |
| extension | `DROP EXTENSION letter` | enforcement triggers depend on letter's functions via `pg_depend`: refused without `CASCADE`, dropped with it. **Verified 2026-09-22: the generated assignment functions and their triggers on user tables survive** (they are not extension members) and every write to a source table then errors → stop S1 | verify + test |
| partition / child | attach, inherit | child is unprotected unless granted (`17` §4) | *doc* |

### 3.2 What cascade must do, precisely

`sql_drop` handler (`letter.on_sql_drop()`, `LANGUAGE C` or plpgsql over
`pg_event_trigger_dropped_objects()`): for each dropped `table` OID *t*:
1. `DELETE FROM letter.grants WHERE on_table = t OR scope = t` (NOTICE per row).
2. For each assignment with `table_name = t OR scope_table = t`: drop its trigger
   functions (the source triggers went with the table if the source was dropped; drop
   them explicitly if only the scope was), delete the row (cascade → role_assignments
   → roles).
3. `DELETE FROM letter.roles WHERE scope_table = t`.
4. Revalidate every remaining grant whose path *could* pass through *t*; delete those
   that no longer validate (a hop is gone), NOTICE.

For each dropped `table column` (*t*, *c*): delete grants on (*t*, *c*); delete grants on
*t* whose `using_path` contains *c*; delete assignments on *t* using *c* as
`user_column`/`role_column`/scope FK.

The handler runs inside the dropping transaction, so a failure rolls the DROP back —
acceptable: it means letter's own tables are broken, which is worth stopping for.

---

## 4. Dump and restore — open

Found while writing this plan; not decided here. Today letter's tables are *not*
registered with `pg_extension_config_dump`, so `pg_dump` omits grants, roles and
assignments entirely. Registering them raises questions the OID change makes sharper:

- `regclass` columns dump as qualified names and re-resolve on restore — good — but only
  if the referenced tables exist first (they do: schema before data) and no dead OIDs
  remain (§3 guarantees this).
- Restoring user tables fires letter's triggers: enforcement triggers error with no
  user id → **restores must run as a role with `letter.bypass = on`** (`17` D13's
  deployment model); assignment triggers re-create roles that the roles dump *also*
  restores → duplicates. Either roles/role_assignments are not dumped (rebuilt from
  source rows by the assignment triggers — but then directly-inserted roles are lost),
  or assignment triggers are skipped under bypass (they aren't today), or restore order
  is pinned.
- The generated assignment trigger functions are ordinary objects in schema `letter`
  (not extension members): dumped and restored by name, referencing assignment ids that
  are also restored. Fine, provided ids are stable — they are.

**Open question R1 for Paul:** which of letter's tables are configuration (dump) and
which are derived (rebuild)? Proposed: dump `grants` and `assignments`; treat
`roles`/`role_assignments` as derived *unless* the application inserts roles directly,
in which case dump them too and make assignment triggers no-ops under `letter.bypass`.

---

## 5. Steps

Each ends green on `make installcheck`. Estimated total: about a day and a half.

### I1 — Schema and API on `regclass` *(½ day)* — ✅ DONE 2026-09-22, notes in §8
Extension script per §2; `grant`/`revoke`/`assign`/`unassign` signatures; the two info
functions; `CHECK (user_id <> '')`. C: resolve `regclass` → (schema, table) once at
each entry point and keep the name-based internals for now, but *store* OIDs.
Tests: existing suites' expected output; `grant_revoke` gains a mixed-case/spaces
table (works now) and keeps the missing-table case (now a `regclass` resolution error).

### I2 — Internals on OIDs *(½ day)* — ✅ DONE 2026-09-22, notes in §8
Caches and compiled-path keys by OID; protected set = OID hash (rewrite `17` H1's
`get_protected_set`/`relation_is_protected`; supersede D8); `build_barrier_sql` emits
`r.scope_table = <oid>`; assignment trigger functions embed OIDs; `check_grant` /
`row_has_any_select_grant` compare OIDs. Apply `17` D11 here (the `!has_scope` /
`scope_table IS NULL` change touches the same lines). Tests: `hook_infra` 5a becomes
"recreated table is unprotected"; `barrier_sql` golden text changes; D11 fixtures.

### I3 — Lifecycle *(½ day)* — ✅ DONE 2026-09-22 except the `DROP EXTENSION` row (stop S1 below), notes in §8
`sql_drop` cascade (§3.2), `ddl_command_end` revalidation, `BEFORE TRUNCATE` trigger
installed/removed with the others, `DROP EXTENSION` verification. Test:
`test/sql/lifecycle.sql` — one case per matrix row.

### I4 — `letter.check_health()` *(small)* — ✅ DONE 2026-09-22
Consolidates `11` 6.5.1 plus: preload status (`17` D12), roles with bypass defaults,
disabled letter triggers, protected tables with missing/extra triggers, paths without
usable indexes, roles with no assignment (informational). Returns `(severity, object,
message)` rows.

### I5 — Docs — ✅ DONE 2026-09-22 (README written; dump/restore section waits for R1)
`17`: D8 superseded, S5 closed, H1 note. `11`: Phase 6 ticked or pointed here; status.
README: identity model, lifecycle contract, deployment model, dump/restore once R1 is
decided.

---

## 6. Decisions

- **D1 — tables are identified by OID (`regclass`); columns by name.** *(Decided
  2026-09-22.)* Supersedes `17` D8.
- **D2 — drop cascades, alter refuses.** *(Decided 2026-09-22, per Paul's DDLX
  principle.)* Dropping an object removes dependent letter state with a NOTICE per row;
  altering an object so that letter state becomes invalid is refused.
- **D3 — `TRUNCATE` on a protected table requires `letter.bypass`.** *(Decided
  2026-09-22; found during the audit.)*
- **D4 — direct DML on `letter.grants`/`assignments` is unsupported;** the API is the
  interface. `check_health` reports the symptoms. *(Decided 2026-09-22.)*

- **D5 — generated assignment functions depend on `letter.assign()`.** *(Decided
  2026-09-22; resolves stop S1, option a.)* `assign()` records a normal `pg_depend`
  dependency from each `source_upsert_*` / `source_delete_*` / `scope_delete_*` function
  on `letter.assign()` itself, so `DROP EXTENSION` refuses without `CASCADE` and removes
  them (and their triggers) with it, while `pg_dump` still dumps them as ordinary objects.

Open: **R1** (dump/restore, §4); **U1** — does letter want a `letter.forget_user(user_id)`
that deletes every role row for a user id, as the one hook an application needs when it
deletes a user? *(Proposed: yes, trivial, and it documents the responsibility.)*

---

## 7. Stop-and-discuss triggers

1. `regclass` resolution on restore fails for any letter table in a plain
   `pg_dump | psql` round trip.
2. An event trigger cannot see what §3.2 needs (e.g. dropped-column reporting differs
   from expectation).
3. Cascade removes more than the matrix row says.
4. `DROP EXTENSION` leaves a dangling trigger or function.
5. Anything that would need an OID to be re-resolved from a name at run time.

---

## 0. Status — resume here

**2026-09-22: I1–I5 ✅ done; 15 regression tests green (twice).** D1–D5 decided; S1
resolved. Still open, neither blocking: **R1** (dump/restore — `pg_extension_config_dump`
is *not* yet called, so `pg_dump` omits letter's tables) and **U1**
(`letter.forget_user`). **Next: `17` H3** (substitution) with
`/implement-plan plan/17-planner-hook-implementation.md`.

### S1 — `DROP EXTENSION letter CASCADE` leaves the assignment machinery behind — ✅ RESOLVED 2026-09-22 → D5 (option a)
Measured in `lifecycle.sql` §9 (removed from the test until resolved): with one grant and
one assignment in place, `DROP EXTENSION letter CASCADE` drops the enforcement triggers
(they depend on letter's C functions) but **not** the generated `letter.source_upsert_*`
/ `source_delete_*` / `scope_delete_*` functions or their triggers on the source and
scope tables — they are ordinary objects in schema `letter`, not extension members.
Afterwards every INSERT/UPDATE/DELETE on a source table fails with *relation
"letter.role_assignments" does not exist*. Our `sql_drop` trigger cannot help: an event
trigger does not fire for the command that drops its own function (verified). Options:
- **(a)** In `assign()`, record a `pg_depend` **normal** dependency from each generated
  function on `letter.assign()` (`recordDependencyOn`, ~25 lines). `DROP EXTENSION`
  then refuses without `CASCADE` and removes them with it — exactly how the enforcement
  triggers already behave — and, being non-members, they are still dumped by `pg_dump`.
- **(b)** Make them extension members (`ALTER EXTENSION … ADD FUNCTION`): dropped with
  the extension, but then *not dumped* — a restore would have assignment rows with no
  functions. Interacts badly with R1.
- **(c)** A `letter.uninstall()` to run before `DROP EXTENSION`. Manual; easy to forget.
- *Claude's lean: (a).* It is the same mechanism PostgreSQL already applies to the
  enforcement triggers, and it keeps dump/restore untouched.
 Continue with `/implement-plan
plan/18-object-identity-and-lifecycle.md`.

---

## 8. Findings log

*(Append mid-implementation discoveries here, dated.)*

### 2026-09-22 — I1 schema and API on `regclass`

13 tests green (twice — the OID-bearing outputs are stable). Every test's expected
output changed; the changes were reviewed line by line and are only the intended ones.

- **API: unscoped = `NULL` scope.** A `regclass` parameter cannot take `''`, so
  `grant()`/`revoke()` take `scope regclass DEFAULT NULL`; NULL is stored as `0`.
  `revoke()` is therefore no longer `STRICT` (it checks its own required arguments).
  Forced by D1 rather than chosen, but it is user-visible API.
- **`17` D13 landed here** (`assign()`/`unassign()` require bypass): their signatures
  changed anyway, so every test calling them was touched once, not twice.
- **`hook_infra` 5a flipped in I1, not I2**: grants store the old table's OID, so the
  recreated table is unprotected as soon as the storage changes. The test now shows
  silent → re-grant → found.
- **OIDs in generated text are not stable across runs.** `build_barrier_sql` now emits
  `r.scope_table = <oid>` (§1.3). The golden-text test displays the SQL through a
  `show_sql()` helper that renders each OID as `<schema.table>`; the executable views
  use the raw text. Parity is unchanged (0/0 everywhere).
- **`regclass` column vs string literal.** `WHERE on_table = 'public.documents'` fails
  with *invalid input syntax for type oid*: with no `regclass = regclass` operator PG
  picks `oid = oid` and coerces the literal to `oid`. Hand queries against
  `letter.grants`/`roles` must write `'public.documents'::regclass`. Document this
  (README, I5); `list_grants()`/`user_permissions()` are unaffected.
- **`regclass` output is `search_path`-relative** (`projects`, not `public.projects`,
  in the tests). Cosmetic; `letter.read()` and the C internals render qualified names
  themselves.
- **The D10 check in `grant()` is now `regclass` resolution** ("relation … does not
  exist"); the explicit check survives only as `rel_qualified_name()`'s guard against a
  dead OID passed numerically.
- Internals are still name-keyed (`'schema.table'` strings rendered from OIDs at each
  entry point via `rel_qualified_name[_or_null]()`); rows whose OID no longer resolves
  are skipped by the cache loaders — that is the pre-I3 behaviour for dead rows. I2
  moves the keys to OIDs.

### 2026-09-22 — I2 internals on OIDs, `17` D11

13 tests green (twice). Nine suites' expected output did not change at all; the four
that did (`enforce_write`, `info`, `barrier_sql`, `hook_infra`) changed only for D11
and for one I1 slip, below.

- Cache structs hold `Oid on_table`, `Oid scope`, `Oid scope_table`; rows whose OID no
  longer resolves are skipped at load. Compiled scope paths are keyed `relid|scope|path`
  and derive names at compile time (a rename invalidates the relcache → flush →
  recompile). The protected set is an OID hash; `relation_is_protected` is one
  `hash_search`. `check_grant`/`row_has_any_select_grant` are now thin loops over a
  shared `grant_applies()` + `holds_role()`; the triggers pass `RelationGetRelid(rel)`,
  `letter.read()` resolves its name argument once with `RangeVarGetRelid`.
- **D11 in three places**: `holds_role()` for unscoped grants requires a role row with
  no scope; the generator's unscoped test gains `AND r.scope_table IS NULL`;
  `user_permissions()` likewise. Tests: `enforce_write` Test 7 (scoped `editor` denied
  by an unscoped insert grant until given the global role), `barrier_sql` user `erin`
  (auditor scoped to a project sees nothing through the unscoped grants), `info`
  (Alice's and Bob's scoped roles no longer list the unscoped grants).
- **I1 review slip, corrected here.** `hook_infra` 5a's I1 expected output showed the
  recreated table still detected ("silent" comment, DEBUG line beneath). Cause: the
  protected set is not invalidated by DDL, and in I1 it held the *name*, rendered when
  the set was built before the drop. With OID keys the stale entry is the dead OID and
  matches nothing; a grant on the new table invalidates the set. So "not invalidated by
  DDL" is correct by construction now — a new table cannot enter the set without a
  grant, and grants invalidate it.

### 2026-09-22 — I3 lifecycle (`letter.c`, `sql/letter--0.1.sql`, `test/sql/lifecycle.sql`)

14 tests green (twice). Every existing suite's expected output gained cascade NOTICEs in
its cleanup section and the fourth (TRUNCATE) enforcement trigger; `walker_cache`
Test 4 was rewritten (its premise — drop an FK on a path, then enforce — is now refused
at the DDL). Built: `letter.enforce_truncate()` (D3); `letter.on_sql_drop()` and
`letter.on_ddl_command_end()` (C event-trigger functions) with the two event triggers;
`revalidate_all()`, `remove_assignment()` (also used by `unassign()`), and
`try_in_subxact()`.

- **Cascade vs refuse is decided by what was dropped, not by the command.** `sql_drop`
  fires before `ddl_command_end` for the same statement, so an `ALTER TABLE … CASCADE`
  that drops an FK on a path would have had its broken grants *removed* by `sql_drop`
  before `ddl_command_end` could refuse it (found by `lifecycle` §2). Rule now: a
  dropped **table or column** → cascade (remove with NOTICE, then revalidate-and-remove
  the rest); an **index-only** drop (`DROP INDEX`, or a constraint's index under ALTER)
  → refuse-mode revalidation plus the grant-time FK-index warning; anything else under
  `ALTER TABLE` → `ddl_command_end` refuses. Both handlers re-enter-guard themselves.
- **Snapshots.** Read-only SPI inside an event trigger sees the snapshot from *before*
  the command's own catalog changes: the handlers call `CommandCounterIncrement()` and
  push a fresh snapshot, and their own loads of `letter.*` are not read-only so they see
  the handler's own deletes (otherwise a grant was "removed" twice).
- **`SPI_processed`/`SPI_tuptable` are clobbered by nested SPI.** `revalidate_all`
  originally iterated the result set while the validators ran their own queries —
  only the first row was ever checked. Rows are copied out first now (the drop handler
  already did).
- **NOTICE granularity:** one summary line per dropped table/column
  (`removed N grant(s), M assignment(s), K role(s)`) plus one line per grant or
  assignment removed by revalidation, naming the reason — rather than §3's "per row",
  which would be noisy for a table with many grants.
- **`DROP INDEX` warnings** cannot come from `ddl_command_end` (`pg_event_trigger_ddl_
  commands()` does not report drops) — they come from `sql_drop`, only when no table
  went with the index (a table drop takes its own indexes and should not re-warn for
  unrelated grants).
- **`pg_event_trigger_dropped_objects()`**: a dropped column is `table column` with
  `objid` = table, `objsubid` = attnum and the raw names in `address_names`; a table's
  drop also lists its type, constraints, indexes and RI triggers.
- Matrix rows not covered by `lifecycle.sql`: scope-row PK update (needs `ON UPDATE
  CASCADE` on the FK; documented), `DROP EXTENSION` (S1), partitions (doc).
- Incidental: the `letter` schema survives `DROP EXTENSION … CASCADE` in the test
  database (count 1 afterwards) — expected while the orphaned functions live in it;
  re-check once S1 is resolved.

### 2026-09-22 — I4 `check_health()`, I5 docs

- `letter.check_health()` is SQL over the catalogues plus `letter._problems()` (C):
  the latter runs the same revalidation as the event triggers in a *report* mode and
  captures the FK-index warning as rows (`health_sink`). Severities: `error` (enforcement
  is not what the catalogue says), `warning` (works, not as intended), `info`. Covers
  `11` 6.5.1 plus preload status, `enforce_reads`, roles with a bypass default, disabled
  letter triggers, stale triggers, directly-managed roles. Test: `check_health.sql`
  (ids normalised). In the test environment the library is not preloaded, so that
  warning is always present — a useful reminder for `17` D12.
- D5 landed (`depend_on_assign()` in `assign()`; `lifecycle.sql` §9 back in): after
  `DROP EXTENSION letter CASCADE` there are 0 letter triggers, 0 functions in schema
  `letter`, and writes to a former source table work. `DROP EXTENSION` without CASCADE is
  refused, as for the enforcement triggers.
- README written from scratch (it was a title): install and preload, the API, the
  deployment model (`17` D13), identity and lifecycle (this doc), `check_health`,
  known gaps. Dump/restore is stated as open pending R1.

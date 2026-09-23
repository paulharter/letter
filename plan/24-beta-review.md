# Letter — Beta review: what three independent reviews found

End of 2026-09-23, after the first beta was committed (`01f193c`). Three reviews were
run over the whole codebase — security, consistency, small features — and their
findings are merged and ranked here. Items marked **[verified]** were reproduced by a
reviewer against the installed build in a scratch database; the rest were verified by
reading. Nothing has been changed yet: this is the work list, for Paul's pass.

---

## A. Must fix before anyone deploys the beta

**A1. Stored `if` expressions run as the extension owner in the write path.**
`if_holds()` executes the prepared `if` plan inside `guard_enter`, which switches the
session to the extension owner (a superuser). The barrier evaluates the same `if` as
the invoker. So on every write to a protected table, any function an `if` names runs
as superuser — and the grant-time validation (IMMUTABLE, pg_catalog, `letter.user_id()`)
is not re-run, so a function replaced later by its owner runs with whatever body it
now has. `if_prepare` also resolves names under the caller's `search_path`, which the
application role controls. The generated `_rule_*` functions do this right (pinned
`search_path`, qualified text). **Fix:** evaluate the `if` plan as the invoker — bump
`letter_guard_depth` without the uid switch — matching the read path; the plan reads a
composite parameter and needs no privileged table access. Optionally also pin
`search_path = pg_catalog` and embed the qualified text (`deparse_if_as(qualify)`), as
the rule functions do. Test: an `if` naming a function owned by a non-superuser, whose
body is then replaced to call `current_user`/`require_superuser`-guarded work.

**A2. Cross-backend membership invalidation is dead. [verified]**
`letter_cache_inval()` compares the trigger's relation name to `"roles"` and looks up a
signal table named `"roles_epoch"`; both were renamed in plan 20 (`memberships`,
`_membership_signal`). A membership added or removed in one backend is invisible to
the write triggers (and `letter._read()`, `holds_role`) of every other backend that has
already cached that user, until a grants write or a full relcache flush. Reproduced:
a revoked membership kept authorising inserts in another session. Reads are
unaffected (the barrier reads memberships live). `hook_cache.sql` §3 meant to test
this but never warms the remote cache. **Fix:** compare to `"memberships"`, look up
`"_membership_signal"`; make hook_cache §3 do an INSERT as bob before the remote
change. Then grep for every other leftover of the rename (see D).

**A3. `letter._read()` is callable by the application role and runs a raw SQL condition
as the extension owner.** It interpolates its `condition` argument verbatim and runs
under the guard — no hook, owner privileges — and the SQL script never revokes EXECUTE
from PUBLIC (nothing in the script is revoked). An app role can read any table through
a correlated subquery in the condition. **Fix:** `REVOKE EXECUTE ON FUNCTION letter._read
FROM PUBLIC` in the script (and on `read_policy`, `write_policy`, `_problems` while at
it — they disclose configuration, not data, but the app has no business with them);
the stories fixture's `REVOKE ALL ON ALL TABLES` should become a story-10 test that
the app cannot call `_read`.

**A4. `ON CONFLICT DO UPDATE` reaches rows a plain `UPDATE` cannot see. [verified]**
The row-visibility qual (plan 19 D1) is added only for `CMD_UPDATE`/`CMD_DELETE`; an
INSERT's ON CONFLICT path has none, so with a scoped select and a global update grant an
upsert rewrote a hidden row that `UPDATE … WHERE` skipped. The trigger still checks
writability, so it is not a bypass of write grants, but it contradicts the README's
"rows the user cannot see are not there for UPDATE". **Fix:** AND the row qual into
`onConflictWhere` in `write_mutator` (the arbiter must stay raw, as fixed in P4).
Decide: silently skip (consistent with D1) or refuse loudly (the conflicting row is
revealed by the unique violation anyway).

## B. Should fix for the beta

**B1. Renaming a rule's FK or PK column is allowed and breaks the rule. [verified]**
`validate_assignment_row` checks `user_column`, `role_column` and the `if`, but the
generated functions bake the scope FK and PK names, which are not stored. `RENAME
COLUMN project_id TO proj_id` succeeds; the next insert fails with `record "new" has
no field "project_id"`; `check_health()` says nothing. **Fix:** store `scope_column`
and `pk_column` in `membership_rules` and validate them by name (refuse the rename,
like a grant's column).

**B2. `grant_*` validates neither the privilege name nor the columns. [verified]**
`grant_global('slect', …)` is stored and never enforced; a nonexistent column is
accepted and then breaks the next unrelated `ALTER TABLE` with "column … *no longer*
exists". **Fix:** reject unknown privileges in C and `CHECK (privilege IN (…))` on the
table; `column_exists` per column at grant time.

**B3. `DROP FUNCTION` / `ALTER FUNCTION` under an `if` is neither refused nor cascaded.
[verified]** After `DROP FUNCTION is_ok`, reads of the table fail with a bare
"function is_ok(text) does not exist" (fail-closed, wrong voice); `check_health()` does
report it. **Fix:** `'function'` in the `sql_drop` filter (cascade with NOTICE) and
`ALTER FUNCTION` in the `ddl_command_end` tags (refuse a volatility change).

**B4. Silent caps: 256 memberships, 1024 grants per user.** The SPI reads are
truncated; a user over the cap is denied writes the barrier permits. **Fix:** error
when the cap is hit, or allocate dynamically.

**B5. `FROM ONLY` is ignored. [verified]** The barrier renders `FROM schema.table b`
whatever the original RTE's `inh`; `SELECT … FROM ONLY parent` returned a child's row.
**Fix:** render `FROM ONLY` when `inh` was false.

**B6. `assign`/`unassign` interpolate role, column and user_column unquoted.**
Superuser-only, so not an unprivileged injection, but a role with a quote breaks, or
injects into a SECURITY DEFINER body. **Fix:** `quote_identifier` / `quote_literal_cstr`
(the `if` text already is).

**B7. `user_from_claims()` in token mode sets a GUC that enforcement ignores** — silently
ineffective. **Fix:** error ("letter.identity is token: use letter.login()").

**B8. `forget_user()` is plain plpgsql, not SECURITY DEFINER**, so the application role
the README names as its caller cannot run it. Either make it SECURITY DEFINER for the
current user only, or document it as the admin's.

## C. Error voice and README

- `require_bypass`'s message lacks the `letter: ` prefix; several configuration errors
  are `elog(ERROR)` (SQLSTATE XX000) rather than `ereport` with a proper code.
- `grant_scoped` / `revoke_scoped` are plpgsql and add a `CONTEXT:` line to every
  grant-time error. Move the NULL-scope check into `_grant`/`_revoke`, make the wrappers
  `LANGUAGE sql`.
- Key-configuration failures are reported as "token rejected: letter.jwt_keys: …"
  (28000) and `check_health()` copies the wording though nothing was rejected.
- README: `user_from_claims` has a second parameter (`setting`); `write_policy` and
  `logout()` missing from the API block; an `anyone` *insert* grant also serves
  anonymous writes (README says select only); `revoke_scoped` has no `columns` default
  so a scoped insert/delete needs `ARRAY['*']`; dropping a scope table's PK is not
  refused (reads then fail at plan time); TRUNCATE is refused on every non-exempt
  table, not only protected ones; `letter.control` still says "role-based";
  event-trigger cascades run as the DDL caller, so a non-superuser table owner's
  `DROP TABLE` fails on letter's tables — undocumented.

## D. Dead code and leftover names

`letter_role_cleanup`, `roles_epoch_oid`/`letter_roles_epoch_oid` (A2), `LETTER_PRIV_SET`,
`check_fn`, `if_fn`/`role_name_arg`, `should_bypass()`; comments naming `letter.read()`,
`letter.grant()`, `role_assignments`/`roles`, `'set'`; SQL index names
`roles_user_id_idx`/`roles_role_idx`; **user-facing** `check_health()` object strings
still say `assignment …`, `role … of …`, `roles`; `test/sql/schema.sql` says
`roles_epoch`; the dead "grants may be declared before their tables" branch in
`validate_scope_path`; `_grant` and siblings are not STRICT yet `PG_GETARG` NULLs.

## E. JWT verifier: minor spec gaps

`crit` header ignored (RFC 7515: reject unknown `crit`); base64url decoder accepts
trailing garbage after `=` and a truncated final quantum; `exp`/`nbf` as double (past
2^53 precision); an embedded NUL in the claim is truncated by `set_config_option`.
Confirmed handled: HMAC and `none` refused, key type must match the algorithm, ECDSA
length and curve checks, exact `kid` match, three-segment structure.

## F. Test gaps (promises with no test)

Invalid privilege; nonexistent column at grant time; a warm cache across backends (A2);
ON CONFLICT on a hidden row (A4); renaming a rule's FK/PK column (B1); >256 memberships
(B4); `FROM ONLY` (B5); DROP/ALTER FUNCTION under an `if` (B3); `user_from_claims` in
token mode (B7); `forget_user` from the app role (B8); `login()` in the default mode; the
app calling `_read` (A3).

## G. Small additions worth having (ranked by value/cost)

1. `list_grants(role, on_table)` filter and `list_rules()` — hours.
2. `my_memberships()` for the current user, with sources (SECURITY DEFINER) — half a day.
3. `writable_columns(rel, pk)` and a batch `visible_columns(rel, pk[])` — a day.
4. Denial errors that name what would have allowed ("granted to: editor in
   public.projects, if …") — hours; the biggest debugging win.
5. `grant_*`/`revoke_*` return a count and NOTICE on a no-op revoke — hours.
6. `add_member`/`remove_member` with validation; `check_health()` lines for a role
   nobody grants and a granted role nobody holds — half a day.
7. `rename_column(rel, old, new)` doing the revoke/rename/grant dance (refuse when an
   `if` names it) — a day.
8. `copy_grants(from, to)` for partitions and LIKE tables — hours.
9. Exposure warnings for `anyone` grants and `any_user` with `'*'`, and a health line
   listing anyone-readable tables — hours.
10. `letter.version()` and `resolve_path(rel, scope, via)` (the inferred hop, before
    committing) — hours.

---

## 0. Status — resume here

**2026-09-23: DRAFTED from the reviews.** Proposed order: A1–A4 (each with a
regression test), then B1–B3, then D as one sweep (the rename leftovers), then C,
then G4/G5/G1 as the cheap wins; B4–B8, E and the rest of G as Paul chooses.

**2026-09-23 (later): Paul: "do all the fixes A–F; on B4 dynamic allocation."
DONE, except the two rulings below.** 19 C tests and 72 story tests green on PG 16.15
and 17.9. Uncommitted.

Done, with tests:
- **A1** `if_prepare`/`if_holds` bump `letter_guard_depth` only, no uid switch: the
  `if` runs as the writer (enforce_write Test 15). search_path is NOT pinned — see
  the findings below.
- **A2** `letter_cache_inval` compares `"memberships"` and signals
  `_membership_signal`; the signal OID is resolved lazily on BOTH ends
  (`membership_signal_oid()`, called from `populate_cache`), since the receiving
  backend never wrote memberships and had no OID to compare against — a second
  bug behind the first. hook_cache §3 warms bob's cache through a refused INSERT
  (an insert grant on the table is needed for that: the D14 gate is before the
  trigger), then checks both directions: a membership added elsewhere allows, one
  removed elsewhere refuses while the row stays visible as viewer.
- **A3** `REVOKE EXECUTE … FROM PUBLIC` on `_read`, `read_policy`, `write_policy`,
  `_problems` in the script; story 10 `test_the_walker_oracle_is_not_the_apps`.
- **B1** `membership_rules.pk_column` (NOT NULL) and `scope_column`; `assign` looks
  the keys up before inserting the rule and stores them; `validate_assignment_row`
  checks both by name and that the FK to the scope is still that column
  (lifecycle §2).
- **B2** `_grant` rejects a privilege that is not one of the five (`privilege_bit`)
  and a column that does not exist (`column_exists`), before SPI; `CHECK (privilege
  IN (…))` on the table (grant_revoke). Found `test/sql/info.sql` granting a
  `status` column its `projects` table did not have — fixture fixed.
- **B3** `sql_drop` also takes `function` objects outside schema letter (so
  unassign's own DROP FUNCTION is not a cascade) → REVALIDATE_REMOVE; the
  ddl_command_end trigger's tags gain `ALTER FUNCTION` → refuse (lifecycle §2b:
  STABLE refused, RENAME refused, DROP cascades a grant and a rule).
- **B4** (Paul: dynamic) `LetterRole`/`LetterGrant` hold `char *` strings and the
  cache holds `palloc`'d arrays sized to `SPI_processed`, all in
  `letter_cache_cxt`; tcount 0; the fixed `role[64]`/`scope_id[256]`/`via[512]`
  buffers (and their silent `strlcpy` truncation) are gone with the caps
  (enforce_write Test 14: membership 300, grant 1100).
- **B5** `HookTarget.inh`; `build_barrier_sql(relid, from_only)` renders `FROM ONLY`
  in the subquery form (hook_read §11, with an inheritance child).
- **B6** `assign`/`unassign` quote every identifier and literal they interpolate
  (assign.sql "Odd Members", roles `it's` and `o'brien`).
- **B7** `user_from_claims()` raises 28000 in token mode (token §6).
- **C** `require_bypass` has the prefix; user-reachable `elog(ERROR)`s in
  assign/unassign/validate_scope_path are `ereport` with codes; `grant_scoped`/
  `revoke_scoped` are inlined SQL — the NULL-scope check moved into C behind a new
  trailing `scoped boolean DEFAULT false` on `_grant`/`_revoke` (the CONTEXT lines
  are gone from enforce_write.out); key-configuration failures are
  `letter: letter.jwt_keys: …` (22023, `keys_reject`) with the bare reason in
  errdetail, which `_jwt_keys_check` returns as `does not parse: …`; `letter.control`
  says relationship-based; README: `user_from_claims` signature, `write_policy` and
  `logout()` in the API block, anyone insert grants, `revoke_scoped`'s `ARRAY['*']`,
  scope-table PK drop, TRUNCATE on every table, DDL cascades as the caller, plus
  A1/A3/B1/B2/B3 in Concepts, Deployment model and Lifecycle.
- **D** every leftover listed: `letter_membership_cleanup`, `membership_signal_oid`,
  `LETTER_PRIV_FILL`, `if_expr`/`role_arg`, `should_bypass()` inlined, comments,
  `memberships_*_idx`, check_health says `rule …`, `membership … of …`,
  `memberships`; C messages say "membership rule"/"rule(s)"/"membership(s)";
  `schema.sql`; the dead branch and `table_exists` removed; `_grant`/`_revoke`/
  `_assign`/`_unassign` check their required arguments (grant_revoke).
- **E** `crit` present → rejected; base64url refuses anything after `=` and a
  one-character final quantum ("not.a.token" now fails there, before the JSON);
  `exp`/`nbf` compared as numeric (`numeric_cmp_int64`); a NUL inside any string
  field is rejected.
- **F** all of the list except A4's and B8's tests, which wait on the rulings;
  "login() in the default mode" is token §1 (enforcement follows the setting
  login() made, and the application may still change it there).

**Rulings:**
- **A4 (Paul, 2026-09-23): refuse loudly.** DONE: the planner hook prepends
  `(<row qual>) OR letter._hidden_conflict(<oid>)` to the ON CONFLICT WHERE of an
  INSERT … ON CONFLICT DO UPDATE on a protected table; the C function raises 42501
  "conflicts with a row the user cannot see". DO NOTHING is untouched (it reveals
  nothing). hook_write §5; README "Writes".
- **B8 (Paul, 2026-09-23): a declared users table** — "a cheap way to enforce better
  hygiene for the most common case". DONE: `letter.users(rel)` records the table and
  its single-column key in `letter.user_tables` (dumped) and installs
  `letter_users_forget`, an AFTER DELETE OR UPDATE row trigger (`_users_forget`, C)
  that forgets the old key when it is gone or changed — through `letter._forget_user`,
  the old API function demoted to plumbing — with letter's authority, so the
  application's own delete forgets too, and regardless of bypass. `letter.unusers(rel)`
  undeclares. Several tables may be declared. Revalidation refuses renaming the key
  column, drop cascades the declaration; check_health reports a dead OID, a missing
  trigger and a stray trigger. lifecycle §7b, check_health §2, story 4 (offboarding is
  `DELETE FROM users`; app_rules.sql declares the table), README Concepts/API/
  Lifecycle/Backup. Naming (`users`/`unusers`) is mine — rename at will.

**Incidental findings:**
- ~~An `if`'s function names are resolved under the caller's search_path at use
  time~~ — **RULED (Paul, 2026-09-23): fix it. DONE.** Wider than the `if`: the
  barrier and the write path's tests were parsed under the application's
  search_path too, where `pg_temp` (or any schema the app can create in) could
  shadow an unqualified function or even an operator. Now: `pin_search_path()`
  (search_path = pg_catalog, GUC_ACTION_SAVE) around every generation and parse of
  letter's SQL — `convert_rte_in_place`, `redact_write_target`, `read_policy`,
  `write_policy`, `visible_columns`, `if_prepare` — and every stored `if` is
  canonical: `canonical_if()` resolves the author's text in the author's search_path
  at grant/assign time and stores it deparsed with every non-pg_catalog name
  qualified (row form unprefixed, since the row's alias follows the table's name;
  transition form `old.`/`new.`, deparsed through a bare PlannedStmt shell the way
  EXPLAIN builds its context — no planning, so nothing is inlined). Revalidation
  parses the stored form under the pin. `list_grants()` shows the canonical text.
  hook_read §12: a schema first in search_path and `pg_temp`, each with its own
  `is_ok()` and its own `=` for uuid, change nothing on either path. Pre-existing
  and left: an `if` that passes the whole row (`is_public(notes)`) names the table
  and does not survive a rename of it.
- ~~`CREATE OR REPLACE FUNCTION` not revalidated~~ — DONE (Paul, 2026-09-23): the
  ddl_command_end trigger also fires on `CREATE FUNCTION`; the handler skips when
  every created object is in schema letter (assign's own rule functions), else
  revalidates. lifecycle §2b.
- ~~Both forms' failures reported~~ — DONE: `if_invalid()` reports one reason: the
  transition form's when the row form complained that old or new is missing, the row
  form's otherwise. enforce_write §12, lifecycle §2b.
- ~~A scope table may lose its primary key without refusal~~ — DONE:
  `reject_composite_pk` refuses no key as well as a composite one, at grant time and
  on revalidation (lifecycle §2, grant_revoke). README Lifecycle updated.
- ~~Dropping a scope table leaves the enforcement triggers on the tables whose grants
  were scoped to it~~ — FIXED (Paul, 2026-09-23): `cascade_dropped_table` deletes with
  `RETURNING on_table` and calls `maybe_remove_enforcement_triggers` for each other
  table; lifecycle §7's state no longer lists team_members' four triggers.

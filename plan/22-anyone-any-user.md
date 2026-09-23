# Letter — Built-in roles: `anyone` and `any_user`

Drafted 2026-09-23 from plan `21` finding 5 (sign-up is a privileged step) and Paul's
DDLX design. Two roles that need no membership: `any_user` is any session with a user
set, `anyone` is any session at all. They let a relationship model express its own
first step — a user inserting the row that brings them into existence — and public
tables, without a privileged process.

Decisions already taken (Paul, 2026-09-23): the names are lowercase, to match the
rest of the API; an unset user stays an error everywhere except on a table that
grants `anyone` something.

---

## 1. Semantics

| Role | Holds it | Test in the barrier | Membership row |
|---|---|---|---|
| `any_user` | every session with `letter.user_id` set | `letter.user_id() IS NOT NULL` | none |
| `anyone` | every session, user set or not | `TRUE` | none |

- **Global scope only.** `grant_scoped` refuses either name: a scope is a relationship,
  and these roles have none. `grant_global` accepts them like any role; the rule's
  `if` applies as usual (`if := 'id = letter.user_id()::uuid'` is sign-up).
- **Reserved.** `letter.memberships.role` gets `CHECK (role NOT IN ('anyone',
  'any_user'))`; `assign` refuses them as `role` (a rule cannot confer what everyone
  holds); `revoke_*` works as for any role.
- **The unset user.** Today every protected read and write errors when
  `letter.user_id` is unset (`17` D2 as amended) — the guard against a request that
  forgot to set it. That stays, with one exception: **a table with at least one
  `anyone` grant serves an anonymous session its anonymous view** — the rows and
  columns the `anyone` rules give, nothing else. On such a table the membership tests
  read the user through `letter.user_id()` (NULL when unset, so they match nothing)
  instead of `letter._user_id()` (which errors). Every other table keeps
  `letter._user_id()`. A statement touching two tables, one with an `anyone` grant
  and one without, errors — the unset user is still a mistake on the second.
- **Writes with no user.** The triggers today error before looking at grants. With
  `anyone` rules on the table they check those rules only (`holds_role` is true for
  `anyone`, false for everything else when the user is unset); no applicable rule →
  the same error as today. `any_user` rules need the user set, like any other.
- **`visible_columns()`** and `letter._read()` follow the triggers' `holds_role`.
- **Precedence** — none: rules are a permissive set (`17` D15). An `anyone` select
  rule and an `editor` rule on one table are two groups in the barrier, the `anyone`
  group's row test `TRUE`; the generator's branch machinery (`17` D17) makes its branch
  `SELECT … WHERE TRUE` and excludes it from the later ones.
- **Performance.** An `anyone` select rule makes the whole table visible to everyone
  (its columns); the planner sees a plain scan for that branch, which is what was asked.

## 2. Changes

- `sql/letter--0.1.sql`: the CHECK on `memberships.role`.
- `letter.c`:
  - `letter_grant`: refuse `anyone`/`any_user` with a scope; `letter_assign`: refuse
    them as `role`.
  - Generator: in `barrier_append_test`, a group whose roles include `anyone` renders
    `TRUE`; one including `any_user` renders `(letter.user_id() IS NOT NULL OR <the
    membership test for the other roles>)`; the other roles' membership test as now.
    The user function per table: `letter.user_id()` when the table has an `anyone`
    grant, else `letter._user_id()` (`BARRIER_USER_ID` becomes a per-generation
    choice). Column tests likewise.
  - Triggers: `holds_role()` — `anyone` → true; `any_user` → user set; the "user_id is
    not set" errors in the three triggers move after the grant check, raised only when
    no `anyone` rule applied.
  - `get_current_user_id()` callers that assume non-NULL: audit.
- Tests (`test/sql`): `grant_revoke` (refusals: scoped, as an assign role, as a
  membership row); `barrier_sql` fixture 11 (golden text with `anyone` + a scoped
  role, and with `any_user`; parity with `visible_columns()`; the anonymous view);
  `hook_read` (an anonymous session reads a public table, errors on another table,
  errors on a join of both; `any_user` sees the table without any membership);
  `enforce_write` (sign-up: an `any_user` insert with `if := 'id = letter.user_id()
  ::uuid'`, refused for another id; an `anyone` insert with no user set; an update by
  an anonymous session refused where only `any_user` rules exist).
- Stories: story 3 signs Dave up as the application (`FINDINGS.md` #5 closed);
  `app_rules.sql` grants `any_user` the insert on `users` and the select on
  `users(id, name)` (the `users` → `user` rule can go, or stay as the example of a
  global rule). README: the two roles in "Concepts" and the API block; the deployment
  model paragraph on the two privileged writes loses sign-up.

## 3. Steps

- [x] **A1** — Schema CHECK, grant/assign refusals, tests in `grant_revoke.sql` *(2026-09-23)*.
- [x] **A2** — Generator: the two tests, the per-table user function; `barrier_sql`
  fixture 11; `hook_read` case 9 *(2026-09-23)*.
- [x] **A3** — Triggers, `holds_role`, the unset-user error moved; `enforce_write`
  test 13; `visible_columns()`/`_read()` parity in fixture 11 *(2026-09-23)*.
- [x] **A4** — Story 3 and `app_rules.sql`; README; `FINDINGS.md` #5; PG16 run *(2026-09-23)*.

## 4. Decisions

- **D1 — names `anyone`, `any_user`** *(Paul, 2026-09-23)*.
- **D2 — an unset user stays an error**, except on a table with an `anyone` grant,
  which serves the anonymous view *(Paul, 2026-09-23)*.
- **D3 — global only; reserved in memberships and assign** *(implemented as proposed, A1)*.

## 5. Stop-and-discuss triggers

1. A place where the unset user must be decided at plan time rather than run time
   (cached plans across sessions with and without a user).
2. The anonymous view of a table leaking through a join to a table without an
   `anyone` grant (the join must error, not filter).
3. Anything that makes `anyone` behave differently in the barrier and in the triggers.

---

## 0. Status — resume here

**2026-09-23: COMPLETE — A1–A4.** Landed: CHECKs on `memberships.role` and
`membership_rules.role`; `grant_scoped` and `assign` refuse the two names; the barrier
renders `anyone` as `TRUE` and `any_user` as `<user_fn> IS NOT NULL` (OR-ed with the
membership test of the group's other roles), and reads the user through
`letter.user_id()` on a table with an `anyone` select grant, `letter._user_id()`
elsewhere; the triggers' cache holds `anyone` always and `any_user` when a user is
set, `holds_role` answers for both, the "user_id is not set" error is raised only when
no rule applied (`write_denied`); the walker serves an anonymous session on a table
with an `anyone` select grant. Tests: grant_revoke (refusals), barrier_sql fixture 11
(golden text, three sessions incl. anonymous, parity with `visible_columns()` and
`_read()`), hook_read 9, enforce_write 13 (sign-up, guestbook). Story 3 signs Dave up
as himself; the story app's `users → user` rule is gone, replaced by `any_user`.
README: the two roles in Concepts and the deployment model. 18 C tests green on PG
16 and 17; 35 story tests green. Next: plan `21` findings 6–9, then P4.

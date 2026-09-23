# Letter — User Stories: a black-box suite

Drafted 2026-09-23, for the first beta. The regression suite (`test/sql`, pg_regress)
is white-box: it proves the machinery does what plans `15`–`20` say — golden barrier
text, parity oracles, fail-closed shapes, cache invalidation. It never touches the
surface an application uses: a driver, a pool, a request cycle, a migration, a dump.
This suite does only that. It answers one question per story: *can someone build this
on letter, and what happens when they try?*

What it is **not**: a second correctness suite. Redaction semantics and plan shape stay
under pg_regress; a story never asserts on generated SQL, never reads `letter._*`,
never calls `letter._read()`. When a story and a plan disagree, the plan is read and
the disagreement is a finding (S-item), not a test to patch.

---

## 1. Shape

- **Tooling.** Python 3, `pytest`, `psycopg` 3 (`psycopg[binary]`), `psycopg_pool`, in a
  virtualenv under `stories/.venv` (none of these are installed on the dev machine
  today — `stories/requirements.txt`, `make stories` creates the venv on first run).
  Not part of `make installcheck`; CI runs the C suite first, then `make stories`.
- **Layout.**
  ```
  stories/
    conftest.py          # database per module, roles, connections, as_user()
    requirements.txt
    test_01_request_cycle.py … test_10_cannot.py
    schema/              # the story application's DDL, one file per story where needed
  ```
- **Connection and deployment model — the tests use the real one.** A session fixture,
  connecting as a superuser from `LETTER_TEST_DSN` (default `dbname=postgres`), creates
  one database per module (`letter_story_<nn>`), `CREATE EXTENSION letter`, and:
  ```sql
  ALTER DATABASE letter_story_nn SET session_preload_libraries = 'letter';
  CREATE ROLE story_app   LOGIN PASSWORD '…';                       -- the application
  CREATE ROLE story_admin LOGIN PASSWORD '…';  ALTER ROLE story_admin SET letter.bypass = on;
  REVOKE ALL ON ALL TABLES IN SCHEMA letter FROM story_app;         -- README "Default deny"
  ```
  Application connections are `story_app` — **never a superuser** — so a story that
  quietly needs more than the app role has is itself a finding. Migrations, seeding
  and assertions about ground truth use `story_admin`. The database is dropped at the
  end of the module unless `LETTER_STORY_KEEP=1`.
- **Helpers** (`conftest.py`): `as_user(conn, user_id)` — a context manager that does
  `SET letter.user_id` and `RESET` in `finally`, the way a request handler would;
  `request(pool, user_id, fn)` — borrow a pooled connection, run `fn` as the user,
  return it; `truth(sql)` — the same query through `story_admin`, for ground truth.
- **Assertions are about outcomes** — rows returned, NULLs, exceptions with their
  SQLSTATE and the `letter:` prefix, counts against `truth()`. No timing assertions
  (they go flaky); story 9 records durations to the log only.
- **Every story ends by appending to `stories/FINDINGS.md`** what it found the API
  could not express, or needed `story_admin` for. That file is the source of the
  README's "Known gaps" at beta.

## 2. The ten stories

Ordered by consequence: the first two are the security perimeter, then building an
application, then operating one, then the negative catalogue.

### 1. The request cycle on a pooled connection
*As a web app, I set the user once per request on a connection I do not own.*
`psycopg_pool.ConnectionPool(min_size=2)` against `story_app`. Alice's request reads
her projects; the connection goes back; Bob's request on the same physical connection
reads his. Asserts: no row of Alice's is visible to Bob and vice versa (against
`truth()`); a request that raises *before* setting the user leaves the next request
erroring with "letter.user_id is not set" rather than inheriting a user; `SET LOCAL`
inside a transaction is enough and is gone after `COMMIT`/`ROLLBACK`; a connection
that never calls a letter function is still enforced (`session_preload_libraries`
does its job — the first statement on a fresh connection is a plain `SELECT`);
`pool.check()` / reset on return does not clear a user set with `ALTER ROLE` (admin).
pgbouncer transaction mode is not installed here: the story documents the recipe
(`SET LOCAL` per transaction, never `SET`) and D4 leaves it untested.

### 2. Auto-prepared statements across users
*As a driver, I prepare the same statement after five executions and reuse it.*
One connection, `prepare_threshold=5` (psycopg's default): run the same `SELECT` six
times as Alice, switch user, run it as Bob — the seventh execution is the prepared,
generic plan. Asserts Bob's rows. Repeat with `prepare_threshold=0`, with
`plan_cache_mode = force_generic_plan`, and with a grant added *between* executions
from `story_admin` on another connection (the plan must be invalidated). Then the
same through a PL/pgSQL function called from Python. This is `17` H5.4/5.5 through a
real driver rather than `PREPARE`.

### 3. Sign-up to first project
*As a new user, I join an org, get a project, and see only mine.*
The story application's schema (`schema/app.sql`: users, orgs, projects, tasks,
comments, team_members, org_members) and its membership rules
(`assign('team_members', 'user_id', role_column := 'role', scope := 'projects')`,
`assign('org_members', 'user_id', role := 'org_member', scope := 'orgs')`) and grants.
Carol signs up (insert as `story_app`? — finding expected: who inserts the user row),
is added to a project as editor, reads her project's tasks and not the neighbouring
project's, `visible_columns()` drives which fields the UI renders, and a plain
`SELECT * FROM projects` returns what the UI would show. Asserts against `truth()`.

### 4. Invite, promote, demote, leave
*As an org admin, I change what people can do, and it takes effect now.*
Through the source table only: insert a `team_members` row (invite), update its role
(promote/demote), delete it (remove), `forget_user()` (off-boarding, both kinds of
membership). After each step: the effect in the same session, in a second
`story_app` session already open, and in a session that had a prepared statement.
Asserts memberships are never edited directly by the app.

### 5. Authorship and workflow — the `if` story
*As an editor I may edit my own comments; a task moves draft → review → done.*
Comments: `update`/`delete` with `if := 'author_id = letter.user_id()::uuid'`; a
reviewer may `fill` `reviewed_by` only on comments not their own. Tasks: editors may
change `status` with a transition rule (`old.status = 'draft' AND new.status =
'review'`), reviewers with another (`review → done`), and nobody may go backwards.
Asserts each transition's allowed/refused matrix, the "both must pass" default on a
single-row rule, and that a refused write is loud (SQLSTATE 42501, `letter:` message)
while an invisible row is silently skipped (`rowcount == 0`).

### 6. The audit reader
*As an auditor I read across everything, but only the columns I am given, and I
cannot cheat.*
A global `auditor` role with column-limited `select` on every table; joins across
three tables, `GROUP BY`, `ORDER BY`, window functions; a report query the way an
analyst writes it. Asserts: hidden columns are NULL everywhere, `WHERE hidden > x`,
`ORDER BY hidden`, `max(hidden)` reveal nothing (`14` §1 through a driver), and an
auditor's `INSERT`/`UPDATE` is refused. The FK-join gap (`README` "Known gaps"): the
story records which joins needed an extra column grant.

### 7. Migrations while live
*As the migrator, I change the schema under a running app.*
`story_admin` runs a migration script (Alembic-shaped: plain SQL in a transaction)
while a `story_app` session holds a prepared statement: add a column and grant it;
rename a granted column (refused → revoke, rename, grant); drop a foreign key on a
scope path (refused); add a second FK that makes an inferred hop ambiguous (refused,
fix with `via`); drop a table with grants (cascade `NOTICE`, captured); create a
table and forget to grant it (the app's next read errors: default deny, `17` D14).
`check_health()` as a startup probe before and after. Asserts the app session sees
the new column after the migration commits without reconnecting.

### 8. Dump and restore
*As the operator, I restore last night's dump and everyone sees what they saw.*
`pg_dump` the story-3 database as `story_admin`, restore into a fresh database with
the documented `PGOPTIONS='-c letter.bypass=on -c session_replication_role=replica'`,
then run story 3's assertions against the copy. Then restore *without* the options
and assert the documented failure (the first `COPY` or `ADD CONSTRAINT`), so the
README's recipe stays true.

### 9. Bulk and background jobs
*As a job, I move data in bulk without a browser in the loop.*
As `story_app` with an insert grant: `COPY tasks FROM STDIN` (through psycopg's
`copy()`), `INSERT … SELECT` from one protected table into another, `UPDATE … FROM`,
`INSERT … ON CONFLICT DO UPDATE` where the conflict target's hidden columns are read,
`COPY tasks TO STDOUT` (refused) and `COPY (SELECT …) TO STDOUT` (redacted), `TRUNCATE`
(needs bypass → the job's own role, `story_admin`). Durations at 100k rows go to the
log, not to assertions.

### 10. What letter cannot do
*As the README, I would like to be true.*
The negative catalogue as executable expectations, one test each, `pytest.raises` or
`xfail(strict=True)` so a change in either direction is noticed: `MERGE` (`19` D5);
whole-row `RETURNING t` (`19` D3); a scope reached through a many-to-many join table
(`15` — bounded: no recursion, no many-to-many); a scope by a non-FK column; a
partition child not protected unless granted; a composite-PK scope table; column-level
`INSERT` limits (`11` 5b: an insert grant is row-level); a select grant on a table the
user may not otherwise join to; letter's own tables reachable by the app when the
`REVOKE` was forgotten; `letter.user_id` settable by the app to anyone (by design —
the perimeter is the app; the story states it). Each test's docstring is the README
sentence.

## 3. Steps

- [x] **P1 — Scaffolding** *(2026-09-23; the smoke test found S1 → D7)*. `stories/requirements.txt`, `conftest.py` (database per
  module, roles, `session_preload_libraries`, `as_user`, `request`, `truth`),
  `schema/app.sql`, `make stories` (creates `.venv` if missing, runs pytest), a
  `README` paragraph "Running the stories". Smoke: story 3's first assertion.
- [x] **P2 — Stories 1 and 2** (the perimeter) *(2026-09-23: 10 tests; findings 3 and 4)*.
- [x] **P3 — Stories 3–6** (building an app) *(2026-09-23: 25 tests; D8 for `assign`; findings 5–9)*.
- [ ] **P4 — Stories 7–9** (operating it).
- [ ] **P5 — Story 10** and the README: "Known gaps" rewritten from `FINDINGS.md`
  and story 10's docstrings; the beta status line.

## 4. Decisions (proposed — Paul to confirm or strike)

- **D1 — Black-box only.** Stories use the public API and a driver; never
  `letter._*`, never `read_policy()` in an assertion, never a superuser as the app.
- **D2 — Tooling:** pytest + psycopg 3 + psycopg_pool in `stories/.venv`; run by
  `make stories`; separate from `make installcheck`.
- **D3 — The deployment model is the fixture:** `story_app` without bypass,
  `story_admin` with `ALTER ROLE … SET letter.bypass = on`, `session_preload_libraries`
  on the database, `REVOKE ALL ON ALL TABLES IN SCHEMA letter FROM story_app`.
- **D4 — pgbouncer is out of scope** for now (not installed); transaction-mode pooling
  is documented as a recipe in story 1 and tested only with `psycopg_pool`.
- **D5 — The C suite is the authority.** A story that disagrees with a plan raises an
  S-item here; it is not fixed in either suite until the plan is amended.
- **D6 — `FINDINGS.md` is the README's "Known gaps".** Nothing goes into the README's
  gaps list that a story does not demonstrate.

- **D8 — `assign` can make a table its own scope** *(decided 2026-09-23, Paul; found
  by P3 before story 3 could be written)*. `assign('projects', 'owner_id', role :=
  'owner', scope := 'projects')` was refused ("could not find FK from projects to
  projects"); grants already allowed a table to be its own scope. When the scope table
  is the source table the scope id is the source row's primary key: the rule's
  upsert writes `NEW.<pk>`, the backfill `s.<pk>`, no scope-delete trigger is
  installed (the source-delete trigger already removes the row's memberships), and
  revalidation accepts the self case instead of demanding one foreign key. This is
  the rule that lets a user bootstrap a scope by authoring the resource.

- **D9 — Configuration is a superuser's** *(decided 2026-09-23, Paul, from finding 1;
  "we can change this later")*. `grant_*`, `revoke_*`, `assign` and `unassign` refuse
  any other role (`require_superuser`), so a migrator with bypass but without table
  privileges fails with a letter message at the door rather than a bare "permission
  denied" inside. The extension grants nothing on its schema; the application role
  needs `USAGE` on it and nothing else. A named migrator role can be added later
  without touching anything else.

- **D10 — `letter.enforcing()`** *(decided 2026-09-23, Paul, from finding 4)*: a
  boolean the application role can call — true when the library was preloaded (so
  every session has the hook), reads are enforced and bypass is off. The start-up
  probe: call it on a fresh pooled connection, refuse to serve on false. Finding 3 is
  documentation only (README "Using letter from an application").

## 5. Stop-and-discuss triggers

1. A story needs `story_admin` for something an application should be able to do.
2. A driver behaviour reaches a protected table without the hook (a leak) — stop
   before writing the assertion.
3. A story cannot be expressed at all with the current API — it goes to story 10 and
   `FINDINGS.md`; extending the API is a separate plan.
4. A story is flaky twice.
5. Anything in a story that contradicts a plan's decision.

---

## 0. Status — resume here

**2026-09-23: D1–D6 decided (Paul). P1 scaffolding in place** — `stories/`
(`conftest.py`, `helpers.py`, `schema/app.sql`, `schema/app_rules.sql`,
`test_03_signup.py` smoke, `FINDINGS.md`, `pytest.ini`, `requirements.txt`), `make
stories` (venv under `stories/.venv`, python3.13; psycopg 3.3.6, psycopg_pool 3.3.3,
pytest 9.1.1). **P1 ✅, P2 ✅ (2026-09-23): 11 story tests green.** Story 1: consecutive requests
on one physical connection see their own rows; a request failing before SET leaves
nothing behind; a forgotten RESET leaks to the next borrower (the app's bug — pool
`reset=` hook closes it, finding 3); `SET LOCAL` is transaction-scoped; a session that
never calls a letter function is enforced by `session_preload_libraries`. Story 2:
psycopg's auto-prepare (threshold 5) across three users; `prepare_threshold=0` +
`force_generic_plan`; a grant and a membership change made from the admin connection
reach a warm prepared statement on the next execution; a PL/pgSQL function's cached
plan across users. **P3 ✅ (2026-09-23): 35 story tests green.** The story application is now the
owner model (D7): `orgs.owner_id`/`projects.owner_id`, insert grants with `if owner_id =
letter.user_id()::uuid`, self-scoped rules (D8) for `org_admin` and `owner`, owners
manage `team_members`. Story 3: sign-up is privileged (finding 5), starting an org or a
project makes you its admin/owner, refusals by the `if`, an owner invites, `SELECT *`
equals `visible_columns()`. Story 4: invite/promote/demote/remove seen by a second
session's warm prepared statement, out-of-scope invite refused, delete needs a select
grant (finding 6), `forget_user()`, the app cannot touch `letter.*`. Story 5: authorship
on insert/update/delete, `fill` for reviewers, the transition matrix (8 cases), silent
skip vs loud refusal. Story 6: hidden columns say nothing through a driver, global
joins need the key columns (finding 7), an auditor cannot write. Finding 8 is an API
rough edge for Paul: `visible_columns` needs a cast from a driver. **Next: P4 (stories
7–9).**

### S1 — letter's own SPI runs with the application's privileges — ✅ RESOLVED 2026-09-23 → D7 (Paul: option a)
The first plain `SELECT` as `story_app` (no privileges on schema `letter`, as the
README's "Default deny" says) dies inside the planner hook: `permission denied for
table grants`. `FINDINGS.md` #2 has the measured ladder: reads need `SELECT` on
`letter.grants`; `visible_columns()` and the write triggers need `SELECT` on
`letter.memberships` too; a membership rule's trigger fired by an application write
needs `SELECT, INSERT, UPDATE, DELETE` on `memberships` and `membership_sources` — and
then the application can insert any membership it likes, directly. The generated
barrier is fine (`17` D6 zeroes `requiredPerms`); everything letter does through
plain SPI — the protected-set load, `populate_cache`, `visible_columns()`, the
generated `_rule_*` plpgsql functions — is checked against the *caller's* ACL.
Options: (a) run letter's internal SPI as the extension owner (`SetUserIdAndSecContext`
with `SECURITY_LOCAL_USERID_CHANGE` inside `guarded_spi_execute*`, the way a
SECURITY DEFINER function does) and generate the `_rule_*` functions `SECURITY
DEFINER` — the app then needs `USAGE` on schema `letter` and nothing else, and the
README's `REVOKE` stands; (b) zero `requiredPerms` on the internal queries the way the
barrier does (a parse-tree walk per query; does not help the plpgsql rule functions);
(c) document that the app role needs `SELECT` on `grants`/`memberships` and make the
rule functions `SECURITY DEFINER` — cheaper, but discloses every grant and membership
to the app. Ruling-shaped: the trust boundary of `14` §2.

**D7 (2026-09-23, Paul):** (a). Configuration is done by a superuser with bypass;
memberships arise from the application's own writes through rules (an owner
bootstraps a scope by authoring the resource; an `if` on the insert grant ties
`owner_id` to the current user), or are written to `letter.memberships` directly by a
privileged process — never through a letter-enforced route. Landed the same day:
`guard_enter`/`guard_exit` switch the session to the extension owner
(`SetUserIdAndSecContext` with `SECURITY_LOCAL_USERID_CHANGE`) for every one of
letter's own queries — the protected-set load, the session cache, the barrier's
grant read, `visible_columns()`, the hop walks, the `if` plans; configuration calls
run as their caller. The generated `_rule_*` functions are `SECURITY DEFINER SET
search_path = pg_catalog, pg_temp`, and the rule's `if` is embedded schema-qualified
(`deparse_if_as(…, qualify = true)`: analysed in the configurer's search_path, deparsed
with only `pg_catalog` visible — pg_dump's trick). Verified as `story_app` with no
privilege on letter's tables: reads, `visible_columns()`, an editor inviting a viewer
through `team_members` (the rule confers the membership), the app refused on a direct
`INSERT`/`SELECT` on `letter.memberships`. README "Deployment model" rewritten.
`FINDINGS.md` #1 stands as documentation: a non-superuser migrator needs privileges on
letter's schema.

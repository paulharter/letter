# Findings from the user stories (plan/21)

What the stories found the API could not express, or needed the admin role
for. Source of the README's "Known gaps" at beta (plan/21 D6).

1. **The extension grants no privileges on its own schema** (P1, scaffolding —
   ✅ resolved 2026-09-23 → D9: configuration is a superuser's; the four
   configuration calls refuse any other role with a letter message). A
   non-superuser migrator could not call `grant_*`/`revoke_*`/`assign` until it
   had `ALL` on letter's tables and `USAGE, CREATE` on schema `letter`. The
   application role needs `USAGE` on the schema to call `letter.user_id()` and
   `letter.visible_columns()`, and nothing else. The story admin is now a
   superuser.

2. **Letter's own reads and writes ran with the application's privileges**
   (P1, the smoke test — plan/21 S1, ✅ resolved 2026-09-23 → D7: letter's own
   queries now run as the extension owner and the rule functions are
   `SECURITY DEFINER`; the application role needs `USAGE` on schema `letter`
   and nothing else). The ladder as measured before the fix: Measured as `story_app` with the
   README's `REVOKE ALL ON ALL TABLES IN SCHEMA letter` in place:
   - a plain `SELECT` fails inside the planner hook: `permission denied for
     table grants` (the protected-set load is a plain SPI query);
   - with `SELECT` on `letter.grants` reads work (the barrier's own reads carry
     `requiredPerms = 0`, `17` D6), but `visible_columns()` and every write
     trigger fail on `letter.memberships`;
   - with `SELECT` on both, reads, `visible_columns()` and writes work;
   - a membership rule's trigger (an editor inviting a viewer by inserting a
     `team_members` row) fails on `letter.membership_sources`, and needs
     `SELECT, INSERT, UPDATE, DELETE` on `memberships` and `membership_sources`
     — at which point the application role can `INSERT INTO letter.memberships
     ('org_admin', …)` directly, and read every grant and membership.
   So the deployment model as then documented could not be deployed. Fixed on
   letter's side (D7); the README's "Deployment model" now says exactly what
   each role needs.

3. **A forgotten RESET is the application's bug, and letter cannot see it**
   (story 1 — ✅ 2026-09-23: README "Using letter from an application", the
   three recipes and the pgbouncer rule; Paul: documentation only). A handler that sets `letter.user_id` and never resets it leaves
   the user on the pooled connection for the next borrower, who then reads
   as that user. letter has no notion of a request boundary. The recipe:
   `as_user`-style set/RESET in a `finally`, or `SET LOCAL` inside the
   request's transaction, plus a pool reset hook (`psycopg_pool`'s `reset=`,
   `RESET letter.user_id` or `DISCARD ALL`) as the second line of defence.
   Under pgbouncer in transaction mode, `SET LOCAL` only (untested here, D4).
   Documentation, not a gap in letter.

4. **The application role cannot `SHOW session_preload_libraries`** (story 1 —
   ✅ 2026-09-23 → `letter.enforcing()`, the start-up probe; D10):
   only `pg_read_all_settings` may. A startup probe that wants to confirm the
   hook is loaded should run `letter.check_health()` as the admin role, or
   simply rely on the behaviour: a SELECT with no user set errors.

5. **Sign-up is a privileged step** (story 3). A user who does not exist yet
   holds no role, so no grant can let them insert their own `users` row; the
   application inserts it with bypass (or a backend process does). From then
   on everything follows from rules: the `users` row confers the global role
   `user`, which may start an org (`if owner_id = letter.user_id()::uuid`),
   whose author is its admin, who starts projects, whose author owns them
   (D7, D8). Documentation.

6. **A write reaches only the rows the writer can see** (story 4, `19` D1).
   An owner with insert and delete grants on `team_members` but no select
   grant issues a `DELETE` that matches nothing — silently. Managing a
   membership source table needs a select grant on it too. Documentation,
   and an argument for a "manage" idiom in the README.

7. **Under a global grant, a join needs the key columns granted** (story 6;
   README "Known gaps"). The auditor's `projects ⋈ tasks` matched nothing
   until `tasks.project_id` was granted. Scoped grants disclose their own path
   column (`17` D16); global ones have no path. Documentation.

8. **`visible_columns(rel, pk anyelement)` needs a cast from a driver**
   (story 3): a parameter sent as unknown cannot resolve the polymorphic
   argument — `could not determine polymorphic type`. Write
   `letter.visible_columns('public.projects', $1::uuid)`. The function turns
   the key into text and casts it to the column's type itself, so `$1::text`
   works for any key type. A `(regclass, text)` overload would remove the
   surprise. API rough edge — for Paul.

9. **An emptied user reads nothing, not an error** (story 4). After
   `forget_user()` the user's `SELECT` on a granted table returns zero rows;
   only a table with no grants at all errors (`17` D14). Documentation.

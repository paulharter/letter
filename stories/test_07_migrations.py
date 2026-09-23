"""Story 7 — Migrations while live.

As the migrator, I change the schema under a running app. (plan/21 §2.7)
Each migration is a transaction run by story_admin — a superuser with
bypass, as configuration must be (D9) — while Alice's session stays open
with a prepared statement.
"""
import pytest
import psycopg

from helpers import ALICE, CAROL, ALPHA, as_user, col, denied, rows, seed_basic, truth

Q = "SELECT name, budget FROM projects ORDER BY name"


@pytest.fixture(scope="module")
def seeded(app_rules):
    seed_basic(app_rules)
    return app_rules


@pytest.fixture(scope="module")
def alice(story_db, seeded):
    """Alice's session, open throughout, prepared statements from the start."""
    from conftest import _conninfo
    with psycopg.connect(_conninfo(story_db, "story_app"), autocommit=True, prepare_threshold=0) as conn:
        conn.execute("SELECT set_config('letter.user_id', %s, false)", (ALICE,))
        assert conn.execute(Q).fetchall() == [("Alpha", 1000)]
        yield conn


def migrate(admin, *statements):
    """A migration: one transaction, all or nothing. Returns the notices."""
    notices = []
    admin.add_notice_handler(lambda d: notices.append(d.message_primary))
    try:
        with admin.transaction():
            for stmt in statements:
                admin.execute(stmt)
    finally:
        admin._notice_handlers.clear()
    return notices


def health(admin):
    return rows(admin, "SELECT severity, object, message FROM letter.check_health() ORDER BY 1, 2")


def test_healthy_to_start(seeded):
    assert [r for r in health(seeded) if r[0] == "error"] == []


def test_add_a_column_and_grant_it(seeded, alice, app):
    """A new column is hidden until granted; editors with '*' see it at once,
    viewers after their grant; Alice's open session needs no reconnect."""
    migrate(seeded,
            "ALTER TABLE projects ADD COLUMN priority int NOT NULL DEFAULT 3",
            "SELECT letter.grant_scoped('select', 'public.projects', 'viewer', ARRAY['priority'], 'public.projects')")
    assert alice.execute("SELECT priority FROM projects").fetchall() == [(3,)]      # editor '*'
    assert alice.execute(Q).fetchall() == [("Alpha", 1000)]                           # the prepared one still works
    with as_user(app, CAROL):
        assert rows(app, "SELECT name, priority, budget FROM projects") == [("Alpha", 3, None)]


def test_select_star_prepared_before_the_migration(story_db, seeded):
    """PostgreSQL itself, not letter: a statement prepared as SELECT * cannot
    change its result shape. After the column is added the driver gets
    'cached plan must not change result type' on every execution until the
    statement is deallocated (DEALLOCATE ALL, or a pool reset). Explicit
    column lists are unaffected (FINDINGS.md #10)."""
    from conftest import _conninfo
    with psycopg.connect(_conninfo(story_db, "story_app"), autocommit=True, prepare_threshold=0) as conn:
        conn.execute("SELECT set_config('letter.user_id', %s, false)", (ALICE,))
        before = conn.execute("SELECT * FROM projects").fetchone()
        migrate(seeded, "ALTER TABLE projects ADD COLUMN tagline text")
        with pytest.raises(psycopg.errors.FeatureNotSupported) as e:
            conn.execute("SELECT * FROM projects")
        assert "cached plan must not change result type" in str(e.value)
        with pytest.raises(psycopg.errors.FeatureNotSupported):        # and again: the driver does not recover by itself
            conn.execute("SELECT * FROM projects")
        conn.execute("DEALLOCATE ALL")
        after = conn.execute("SELECT * FROM projects").fetchone()
        assert len(after) == len(before) + 1
        assert conn.execute(Q).fetchall() == [("Alpha", 1000)]          # named columns never minded
        migrate(seeded, "ALTER TABLE projects DROP COLUMN tagline")


def test_renaming_a_granted_column_is_refused_then_done_properly(seeded, alice):
    """budget is named by the owner's update grant: RENAME is refused with the
    grant that would break. Revoke, rename, grant — the app never sees a
    broken state, and the prepared statement keeps working in between."""
    with pytest.raises(psycopg.Error) as e:
        migrate(seeded, "ALTER TABLE projects RENAME COLUMN budget TO cost")
    assert "would no longer be valid" in str(e.value) and "owner" in str(e.value)
    assert alice.execute(Q).fetchall() == [("Alpha", 1000)]
    migrate(seeded,
            "SELECT letter.revoke_scoped('update', 'public.projects', 'owner', ARRAY['budget'], 'public.projects')",
            "ALTER TABLE projects RENAME COLUMN budget TO cost",
            "SELECT letter.grant_scoped('update', 'public.projects', 'owner', ARRAY['cost'], 'public.projects')")
    assert alice.execute("SELECT name, cost FROM projects ORDER BY name").fetchall() == [("Alpha", 1000)]
    alice.execute("UPDATE projects SET cost = 1100 WHERE id = %s", (ALPHA,))
    assert truth(seeded, "SELECT cost FROM projects WHERE id = %s", (ALPHA,)) == [(1100,)]
    migrate(seeded,
            "SELECT letter.revoke_scoped('update', 'public.projects', 'owner', ARRAY['cost'], 'public.projects')",
            "ALTER TABLE projects RENAME COLUMN cost TO budget",
            "SELECT letter.grant_scoped('update', 'public.projects', 'owner', ARRAY['budget'], 'public.projects')")


def test_dropping_a_foreign_key_on_a_scope_path_is_refused(seeded, alice):
    with pytest.raises(psycopg.Error) as e:
        migrate(seeded, "ALTER TABLE tasks DROP CONSTRAINT tasks_project_id_fkey")
    assert "would no longer be valid" in str(e.value)
    assert alice.execute("SELECT count(*) FROM tasks").fetchone()[0] == 2


def test_a_second_foreign_key_to_the_scope(seeded, alice):
    """On tasks the hop to projects is inferred from its single foreign key:
    a second one makes it ambiguous and the ALTER is refused, naming the
    fix. On comments the first hop is named (via), so a second key to tasks
    is fine."""
    with pytest.raises(psycopg.Error) as e:
        migrate(seeded, "ALTER TABLE tasks ADD COLUMN moved_from uuid REFERENCES projects(id)")
    assert "more than one foreign key" in str(e.value) and "via" in str(e.value)
    migrate(seeded, "ALTER TABLE comments ADD COLUMN reply_to_task uuid REFERENCES tasks(id)")
    assert alice.execute("SELECT count(*) FROM comments").fetchone()[0] == 0


def test_dropping_a_table_cascades_with_a_notice(seeded, alice):
    migrate(seeded,
            "CREATE TABLE attachments (id serial PRIMARY KEY, task_id uuid REFERENCES tasks(id), name text)",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON attachments TO story_app",
            "SELECT letter.grant_scoped('select', 'public.attachments', 'editor', ARRAY['*'], 'public.projects', ARRAY['task_id'])")
    assert alice.execute("SELECT count(*) FROM attachments").fetchone()[0] == 0
    notices = migrate(seeded, "DROP TABLE attachments")
    assert any("dropped table public.attachments: removed 1 grant(s)" in n for n in notices), notices
    assert [r for r in health(seeded) if r[0] == "error"] == []


def test_a_new_table_nobody_granted(seeded, alice):
    """Default deny (17 D14): a table with no grants errors for the app —
    loudly, the way a configuration mistake should — until it is granted."""
    migrate(seeded, "CREATE TABLE milestones (id serial PRIMARY KEY, project_id uuid REFERENCES projects(id), title text)",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON milestones TO story_app")
    with pytest.raises(psycopg.Error) as e:
        alice.execute("SELECT count(*) FROM milestones")
    assert denied(e.value) and "no grants" in str(e.value)
    migrate(seeded, "SELECT letter.grant_scoped('select', 'public.milestones', 'editor', ARRAY['*'], 'public.projects')")
    assert alice.execute("SELECT count(*) FROM milestones").fetchone()[0] == 0
    assert [r for r in health(seeded) if r[0] == "error"] == []

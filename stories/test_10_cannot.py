"""Story 10 — What letter cannot do.

As the README, I would like to be true. (plan/21 §2.10) Each test's
docstring is the sentence the README's "Known gaps" carries; each test
pins the current behaviour so that a change in either direction is
noticed.
"""
import pytest
import psycopg

from helpers import ALICE, BOB, CAROL, ALPHA, BETA, as_user, col, denied, refused, rows, seed_basic, truth


@pytest.fixture(scope="module")
def seeded(app_rules):
    seed_basic(app_rules)
    return app_rules


def test_merge(seeded, app):
    """`MERGE` on a protected table is refused."""
    with as_user(app, ALICE):
        with pytest.raises(psycopg.Error) as e:
            app.execute("MERGE INTO tasks t USING (SELECT %s::uuid AS project_id, 'merged' AS title) s "
                        "ON t.project_id = s.project_id AND t.title = s.title "
                        "WHEN MATCHED THEN UPDATE SET estimate = 1 "
                        "WHEN NOT MATCHED THEN INSERT (project_id, title) VALUES (s.project_id, s.title)", (ALPHA,))
        assert refused(e.value) and "MERGE" in str(e.value)
    assert truth(seeded, "SELECT count(*) FROM tasks WHERE title = 'merged'")[0][0] == 0


def test_whole_row_returning(seeded, app):
    """A whole-row reference to the table a statement writes to (`UPDATE t … RETURNING t`) is refused."""
    with as_user(app, ALICE):
        with pytest.raises(psycopg.Error) as e:
            app.execute("UPDATE tasks SET estimate = 1 WHERE project_id = %s RETURNING tasks", (ALPHA,))
        assert refused(e.value) and "whole-row" in str(e.value)
        assert app.execute("UPDATE tasks SET estimate = 1 WHERE project_id = %s RETURNING title", (ALPHA,)).rowcount == 2


def test_many_to_many_is_not_a_scope_path(seeded, app):
    """`via` follows foreign keys in the many-to-one direction only, from a row to the row it points at; it never follows a key backwards, so a table that is only pointed at (labels behind a join table) cannot be scoped — give it a key of its own, or grant it globally."""
    seeded.execute("CREATE TABLE labels (id serial PRIMARY KEY, name text)")
    seeded.execute("CREATE TABLE task_labels (task_id uuid REFERENCES tasks(id), label_id int REFERENCES labels(id), PRIMARY KEY (task_id, label_id))")
    with pytest.raises(psycopg.Error) as e:
        seeded.execute("SELECT letter.grant_scoped('select', 'public.labels', 'editor', ARRAY['*'], 'public.projects')")
    assert refused(e.value) and "no foreign key path" in str(e.value)
    # the join table itself can be: it points at tasks, which point at projects
    seeded.execute("SELECT letter.grant_scoped('select', 'public.task_labels', 'editor', ARRAY['*'], 'public.projects', ARRAY['task_id'])")


def test_via_must_name_foreign_keys(seeded, app):
    """`via` names foreign key columns and nothing else."""
    with pytest.raises(psycopg.Error) as e:
        seeded.execute("SELECT letter.grant_scoped('select', 'public.tasks', 'editor', ARRAY['*'], 'public.projects', ARRAY['title'])")
    assert refused(e.value) and "not a foreign key" in str(e.value)


def test_a_path_is_a_fixed_chain(seeded, app):
    """One hop per column `via` names or infers, always many-to-one: a self-reference (`parent_id`) is followed exactly as many times as `via` names it."""
    seeded.execute("ALTER TABLE tasks ADD COLUMN parent_id uuid REFERENCES tasks(id)")
    (t1,) = truth(seeded, "SELECT id FROM tasks WHERE title = 'Alpha task 1'")[0]
    (t2,) = seeded.execute("INSERT INTO tasks (project_id, title, parent_id) VALUES (%s, 'child', %s) RETURNING id", (ALPHA, t1)).fetchone()
    (t3,) = seeded.execute("INSERT INTO tasks (project_id, title, parent_id) VALUES (%s, 'grandchild in Beta', %s) RETURNING id", (BETA, t2)).fetchone()
    seeded.execute("INSERT INTO letter.memberships (role, user_id, scope_table, scope_id) VALUES ('lead', %s, 'public.projects', %s)", (CAROL, ALPHA))   # RBAC-style, by the admin
    # one hop: the parent's project
    seeded.execute("SELECT letter.grant_scoped('select', 'public.tasks', 'lead', ARRAY['title'], 'public.projects', ARRAY['parent_id'])")
    with as_user(app, CAROL):                     # viewer@Alpha sees Alpha's tasks anyway; lead adds the Beta grandchild, whose parent is in Alpha
        assert col(app, "SELECT title FROM tasks ORDER BY title") == ["Alpha task 1", "Alpha task 2", "child", "grandchild in Beta"]
    seeded.execute("SELECT letter.revoke_scoped('select', 'public.tasks', 'lead', ARRAY['title'], 'public.projects')")
    # two hops: the grandparent's project — the child has none, the grandchild's is Alpha
    seeded.execute("SELECT letter.grant_scoped('select', 'public.tasks', 'lead', ARRAY['title'], 'public.projects', ARRAY['parent_id', 'parent_id'])")
    with as_user(app, CAROL):
        assert col(app, "SELECT title FROM tasks ORDER BY title") == ["Alpha task 1", "Alpha task 2", "child", "grandchild in Beta"]
    seeded.execute("SELECT letter.revoke_scoped('select', 'public.tasks', 'viewer', ARRAY['title', 'status'], 'public.projects')")
    with as_user(app, CAROL):                     # lead alone, two hops: only the grandchild
        assert col(app, "SELECT title FROM tasks ORDER BY title") == ["grandchild in Beta"]
    seeded.execute("SELECT letter.grant_scoped('select', 'public.tasks', 'viewer', ARRAY['title', 'status'], 'public.projects')")


def test_partitions_are_tables_of_their_own(seeded, app):
    """A partitioned table is protected through its parent; a partition queried directly is a table of its own to letter, with no grants of its own unless it is granted."""
    seeded.execute("CREATE TABLE events (id serial, project_id uuid REFERENCES projects(id), kind text NOT NULL, PRIMARY KEY (id, kind)) PARTITION BY LIST (kind)")
    seeded.execute("CREATE TABLE events_a PARTITION OF events FOR VALUES IN ('a')")
    seeded.execute("GRANT SELECT, INSERT ON events, events_a TO story_app")
    seeded.execute("INSERT INTO events (project_id, kind) VALUES (%s, 'a'), (%s, 'a')", (ALPHA, BETA))
    seeded.execute("SELECT letter.grant_scoped('select', 'public.events', 'editor', ARRAY['*'], 'public.projects')")
    with as_user(app, ALICE):
        assert app.execute("SELECT count(*) FROM events").fetchone()[0] == 1          # through the parent: enforced
        with pytest.raises(psycopg.Error) as e:
            app.execute("SELECT count(*) FROM events_a")                              # the partition: nobody granted it
        assert denied(e.value) and "no grants" in str(e.value)


def test_an_insert_grant_is_row_level(seeded, app):
    """An insert or delete grant covers the whole row and takes no column list: one is refused at grant time."""
    seeded.execute("CREATE TABLE notes2 (id serial PRIMARY KEY, project_id uuid REFERENCES projects(id), body text, secret text)")
    seeded.execute("GRANT SELECT, INSERT ON notes2 TO story_app")
    seeded.execute("GRANT USAGE ON SEQUENCE notes2_id_seq TO story_app")
    seeded.execute("SELECT letter.grant_scoped('select', 'public.notes2', 'editor', ARRAY['body'], 'public.projects')")
    with pytest.raises(psycopg.Error) as e:
        seeded.execute("SELECT letter.grant_scoped('insert', 'public.notes2', 'editor', ARRAY['body'], 'public.projects')")
    assert refused(e.value) and "row-level" in str(e.value)
    seeded.execute("SELECT letter.grant_scoped('insert', 'public.notes2', 'editor', NULL, 'public.projects')")
    with as_user(app, ALICE):
        app.execute("INSERT INTO notes2 (project_id, body, secret) VALUES (%s, 'x', 'any column at all')", (ALPHA,))


def test_a_join_to_an_ungranted_table_errors(seeded, app):
    """Default deny, by design (README "Default deny"): a join that reaches a table with no grants errors, whatever the user may see in the others; check_health() lists such tables."""
    seeded.execute("CREATE TABLE ungranted (id serial PRIMARY KEY, task_id uuid REFERENCES tasks(id))")
    seeded.execute("GRANT SELECT ON ungranted TO story_app")
    with as_user(app, ALICE):
        with pytest.raises(psycopg.Error) as e:
            app.execute("SELECT t.title FROM tasks t JOIN ungranted u ON u.task_id = t.id")
        assert denied(e.value) and "no grants" in str(e.value)
    assert ("info", "table public.ungranted") in [
        (r[0], r[1]) for r in seeded.execute("SELECT severity, object FROM letter.check_health()")]


def test_letters_own_tables_are_the_operators_to_protect(seeded, app):
    """Letter's tables are ordinary tables and their SQL privileges are the operator's to set (README "Deployment model"): by default the application cannot read them; granted SELECT on `letter.memberships`, it reads every membership — letter does not redact its own tables."""
    seeded.execute("GRANT SELECT ON letter.memberships TO story_app")
    try:
        assert app.execute("SELECT count(*) FROM letter.memberships").fetchone()[0] > 0
    finally:
        seeded.execute("REVOKE SELECT ON letter.memberships FROM story_app")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        app.execute("SELECT count(*) FROM letter.memberships")


def test_the_user_is_whoever_the_app_says(seeded, app):
    """`letter.user_id` is a session setting the application chooses: whoever can run SQL as the application role can be anyone. The application layer that sets it is the perimeter; end users never hold a connection."""
    with as_user(app, ALICE):
        assert col(app, "SELECT name FROM projects") == ["Alpha"]
    with as_user(app, BOB):
        assert col(app, "SELECT name FROM projects") == ["Beta"]

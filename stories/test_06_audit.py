"""Story 6 — The audit reader.

As an auditor I read across everything, but only the columns I am given,
and I cannot cheat. (plan/21 §2.6)

Eve's membership is written directly by the admin — RBAC-style, from a
privileged process, never through a letter-enforced route (D7).
"""
import pytest
import psycopg

from helpers import ALICE, EVE, actual_view, as_user, col, denied, expected_view, rows, seed_basic, truth


@pytest.fixture(scope="module")
def seeded(app_rules):
    seed_basic(app_rules)
    a = app_rules
    a.execute("INSERT INTO users (id, name, email) VALUES (%s, 'Eve', 'eve@example.com')", (EVE,))
    a.execute("INSERT INTO letter.memberships (role, user_id) VALUES ('auditor', %s)", (EVE,))
    for table, cols in (("projects", ["name", "status"]), ("tasks", ["title", "status"]), ("comments", ["body"])):
        a.execute("SELECT letter.grant_global('select', %s, 'auditor', %s)", (f"public.{table}", cols))
    a.execute("INSERT INTO comments (task_id, author_id, body) SELECT id, %s, 'on ' || title FROM tasks", (ALICE,))
    return a


def test_hidden_columns_are_null_and_say_nothing(seeded, app):
    with as_user(app, EVE):
        assert rows(app, "SELECT name, budget, notes FROM projects ORDER BY name") == [("Alpha", None, None), ("Beta", None, None)]
        assert rows(app, "SELECT name FROM projects WHERE budget > 0") == []
        assert rows(app, "SELECT name FROM projects WHERE budget IS NULL ORDER BY name") == [("Alpha",), ("Beta",)]
        assert app.execute("SELECT max(budget), sum(budget) FROM projects").fetchone() == (None, None)
        assert col(app, "SELECT name FROM projects ORDER BY budget DESC NULLS LAST, name") == ["Alpha", "Beta"]
        assert app.execute("SELECT count(*) FROM projects").fetchone()[0] == truth(seeded, "SELECT count(*) FROM projects")[0][0]
        assert actual_view(app, "projects") == expected_view(app, seeded, "projects")


def test_joins_need_the_key_columns_granted(seeded, app):
    """The foreign keys are columns like any other under a global grant:
    without tasks.project_id the join matches nothing (FINDINGS.md #7);
    with it, the report works — GROUP BY, ORDER BY, a window function."""
    report = ("SELECT p.name, count(t.id) FROM projects p JOIN tasks t ON t.project_id = p.id "
              "GROUP BY p.name ORDER BY p.name")
    with as_user(app, EVE):
        assert rows(app, report) == []
    seeded.execute("SELECT letter.grant_global('select', 'public.tasks', 'auditor', ARRAY['project_id'])")
    seeded.execute("SELECT letter.grant_global('select', 'public.comments', 'auditor', ARRAY['task_id'])")
    with as_user(app, EVE):
        assert rows(app, report) == [("Alpha", 2), ("Beta", 1)]
        assert rows(app, "SELECT t.title, row_number() OVER (PARTITION BY t.project_id ORDER BY t.title) "
                         "FROM tasks t ORDER BY t.title") == [("Alpha task 1", 1), ("Alpha task 2", 2), ("Beta task 1", 1)]
        assert rows(app, "SELECT p.name, c.body FROM comments c JOIN tasks t ON t.id = c.task_id "
                         "JOIN projects p ON p.id = t.project_id ORDER BY c.body") == \
            [("Alpha", "on Alpha task 1"), ("Alpha", "on Alpha task 2"), ("Beta", "on Beta task 1")]
        assert col(app, "SELECT author_id FROM comments WHERE author_id IS NOT NULL") == []


def test_an_auditor_cannot_write(seeded, app):
    with as_user(app, EVE):
        with pytest.raises(psycopg.Error) as e:
            app.execute("INSERT INTO projects (org_id, owner_id, name) SELECT org_id, %s, 'x' FROM projects LIMIT 1", (EVE,))
        assert denied(e.value)
        with pytest.raises(psycopg.Error) as e:
            app.execute("UPDATE projects SET name = 'x'")
        assert denied(e.value)
        with pytest.raises(psycopg.Error) as e:
            app.execute("DELETE FROM tasks")
        assert denied(e.value)
    assert truth(seeded, "SELECT count(*) FROM tasks")[0][0] == 3

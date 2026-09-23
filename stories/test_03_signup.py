"""Story 3 — Sign-up to first project.

As a new user, I join, start an org, get a project, and see only mine.
(plan/21 §2.3, on the owner model of D7/D8: whoever authors an org or a
project owns it, and owners invite.)
"""
import pytest
import psycopg

from helpers import (ALICE, CAROL, DAVE, ALPHA, actual_view, as_user, col, denied,
                     expected_view, rows, seed_basic, truth)


@pytest.fixture(scope="module")
def seeded(app_rules):
    seed_basic(app_rules)
    return app_rules


def test_signup_is_a_privileged_step(seeded, app):
    """Dave does not exist yet, so no rule can have given him a role and no
    grant can let him insert his own user row: the sign-up write is the
    application's privileged step (FINDINGS.md #5)."""
    with as_user(app, DAVE):
        with pytest.raises(psycopg.Error) as e:
            app.execute("INSERT INTO users (id, name, email) VALUES (%s, 'Dave', 'dave@example.com')", (DAVE,))
        assert denied(e.value)
    seeded.execute("INSERT INTO users (id, name, email) VALUES (%s, 'Dave', 'dave@example.com')", (DAVE,))
    with as_user(app, DAVE):                       # the 'user' rule fired: he can see who exists
        assert col(app, "SELECT name FROM users ORDER BY name") == ["Alice", "Bob", "Carol", "Dave"]
        assert col(app, "SELECT email FROM users WHERE email IS NOT NULL") == []


def test_starting_an_org_makes_you_its_admin(seeded, app):
    """Dave inserts an org he owns and is its org_admin at once; an org
    owned by somebody else is refused by the insert grant's if."""
    with as_user(app, DAVE):
        with pytest.raises(psycopg.Error) as e:
            app.execute("INSERT INTO orgs (owner_id, name) VALUES (%s, 'Not mine')", (ALICE,))
        assert denied(e.value)
        (org_id,) = app.execute("INSERT INTO orgs (owner_id, name) VALUES (%s, 'Dave Co') RETURNING id", (DAVE,)).fetchone()
        assert rows(app, "SELECT name, plan FROM orgs ORDER BY name") == [("Dave Co", "free")]   # not Acme
        app.execute("UPDATE orgs SET plan = 'team' WHERE id = %s", (org_id,))
        assert col(app, "SELECT plan FROM orgs") == ["team"]
    assert truth(seeded, "SELECT count(*) FROM orgs")[0][0] == 2


def test_starting_a_project_makes_you_its_owner(seeded, app):
    """Dave starts a project in his org and owns it: every column visible,
    Alpha still invisible. A project in Acme, or owned by Alice, is refused."""
    (org_id,) = truth(seeded, "SELECT id FROM orgs WHERE name = 'Dave Co'")[0]
    (acme,) = truth(seeded, "SELECT id FROM orgs WHERE name = 'Acme'")[0]
    with as_user(app, DAVE):
        with pytest.raises(psycopg.Error) as e:
            app.execute("INSERT INTO projects (org_id, owner_id, name) VALUES (%s, %s, 'In Acme')", (acme, DAVE))
        assert denied(e.value)
        with pytest.raises(psycopg.Error) as e:
            app.execute("INSERT INTO projects (org_id, owner_id, name) VALUES (%s, %s, 'For Alice')", (org_id, ALICE))
        assert denied(e.value)
        (solo,) = app.execute("INSERT INTO projects (org_id, owner_id, name, budget) VALUES (%s, %s, 'Solo', 500) RETURNING id",
                              (org_id, DAVE)).fetchone()
        assert rows(app, "SELECT name, budget FROM projects ORDER BY name") == [("Solo", 500)]
        assert set(app.execute("SELECT letter.visible_columns('public.projects', %s::uuid)", (str(solo),)).fetchone()[0]) \
            == {"id", "org_id", "owner_id", "name", "status", "budget", "notes"}
        assert app.execute("SELECT letter.visible_columns('public.projects', %s::uuid)", (ALPHA,)).fetchone()[0] is None
        app.execute("UPDATE projects SET notes = 'kick-off' WHERE id = %s", (solo,))
        assert app.execute("UPDATE projects SET notes = 'x' WHERE id = %s", (ALPHA,)).rowcount == 0   # not there


def test_owner_invites_and_the_member_sees_the_project(seeded, app):
    """Dave invites Carol as an editor by inserting a team_members row;
    Carol, who only viewed Alpha, now sees Solo too, in full."""
    (solo,) = truth(seeded, "SELECT id FROM projects WHERE name = 'Solo'")[0]
    with as_user(app, CAROL):
        assert col(app, "SELECT name FROM projects ORDER BY name") == ["Alpha"]
    with as_user(app, DAVE):
        app.execute("INSERT INTO team_members (project_id, user_id, role) VALUES (%s, %s, 'editor')", (solo, CAROL))
        assert rows(app, "SELECT role FROM team_members") == [("editor",)]
    with as_user(app, CAROL):
        assert rows(app, "SELECT name, budget FROM projects ORDER BY name") == [("Alpha", None), ("Solo", 500)]
        assert app.execute("SELECT letter.visible_columns('public.projects', %s::uuid)", (ALPHA,)).fetchone()[0] == ["id", "name", "status"]


def test_select_star_is_what_visible_columns_says(seeded, app):
    """For each user, SELECT * FROM projects is exactly the rows that
    visible_columns() admits, with the columns it withholds as NULL."""
    for user in (ALICE, CAROL, DAVE):
        with as_user(app, user):
            assert actual_view(app, "projects") == expected_view(app, seeded, "projects")

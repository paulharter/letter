"""Story 4 — Invite, promote, demote, leave.

As a project owner, I change what people can do, and it takes effect now —
in my session, in theirs, and in a statement they had already prepared.
(plan/21 §2.4)
"""
import pytest
import psycopg

from helpers import ALICE, BOB, DAVE, ALPHA, BETA, as_user, denied, rows, seed_basic, truth

Q = "SELECT name, budget FROM projects ORDER BY name"


@pytest.fixture(scope="module")
def seeded(app_rules):
    seed_basic(app_rules)
    app_rules.execute("INSERT INTO users (id, name, email) VALUES (%s, 'Dave', 'dave@example.com')", (DAVE,))
    return app_rules


@pytest.fixture(scope="module")
def dave(story_db, seeded):
    """Dave's own session, open throughout, with a warm prepared statement."""
    from conftest import _conninfo
    with psycopg.connect(_conninfo(story_db, "story_app"), autocommit=True, prepare_threshold=0) as conn:
        conn.execute("SELECT set_config('letter.user_id', %s, false)", (DAVE,))
        assert conn.execute(Q).fetchall() == []
        yield conn


def test_invite_promote_demote_remove(seeded, app, dave):
    with as_user(app, ALICE):                     # owner of Alpha
        app.execute("INSERT INTO team_members (project_id, user_id, role) VALUES (%s, %s, 'viewer')", (ALPHA, DAVE))
    assert dave.execute(Q).fetchall() == [("Alpha", None)]            # invited: name, not budget
    with as_user(app, ALICE):
        app.execute("UPDATE team_members SET role = 'editor' WHERE project_id = %s AND user_id = %s", (ALPHA, DAVE))
    assert dave.execute(Q).fetchall() == [("Alpha", 1000)]            # promoted
    with as_user(app, ALICE):
        app.execute("UPDATE team_members SET role = 'viewer' WHERE project_id = %s AND user_id = %s", (ALPHA, DAVE))
    assert dave.execute(Q).fetchall() == [("Alpha", None)]            # demoted
    with as_user(app, ALICE):
        assert app.execute("DELETE FROM team_members WHERE user_id = %s", (DAVE,)).rowcount == 1
    assert dave.execute(Q).fetchall() == []                           # removed


def test_only_the_owner_of_that_project(seeded, app):
    """Alice cannot put Dave on Beta (Bob's): the insert is out of her scope."""
    with as_user(app, ALICE):
        with pytest.raises(psycopg.Error) as e:
            app.execute("INSERT INTO team_members (project_id, user_id, role) VALUES (%s, %s, 'viewer')", (BETA, DAVE))
        assert denied(e.value)
    with as_user(app, BOB):
        assert rows(app, "SELECT count(*) FROM team_members WHERE project_id = %s", (BETA,)) == [(1,)]


def test_removing_needs_to_see_the_row(seeded, app, dave):
    """An owner without a select grant on team_members would issue a DELETE
    that matches nothing: rows the user cannot see are not there for a
    write (19 D1). With the grant, it works (FINDINGS.md #6)."""
    with as_user(app, ALICE):
        app.execute("INSERT INTO team_members (project_id, user_id, role) VALUES (%s, %s, 'viewer')", (ALPHA, DAVE))
    seeded.execute("SELECT letter.revoke_scoped('select', 'public.team_members', 'owner', ARRAY['*'], 'public.projects')")
    with as_user(app, ALICE):
        assert app.execute("DELETE FROM team_members WHERE user_id = %s", (DAVE,)).rowcount == 0
    assert dave.execute(Q).fetchall() == [("Alpha", None)]
    seeded.execute("SELECT letter.grant_scoped('select', 'public.team_members', 'owner', ARRAY['*'], 'public.projects')")
    with as_user(app, ALICE):
        assert app.execute("DELETE FROM team_members WHERE user_id = %s", (DAVE,)).rowcount == 1
    assert dave.execute(Q).fetchall() == []


def test_offboarding_forgets_every_membership(seeded, app, dave):
    """Dave is on Alpha's team and in Acme; forget_user() removes both
    kinds of membership at once — a privileged step."""
    (acme,) = truth(seeded, "SELECT id FROM orgs WHERE name = 'Acme'")[0]
    with as_user(app, ALICE):                     # org admin of Acme and owner of Alpha
        app.execute("INSERT INTO org_members (org_id, user_id) VALUES (%s, %s)", (acme, DAVE))
        app.execute("INSERT INTO team_members (project_id, user_id, role) VALUES (%s, %s, 'editor')", (ALPHA, DAVE))
    assert dave.execute(Q).fetchall() == [("Alpha", 1000)]
    assert dave.execute("SELECT count(*) FROM orgs").fetchone()[0] == 1
    assert truth(seeded, "SELECT count(*) FROM letter.memberships WHERE user_id = %s", (DAVE,))[0][0] == 2   # org_member, editor
    assert truth(seeded, "SELECT letter.forget_user(%s)", (DAVE,))[0][0] == 2
    assert dave.execute(Q).fetchall() == []
    assert dave.execute("SELECT count(*) FROM orgs").fetchone()[0] == 0
    # what needs no membership stays: any signed-in user sees who exists
    assert dave.execute("SELECT count(*) FROM users").fetchone()[0] == 4
    # his rows in the application's tables are the application's to clean up
    assert truth(seeded, "SELECT count(*) FROM team_members WHERE user_id = %s", (DAVE,))[0][0] == 1


def test_the_app_cannot_touch_memberships(app):
    for stmt in ("INSERT INTO letter.memberships (role, user_id) VALUES ('owner', 'x')",
                 "DELETE FROM letter.memberships",
                 "SELECT count(*) FROM letter.memberships",
                 "SELECT count(*) FROM letter.grants"):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute(stmt)

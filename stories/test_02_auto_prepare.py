"""Story 2 — Auto-prepared statements across users.

As a driver, I prepare the same statement after five executions and
reuse it. (plan/21 §2.2 — 17 H5.4/5.5 through a real driver.)
"""
import pytest
import psycopg

from helpers import ALICE, BOB, CAROL, ALPHA, as_user, col, seed_basic


@pytest.fixture(scope="module")
def seeded(app_rules):
    seed_basic(app_rules)
    return app_rules


Q = "SELECT name, budget FROM projects ORDER BY name"


def prepared_count(conn):
    return conn.execute("SELECT count(*) FROM pg_prepared_statements").fetchone()[0]


def run_n(conn, n):
    for _ in range(n):
        out = conn.execute(Q).fetchall()
    return out


def test_default_threshold_prepares_and_the_next_user_gets_their_rows(app, seeded):
    """psycopg prepares a statement once it has run prepare_threshold
    (5) times. Eight runs as Alice, then the prepared plan as Bob."""
    assert app.prepare_threshold == 5
    with as_user(app, ALICE):
        assert run_n(app, 8) == [("Alpha", 1000)]
    assert prepared_count(app) >= 1
    with as_user(app, BOB):
        assert app.execute(Q).fetchall() == [("Beta", 2000)]
    with as_user(app, CAROL):                      # viewer: name and status only
        assert app.execute(Q).fetchall() == [("Alpha", None)]


def test_prepare_always_and_forced_generic_plans(story_db, seeded):
    """prepare_threshold=0 prepares everything; force_generic_plan makes
    the server reuse one generic plan for every execution."""
    from conftest import _conninfo
    with psycopg.connect(_conninfo(story_db, "story_app"), autocommit=True,
                         prepare_threshold=0) as conn:
        conn.execute("SET plan_cache_mode = force_generic_plan")
        with as_user(conn, ALICE):
            assert run_n(conn, 3) == [("Alpha", 1000)]
        with as_user(conn, BOB):
            assert run_n(conn, 3) == [("Beta", 2000)]
        with as_user(conn, CAROL):
            assert run_n(conn, 3) == [("Alpha", None)]
        with pytest.raises(psycopg.Error):
            conn.execute(Q)                        # no user: the generic plan errors too


def test_a_grant_added_meanwhile_reaches_a_prepared_statement(app, seeded):
    """Carol's prepared statement shows budget as NULL; the admin grants
    viewers the budget on another connection; the very next execution of
    the same prepared statement shows it. Then revoked, then hidden."""
    with as_user(app, CAROL):
        assert run_n(app, 8) == [("Alpha", None)]
        seeded.execute("SELECT letter.grant_scoped('select', 'public.projects', 'viewer', ARRAY['budget'], 'public.projects')")
        assert app.execute(Q).fetchall() == [("Alpha", 1000)]
        seeded.execute("SELECT letter.revoke_scoped('select', 'public.projects', 'viewer', ARRAY['budget'], 'public.projects')")
        assert app.execute(Q).fetchall() == [("Alpha", None)]


def test_a_membership_change_meanwhile_reaches_a_prepared_statement(app, seeded):
    """Bob is made viewer on Alpha through team_members while his prepared
    statement is warm; the next execution shows Alpha too. Removed again,
    it disappears."""
    with as_user(app, BOB):
        assert run_n(app, 8) == [("Beta", 2000)]
        seeded.execute("INSERT INTO team_members (project_id, user_id, role) VALUES (%s, %s, 'viewer')", (ALPHA, BOB))
        assert app.execute(Q).fetchall() == [("Alpha", None), ("Beta", 2000)]
        seeded.execute("DELETE FROM team_members WHERE project_id = %s AND user_id = %s", (ALPHA, BOB))
        assert app.execute(Q).fetchall() == [("Beta", 2000)]


def test_plpgsql_function_plan_cache(app, seeded):
    """A PL/pgSQL function caches its plans across calls in a session:
    called as Alice then as Bob, it returns each user's rows."""
    seeded.execute("""
        CREATE OR REPLACE FUNCTION my_project_names() RETURNS SETOF text LANGUAGE plpgsql AS $$
        BEGIN RETURN QUERY SELECT name FROM projects ORDER BY name; END $$""")
    seeded.execute("GRANT EXECUTE ON FUNCTION my_project_names() TO story_app")
    with as_user(app, ALICE):
        for _ in range(3):
            assert col(app, "SELECT my_project_names()") == ["Alpha"]
    with as_user(app, BOB):
        assert col(app, "SELECT my_project_names()") == ["Beta"]
    with pytest.raises(psycopg.Error):
        col(app, "SELECT my_project_names()")

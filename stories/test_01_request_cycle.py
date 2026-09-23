"""Story 1 — The request cycle on a pooled connection.

As a web app, I set the user once per request on a connection I do not
own. (plan/21 §2.1)

The recipe this story establishes:
  - per request: set letter.user_id on entry, RESET on exit whatever
    happens (helpers.as_user), or SET LOCAL inside the request's
    transaction so that COMMIT/ROLLBACK clears it;
  - a pool that resets connections on return (psycopg_pool's `reset`
    hook, or DISCARD ALL) as a second line of defence;
  - under pgbouncer in transaction mode (not installed here, D4): SET
    LOCAL only, never SET — a session-level SET would follow the server
    connection to the next client.
"""
import pytest
import psycopg
from psycopg_pool import ConnectionPool

from helpers import ALICE, BOB, CAROL, as_user, col, request, seed_basic, truth, unset_user


@pytest.fixture(scope="module")
def seeded(app_rules):
    seed_basic(app_rules)
    return app_rules


@pytest.fixture(scope="module")
def one_conn_pool(story_db, seeded):
    """A pool with a single physical connection, so every request in the
    story shares it — the worst case for state leaking between users."""
    from conftest import _conninfo
    pool = ConnectionPool(_conninfo(story_db, "story_app"), min_size=1, max_size=1,
                          kwargs={"autocommit": True}, open=True)
    yield pool
    pool.close()


def projects(conn):
    return col(conn, "SELECT name FROM projects ORDER BY name")


def pid(conn):
    return conn.execute("SELECT pg_backend_pid()").fetchone()[0]


def test_consecutive_requests_share_a_connection_and_not_a_user(one_conn_pool, seeded):
    """Alice's request, then Bob's, then Carol's on the same backend: each
    sees exactly their projects, as ground truth says."""
    pids = set()
    for user, expected in ((ALICE, ["Alpha"]), (BOB, ["Beta"]), (CAROL, ["Alpha"])):
        seen = request(one_conn_pool, user, lambda c: (pids.add(pid(c)), projects(c))[1])
        assert seen == expected
    assert len(pids) == 1, "the story needs every request on one physical connection"
    assert truth(seeded, "SELECT count(*) FROM projects")[0][0] == 2


def test_request_that_fails_before_setting_the_user(one_conn_pool):
    """A handler that raises before SET leaves nothing behind: the next
    request that forgets to set a user gets an error, not Alice."""
    request(one_conn_pool, ALICE, projects)                      # a normal request first
    with pytest.raises(RuntimeError):
        with one_conn_pool.connection():
            raise RuntimeError("boom before SET")
    with one_conn_pool.connection() as conn:                      # forgot to set the user
        with pytest.raises(psycopg.Error) as e:
            projects(conn)
        assert unset_user(e.value)


def test_forgotten_reset_is_the_apps_bug_and_a_pool_reset_hook_closes_it(story_db, seeded):
    """letter cannot tell a request boundary from a statement boundary:
    a handler that SETs and never RESETs leaves the user on the connection
    for the next borrower. psycopg_pool's reset hook (or DISCARD ALL) is
    the second line of defence."""
    from conftest import _conninfo

    def naive_handler(conn):                      # SET without RESET
        conn.execute("SELECT set_config('letter.user_id', %s, false)", (ALICE,))
        return projects(conn)

    with ConnectionPool(_conninfo(story_db, "story_app"), min_size=1, max_size=1,
                        kwargs={"autocommit": True}, open=True) as pool:
        with pool.connection() as conn:
            assert naive_handler(conn) == ["Alpha"]
        with pool.connection() as conn:           # the next request inherits Alice
            assert projects(conn) == ["Alpha"]

    def reset(conn):
        conn.execute("RESET letter.user_id")

    with ConnectionPool(_conninfo(story_db, "story_app"), min_size=1, max_size=1,
                        kwargs={"autocommit": True}, reset=reset, open=True) as pool:
        with pool.connection() as conn:
            assert naive_handler(conn) == ["Alpha"]
        with pool.connection() as conn:
            with pytest.raises(psycopg.Error) as e:
                projects(conn)
            assert unset_user(e.value)


def test_set_local_is_scoped_to_the_transaction(app, seeded):
    """SET LOCAL inside the request's transaction is enough, and is gone
    after COMMIT and after ROLLBACK."""
    with app.transaction():
        app.execute("SELECT set_config('letter.user_id', %s, true)", (BOB,))
        assert projects(app) == ["Beta"]
    with pytest.raises(psycopg.Error) as e:
        projects(app)
    assert unset_user(e.value)
    with pytest.raises(ZeroDivisionError):
        with app.transaction():
            app.execute("SELECT set_config('letter.user_id', %s, true)", (BOB,))
            assert projects(app) == ["Beta"]
            1 / 0
    with pytest.raises(psycopg.Error):
        projects(app)


def test_a_session_that_never_calls_letter_is_enforced(story_db, seeded):
    """A fresh connection whose first statements are a plain SET and a
    plain SELECT: the hook is there (session_preload_libraries on the
    database; the app role may not even SHOW it), so the SELECT is
    redacted — Bob does not see Alpha — and without a user it errors
    rather than returning everything. letter.enforcing() is the start-up
    probe an application can make with no more than USAGE on the schema."""
    from conftest import _conninfo
    with psycopg.connect(_conninfo(story_db, "story_app"), autocommit=True) as conn:
        assert conn.execute("SELECT letter.enforcing()").fetchone()[0] is True   # the start-up probe
        with pytest.raises(psycopg.Error) as e:
            projects(conn)
        assert unset_user(e.value)
    with psycopg.connect(_conninfo(story_db, "story_app"), autocommit=True) as conn:
        with as_user(conn, BOB):
            assert projects(conn) == ["Beta"]
            assert col(conn, "SELECT budget FROM projects ORDER BY name") == [2000]


def test_identity_from_a_proxys_claims(app, seeded):
    """Behind PostgREST or Supabase the proxy has verified the JWT and exposes
    its claims as request.jwt.claims; letter.user_from_claims() as the
    pre-request function sets the identity for the transaction — and a
    request with no subject stays anonymous."""
    with app.transaction():
        app.execute("SELECT set_config('request.jwt.claims', %s, true)", ('{"role": "authenticated", "sub": "%s"}' % BOB,))
        assert app.execute("SELECT letter.user_from_claims()").fetchone()[0] == BOB
        assert projects(app) == ["Beta"]
    with pytest.raises(psycopg.Error) as e:                        # gone with the transaction
        projects(app)
    assert unset_user(e.value)
    with app.transaction():
        app.execute("SELECT set_config('request.jwt.claims', %s, true)", ('{"role": "anon"}',))
        assert app.execute("SELECT letter.user_from_claims()").fetchone()[0] is None
        with pytest.raises(psycopg.Error) as e:
            projects(app)
        assert unset_user(e.value)

"""Helpers for the user stories (plan/21). Black-box only: the public API,
through a driver, the way an application would use it."""
import contextlib
import pathlib

import psycopg

HERE = pathlib.Path(__file__).parent


@contextlib.contextmanager
def as_user(conn, user_id):
    """Run a block as an end user, the way a request handler does: set
    letter.user_id on entry, reset it on the way out, whatever happened."""
    conn.execute("SELECT set_config('letter.user_id', %s, false)", (user_id,))
    try:
        yield conn
    finally:
        conn.execute("RESET letter.user_id")


def request(pool, user_id, fn):
    """Borrow a pooled connection, run fn(conn) as user_id, return the
    connection to the pool. One web request."""
    with pool.connection() as conn:
        with as_user(conn, user_id):
            return fn(conn)


def rows(conn, query, params=None):
    """Fetch all rows of a query as a list of tuples."""
    return conn.execute(query, params).fetchall()


def col(conn, query, params=None):
    """Fetch the first column of every row, as a list."""
    return [r[0] for r in rows(conn, query, params)]


def truth(admin, query, params=None):
    """The same query through the admin connection (letter.bypass on): the
    ground truth a story compares the application's view against."""
    return rows(admin, query, params)


def apply_sql(conn, path):
    """Run a file of SQL statements (a migration, the app schema)."""
    conn.execute(pathlib.Path(path).read_text())


def denied(exc):
    """True if an exception is letter refusing a write: SQLSTATE 42501 with
    the letter: prefix."""
    return isinstance(exc, psycopg.errors.InsufficientPrivilege) and str(exc).startswith("letter:")


# ---------------------------------------------------------------- the story cast
ALICE = "a0000000-0000-0000-0000-000000000001"   # editor @ Alpha
BOB = "a0000000-0000-0000-0000-000000000002"     # editor @ Beta
CAROL = "a0000000-0000-0000-0000-000000000003"   # viewer @ Alpha
DAVE = "a0000000-0000-0000-0000-000000000004"    # signs up during the stories
ERIN = "a0000000-0000-0000-0000-000000000005"    # reviewer @ Alpha (story 5)
EVE = "a0000000-0000-0000-0000-000000000006"     # the auditor (story 6)
ACME = "b0000000-0000-0000-0000-000000000001"
ALPHA = "c0000000-0000-0000-0000-000000000001"
BETA = "c0000000-0000-0000-0000-000000000002"


def seed_basic(admin):
    """Acme (Alice's org), with projects Alpha (Alice's) and Beta (Bob's);
    Alice also edits Alpha, Bob edits Beta, Carol views Alpha. Run as
    story_admin after app_rules: the rules confer the memberships."""
    admin.execute("INSERT INTO users (id, name, email) VALUES "
                  "(%s, 'Alice', 'alice@example.com'), (%s, 'Bob', 'bob@example.com'), "
                  "(%s, 'Carol', 'carol@example.com')", (ALICE, BOB, CAROL))
    admin.execute("INSERT INTO orgs (id, owner_id, name) VALUES (%s, %s, 'Acme')", (ACME, ALICE))
    admin.execute("INSERT INTO projects (id, org_id, owner_id, name, budget) VALUES "
                  "(%s, %s, %s, 'Alpha', 1000), (%s, %s, %s, 'Beta', 2000)",
                  (ALPHA, ACME, ALICE, BETA, ACME, BOB))
    admin.execute("INSERT INTO tasks (project_id, title) VALUES "
                  "(%s, 'Alpha task 1'), (%s, 'Alpha task 2'), (%s, 'Beta task 1')", (ALPHA, ALPHA, BETA))
    admin.execute("INSERT INTO team_members (project_id, user_id, role) VALUES "
                  "(%s, %s, 'editor'), (%s, %s, 'editor'), (%s, %s, 'viewer')",
                  (ALPHA, ALICE, BETA, BOB, ALPHA, CAROL))


def unset_user(exc):
    """True if an exception is letter refusing because no user is set."""
    return isinstance(exc, psycopg.errors.InsufficientPrivilege) and "letter.user_id is not set" in str(exc)


def expected_view(app, admin, table, pk="id"):
    """What SELECT * should return for the current app user, built only from
    the public API: every row of the truth for which visible_columns() is
    not NULL, with the columns it does not list set to None. Compare with
    actual_view()."""
    cols = [c for (c,) in admin.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = 'public' AND table_name = %s ORDER BY ordinal_position", (table,))]
    out = []
    for row in admin.execute(f"SELECT * FROM {table} ORDER BY {pk}"):
        r = dict(zip(cols, row))
        # from a driver the key needs a cast: the parameter is anyelement (FINDINGS.md #8)
        vc = app.execute("SELECT letter.visible_columns(%s, %s::text)",
                         (f"public.{table}", str(r[pk]))).fetchone()[0]
        if vc is None:
            continue
        out.append(tuple(r[c] if c in vc else None for c in cols))
    return out


def actual_view(app, table, pk="id"):
    return app.execute(f"SELECT * FROM {table} ORDER BY {pk}").fetchall()

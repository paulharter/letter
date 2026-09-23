"""One database per story module, set up the way the README says a
deployment looks (plan/21 D3):

  - the application connects as story_app: no letter.bypass, no privileges
    on letter's tables, never a superuser;
  - migrations and ground truth use story_admin: a superuser (configuration
    is a superuser's, D9) with letter.bypass on by ALTER ROLE, owner of the
    application tables;
  - the database preloads letter for every session
    (session_preload_libraries), so a session that never calls a letter
    function is still enforced.

LETTER_TEST_DSN (default "dbname=postgres") must connect as a superuser.
LETTER_STORY_KEEP=1 keeps the databases for inspection.
"""
import os
import pathlib

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo
from psycopg_pool import ConnectionPool

SUPER_DSN = os.environ.get("LETTER_TEST_DSN", "dbname=postgres")
PG_BIN = os.environ.get("LETTER_PG_BIN", "/opt/homebrew/opt/postgresql@17/bin")   # pg_dump, psql (story 8)
PASSWORD = "story"
HERE = pathlib.Path(__file__).parent


def _db_name(request):
    return "letter_story_" + request.module.__name__.removeprefix("test_")


def _conninfo(dbname, user=None):
    kwargs = {"dbname": dbname}
    if user:
        kwargs.update(user=user, password=PASSWORD)
    return make_conninfo(SUPER_DSN, **kwargs)


@pytest.fixture(scope="session", autouse=True)
def story_roles():
    """The two roles are cluster-wide. Drop them when the session ends so
    they do not show up elsewhere (letter.check_health() lists roles with
    bypass on by default)."""
    yield
    if os.environ.get("LETTER_STORY_KEEP"):
        return
    with psycopg.connect(SUPER_DSN, autocommit=True) as su:
        for role in ("story_app", "story_admin"):
            try:
                su.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
            except psycopg.Error as e:            # owns something in a kept database
                print(f"story roles: could not drop {role}: {e}")


@pytest.fixture(scope="module")
def story_db(request):
    """The module's database: created fresh, extension installed, roles and
    privileges as the deployment model says. Yields its name."""
    name = _db_name(request)
    ident = sql.Identifier(name)
    with psycopg.connect(SUPER_DSN, autocommit=True) as su:
        su.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(ident))
        su.execute(sql.SQL("CREATE DATABASE {}").format(ident))
        # the deployment recipe: every session in this database loads letter
        su.execute(sql.SQL("ALTER DATABASE {} SET session_preload_libraries = 'letter'").format(ident))
        for role, opts in (("story_app", ""), ("story_admin", " SUPERUSER")):   # configuration is a superuser's (D9)
            if su.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone() is None:
                su.execute(sql.SQL("CREATE ROLE {} LOGIN" + opts + " PASSWORD {}").format(
                    sql.Identifier(role), sql.Literal(PASSWORD)))
        su.execute("ALTER ROLE story_admin SET letter.bypass = on")     # README "Deployment model"
        su.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO story_app").format(ident))
        su.execute(sql.SQL("GRANT CREATE, CONNECT ON DATABASE {} TO story_admin").format(ident))

    with psycopg.connect(_conninfo(name), autocommit=True) as su:
        su.execute("CREATE EXTENSION letter")
        # the app needs USAGE to call letter.user_id() and visible_columns(), nothing else
        su.execute("GRANT USAGE ON SCHEMA letter TO story_app")
        su.execute("REVOKE ALL ON ALL TABLES IN SCHEMA letter FROM story_app, PUBLIC")   # README "Default deny"

    yield name

    if not os.environ.get("LETTER_STORY_KEEP"):
        with psycopg.connect(SUPER_DSN, autocommit=True) as su:
            su.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(ident))
            su.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name + "_copy")))


@pytest.fixture(scope="module")
def admin(story_db):
    """The migrator / ground-truth connection: story_admin, bypass on."""
    with psycopg.connect(_conninfo(story_db, "story_admin"), autocommit=True) as conn:
        yield conn


@pytest.fixture
def app(story_db):
    """One application connection: story_app, autocommit, no user set."""
    with psycopg.connect(_conninfo(story_db, "story_app"), autocommit=True) as conn:
        yield conn


@pytest.fixture(scope="module")
def app_pool(story_db):
    """The application's connection pool: two physical connections, so
    consecutive requests share them."""
    pool = ConnectionPool(_conninfo(story_db, "story_app"), min_size=2, max_size=2,
                          kwargs={"autocommit": True}, open=True)
    yield pool
    pool.close()


@pytest.fixture(scope="module")
def app_schema(admin):
    """The story application's tables, owned by story_admin, readable and
    writable by story_app at the SQL level — letter decides the rest."""
    admin.execute((HERE / "schema" / "app.sql").read_text())
    return admin


@pytest.fixture(scope="module")
def app_rules(app_schema):
    """The application's membership rules and grants."""
    app_schema.execute((HERE / "schema" / "app_rules.sql").read_text())
    return app_schema


def deploy(dbname, su):
    """The per-database deployment steps that are not data and so not in a
    dump: preload letter for every session, let the app role connect and
    call letter's functions (story 8 re-applies them to a restored copy)."""
    ident = sql.Identifier(dbname)
    su.execute(sql.SQL("ALTER DATABASE {} SET session_preload_libraries = 'letter'").format(ident))
    su.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO story_app").format(ident))
    with psycopg.connect(_conninfo(dbname), autocommit=True) as db:
        db.execute("GRANT USAGE ON SCHEMA letter TO story_app")
        db.execute("REVOKE ALL ON ALL TABLES IN SCHEMA letter FROM story_app, PUBLIC")

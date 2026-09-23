"""Story 8 — Dump and restore.

As the operator, I restore last night's dump and everyone sees what they
saw. (plan/21 §2.8) pg_dump as story_admin; restore with the README's
options; then without them, to keep the README true.
"""
import os
import shutil
import subprocess

import pytest
import psycopg
from psycopg.conninfo import conninfo_to_dict

from helpers import ALICE, BOB, CAROL, as_user, col, seed_basic, truth

pytestmark = pytest.mark.skipif(
    not os.path.exists(os.path.join(os.environ.get("LETTER_PG_BIN", "/opt/homebrew/opt/postgresql@17/bin"), "pg_dump")),
    reason="pg_dump not found: set LETTER_PG_BIN")


def pg(cmd, *args, env=None):
    from conftest import PG_BIN, SUPER_DSN
    d = conninfo_to_dict(SUPER_DSN)
    conn_args = []
    for key, flag in (("host", "-h"), ("port", "-p")):
        if d.get(key):
            conn_args += [flag, str(d[key])]
    full_env = dict(os.environ, **(env or {}))
    return subprocess.run([os.path.join(PG_BIN, cmd), *conn_args, *args],
                          capture_output=True, text=True, env=full_env)


@pytest.fixture(scope="module")
def seeded(app_rules):
    seed_basic(app_rules)
    app_rules.execute("INSERT INTO tasks (project_id, title) SELECT id, name || ' extra' FROM projects")
    return app_rules


@pytest.fixture(scope="module")
def dump(story_db, seeded, tmp_path_factory):
    path = tmp_path_factory.mktemp("dump") / "letter.sql"
    r = pg("pg_dump", "-U", "story_admin", "-d", story_db, "-f", str(path), env={"PGPASSWORD": "story"})
    assert r.returncode == 0, r.stderr
    text = path.read_text()
    assert "CREATE EXTENSION IF NOT EXISTS letter" in text
    assert "COPY letter.grants" in text and "COPY letter.memberships" in text
    return path


def views(dbname):
    """Each user's view of the projects, through the app role."""
    from conftest import _conninfo
    out = {}
    with psycopg.connect(_conninfo(dbname, "story_app"), autocommit=True) as app:
        for user in (ALICE, BOB, CAROL):
            with as_user(app, user):
                out[user] = app.execute("SELECT name, budget FROM projects ORDER BY name").fetchall()
                out[user + "/tasks"] = app.execute("SELECT count(*) FROM tasks").fetchone()[0]
    return out


def test_restore_with_the_documented_options(story_db, seeded, dump):
    from conftest import SUPER_DSN, deploy
    copy = story_db + "_copy"
    with psycopg.connect(SUPER_DSN, autocommit=True) as su:
        su.execute(f'DROP DATABASE IF EXISTS "{copy}" WITH (FORCE)')
        su.execute(f'CREATE DATABASE "{copy}"')
    r = pg("psql", "-X", "-v", "ON_ERROR_STOP=1", "-d", copy, "-f", str(dump),
           env={"PGOPTIONS": "-c letter.bypass=on -c session_replication_role=replica"})
    assert r.returncode == 0, r.stderr
    with psycopg.connect(SUPER_DSN, autocommit=True) as su:
        deploy(copy, su)                          # not data: the per-database deployment steps
    assert views(copy) == views(story_db)
    with psycopg.connect(SUPER_DSN.replace("dbname=postgres", f"dbname={copy}"), autocommit=True) as su:
        assert truth(su, "SELECT count(*) FROM letter.memberships")[0][0] == truth(seeded, "SELECT count(*) FROM letter.memberships")[0][0]
        assert [r for r in su.execute("SELECT severity FROM letter.check_health()") if r[0] == "error"] == []


def test_restore_without_the_options_stops_where_the_readme_says(story_db, dump):
    from conftest import SUPER_DSN
    copy = story_db + "_copy"
    with psycopg.connect(SUPER_DSN, autocommit=True) as su:
        su.execute(f'DROP DATABASE IF EXISTS "{copy}" WITH (FORCE)')
        su.execute(f'CREATE DATABASE "{copy}"')
    r = pg("psql", "-X", "-v", "ON_ERROR_STOP=1", "-d", copy, "-f", str(dump))
    assert r.returncode != 0
    assert "letter:" in r.stderr, r.stderr
    # replica alone: the COPY into a granted table is refused
    with psycopg.connect(SUPER_DSN, autocommit=True) as su:
        su.execute(f'DROP DATABASE IF EXISTS "{copy}" WITH (FORCE)')
        su.execute(f'CREATE DATABASE "{copy}"')
    r = pg("psql", "-X", "-v", "ON_ERROR_STOP=1", "-d", copy, "-f", str(dump),
           env={"PGOPTIONS": "-c session_replication_role=replica"})
    assert r.returncode != 0 and "letter:" in r.stderr, r.stderr

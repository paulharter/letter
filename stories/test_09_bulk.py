"""Story 9 — Bulk and background jobs.

As a job, I move data in bulk without a browser in the loop. (plan/21 §2.9)
COPY in both directions, INSERT … SELECT, UPDATE … FROM, an upsert, and
TRUNCATE; a timing for the trigger path goes to the log, not to an assert.
"""
import time

import pytest
import psycopg

from helpers import ALICE, BOB, CAROL, ALPHA, BETA, as_user, col, denied, refused, rows, seed_basic, truth


@pytest.fixture(scope="module")
def seeded(app_rules):
    seed_basic(app_rules)
    return app_rules


def test_copy_from_needs_an_insert_grant_and_the_rows_must_be_yours(seeded, app):
    """COPY FROM goes through the row triggers: Alice loads tasks into Alpha;
    a file with a Beta row fails as a whole; Carol (viewer) cannot load at all."""
    with as_user(app, ALICE):
        with app.cursor().copy("COPY tasks (project_id, title) FROM STDIN") as cp:
            cp.write_row((ALPHA, "bulk 1"))
            cp.write_row((ALPHA, "bulk 2"))
        assert col(app, "SELECT title FROM tasks WHERE title LIKE 'bulk%' ORDER BY title") == ["bulk 1", "bulk 2"]
        with pytest.raises(psycopg.Error) as e:
            with app.cursor().copy("COPY tasks (project_id, title) FROM STDIN") as cp:
                cp.write_row((ALPHA, "bulk 3"))
                cp.write_row((BETA, "not mine"))
        assert denied(e.value)
    assert truth(seeded, "SELECT count(*) FROM tasks WHERE title IN ('bulk 3', 'not mine')")[0][0] == 0
    with as_user(app, CAROL):
        with pytest.raises(psycopg.Error) as e:
            with app.cursor().copy("COPY tasks (project_id, title) FROM STDIN") as cp:
                cp.write_row((ALPHA, "viewer"))
        assert denied(e.value)


def test_copy_to_is_refused_but_copy_select_is_redacted(seeded, app):
    with as_user(app, BOB):
        with pytest.raises(psycopg.Error) as e:
            with app.cursor().copy("COPY tasks TO STDOUT") as cp:
                list(cp)
        assert refused(e.value) and "COPY (SELECT" in str(e.value)     # 0A000, with the way out in the hint
        with app.cursor().copy("COPY (SELECT title FROM tasks ORDER BY title) TO STDOUT") as cp:
            lines = [bytes(l).decode().strip() for l in cp]
        assert lines == ["Beta task 1"]


def test_insert_select_and_update_from_see_only_your_rows(seeded, app):
    with as_user(app, ALICE):
        n = app.execute("INSERT INTO tasks (project_id, title) SELECT project_id, title || ' (copy)' FROM tasks WHERE title LIKE 'Alpha task%'").rowcount
        assert n == 2
        n = app.execute("INSERT INTO tasks (project_id, title) SELECT project_id, title || ' (copy)' FROM tasks WHERE title LIKE 'Beta%'").rowcount
        assert n == 0                                                     # Beta's tasks are not there
        n = app.execute("UPDATE tasks t SET estimate = 5 FROM projects p WHERE p.id = t.project_id AND p.name = 'Alpha'").rowcount
        assert n == truth(seeded, "SELECT count(*) FROM tasks WHERE project_id = %s", (ALPHA,))[0][0]
        n = app.execute("UPDATE tasks t SET estimate = 5 FROM projects p WHERE p.id = t.project_id AND p.name = 'Beta'").rowcount
        assert n == 0
    assert truth(seeded, "SELECT count(*) FROM tasks WHERE estimate = 5 AND project_id = %s", (BETA,))[0][0] == 0


def test_upsert_on_a_membership_source(seeded, app):
    """An owner re-inviting an existing member: ON CONFLICT DO UPDATE reads
    the existing row (visible to the owner) and the rule follows the role."""
    with as_user(app, ALICE):
        app.execute("INSERT INTO team_members (project_id, user_id, role) VALUES (%s, %s, 'editor') "
                    "ON CONFLICT (project_id, user_id) DO UPDATE SET role = EXCLUDED.role", (ALPHA, CAROL))
    with as_user(app, CAROL):
        assert rows(app, "SELECT name, budget FROM projects") == [("Alpha", 1000)]    # editor now
    with as_user(app, BOB):                                                            # not Alpha's owner: invisible, refused as an insert
        with pytest.raises(psycopg.Error) as e:
            app.execute("INSERT INTO team_members (project_id, user_id, role) VALUES (%s, %s, 'viewer') "
                        "ON CONFLICT (project_id, user_id) DO UPDATE SET role = EXCLUDED.role", (ALPHA, CAROL))
        assert denied(e.value)


def test_truncate_needs_bypass(seeded, app):
    with as_user(app, ALICE):
        with pytest.raises(psycopg.Error) as e:
            app.execute("TRUNCATE tasks")
        assert denied(e.value)
    assert truth(seeded, "SELECT count(*) FROM tasks")[0][0] > 0


def test_trigger_path_timing_for_the_log(seeded, app):
    """10k rows through COPY as an editor — the insert trigger runs per row.
    Recorded, not asserted."""
    n = 10_000
    with as_user(app, ALICE):
        t0 = time.perf_counter()
        with app.cursor().copy("COPY tasks (project_id, title) FROM STDIN") as cp:
            for i in range(n):
                cp.write_row((ALPHA, f"load {i}"))
        dt = time.perf_counter() - t0
    print(f"\nCOPY of {n} rows through the insert trigger: {dt:.2f}s ({n / dt:.0f} rows/s)")
    seeded.execute("DELETE FROM tasks WHERE title LIKE 'load %'")

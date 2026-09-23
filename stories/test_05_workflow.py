"""Story 5 — Authorship and workflow: the `if` story.

As an editor I may edit my own comments; a task moves draft → review → done
and never backwards. (plan/21 §2.5)
"""
import pytest
import psycopg

from helpers import ALICE, BOB, CAROL, ERIN, ALPHA, as_user, col, denied, seed_basic, truth


@pytest.fixture(scope="module")
def seeded(app_rules):
    seed_basic(app_rules)
    a = app_rules
    a.execute("INSERT INTO users (id, name, email) VALUES (%s, 'Erin', 'erin@example.com')", (ERIN,))
    a.execute("INSERT INTO team_members (project_id, user_id, role) VALUES (%s, %s, 'reviewer')", (ALPHA, ERIN))
    # Status moves by transition rules only: editors send to review, reviewers finish.
    a.execute("SELECT letter.revoke_scoped('update', 'public.tasks', 'editor', ARRAY['status'], 'public.projects')")
    a.execute("SELECT letter.grant_scoped('update', 'public.tasks', 'editor', ARRAY['status'], 'public.projects', "
              "if := 'old.status = ''draft'' AND new.status = ''review''')")
    a.execute("SELECT letter.grant_scoped('update', 'public.tasks', 'reviewer', ARRAY['status'], 'public.projects', "
              "if := 'old.status = ''review'' AND new.status = ''done''')")
    a.execute("SELECT letter.grant_scoped('select', 'public.tasks', 'reviewer', ARRAY['*'], 'public.projects')")
    # Comments: authors edit and delete their own, until reviewed; reviewers sign off others'.
    a.execute("SELECT letter.grant_scoped('update', 'public.comments', 'editor', ARRAY['body'], 'public.projects', ARRAY['task_id'], "
              "if := 'author_id = letter.user_id()::uuid AND reviewed_by IS NULL')")
    a.execute("SELECT letter.grant_scoped('delete', 'public.comments', 'editor', NULL, 'public.projects', ARRAY['task_id'], "
              "if := 'author_id = letter.user_id()::uuid')")
    a.execute("SELECT letter.grant_scoped('select', 'public.comments', 'reviewer', ARRAY['*'], 'public.projects', ARRAY['task_id'])")
    a.execute("SELECT letter.grant_scoped('fill', 'public.comments', 'reviewer', ARRAY['reviewed_by'], 'public.projects', ARRAY['task_id'], "
              "if := 'author_id <> letter.user_id()::uuid')")
    return a


def task(admin, title):
    return truth(admin, "SELECT id FROM tasks WHERE title = %s", (title,))[0][0]


def test_you_write_as_yourself(seeded, app):
    t = task(seeded, "Alpha task 1")
    with as_user(app, ALICE):
        with pytest.raises(psycopg.Error) as e:
            app.execute("INSERT INTO comments (task_id, author_id, body) VALUES (%s, %s, 'as carol')", (t, CAROL))
        assert denied(e.value)
        app.execute("INSERT INTO comments (task_id, author_id, body) VALUES (%s, %s, 'looks fine')", (t, ALICE))
    assert truth(seeded, "SELECT count(*) FROM comments")[0][0] == 1


def test_edit_and_delete_only_your_own(seeded, app):
    t = task(seeded, "Alpha task 1")
    seeded.execute("INSERT INTO comments (task_id, author_id, body) VALUES (%s, %s, 'erin says')", (t, ERIN))
    with as_user(app, ALICE):
        assert app.execute("UPDATE comments SET body = 'looks fine!' WHERE author_id = %s", (ALICE,)).rowcount == 1
        with pytest.raises(psycopg.Error) as e:   # she can see Erin's comment, so the refusal is loud
            app.execute("UPDATE comments SET body = 'x' WHERE author_id = %s", (ERIN,))
        assert denied(e.value)
        with pytest.raises(psycopg.Error) as e:
            app.execute("DELETE FROM comments WHERE author_id = %s", (ERIN,))
        assert denied(e.value)
    with as_user(app, BOB):                       # editor on Beta: Alpha's comments are not there at all
        assert app.execute("UPDATE comments SET body = 'x'").rowcount == 0
        assert app.execute("DELETE FROM comments").rowcount == 0
    assert col(seeded, "SELECT body FROM comments ORDER BY body") == ["erin says", "looks fine!"]


def test_review_signs_off_others_and_freezes_the_author(seeded, app):
    with as_user(app, ERIN):
        with pytest.raises(psycopg.Error) as e:   # not her own
            app.execute("UPDATE comments SET reviewed_by = %s WHERE author_id = %s", (ERIN, ERIN))
        assert denied(e.value)
        assert app.execute("UPDATE comments SET reviewed_by = %s WHERE author_id = %s", (ERIN, ALICE)).rowcount == 1
        with pytest.raises(psycopg.Error) as e:   # fill: only while NULL
            app.execute("UPDATE comments SET reviewed_by = %s WHERE author_id = %s", (CAROL, ALICE))
        assert denied(e.value)
    with as_user(app, ALICE):
        with pytest.raises(psycopg.Error) as e:   # reviewed: the if no longer holds
            app.execute("UPDATE comments SET body = 'too late' WHERE author_id = %s", (ALICE,))
        assert denied(e.value)
        assert app.execute("DELETE FROM comments WHERE author_id = %s", (ALICE,)).rowcount == 1   # deleting is still hers


@pytest.mark.parametrize("who,frm,to,ok", [
    (ALICE, "draft", "review", True),
    (ALICE, "review", "done", False),
    (ALICE, "draft", "done", False),
    (ERIN, "draft", "review", False),
    (ERIN, "review", "done", True),
    (ERIN, "done", "review", False),
    (ALICE, "done", "draft", False),
    (ERIN, "done", "draft", False),
])
def test_task_transitions(seeded, app, who, frm, to, ok):
    t = task(seeded, "Alpha task 2")
    seeded.execute("UPDATE tasks SET status = %s WHERE id = %s", (frm, t))
    with as_user(app, who):
        if ok:
            assert app.execute("UPDATE tasks SET status = %s WHERE id = %s", (to, t)).rowcount == 1
        else:
            with pytest.raises(psycopg.Error) as e:
                app.execute("UPDATE tasks SET status = %s WHERE id = %s", (to, t))
            assert denied(e.value)
    assert truth(seeded, "SELECT status FROM tasks WHERE id = %s", (t,))[0][0] == (to if ok else frm)


def test_invisible_rows_are_skipped_not_refused(seeded, app):
    t = task(seeded, "Alpha task 2")
    with as_user(app, BOB):
        assert app.execute("UPDATE tasks SET status = 'review' WHERE id = %s", (t,)).rowcount == 0

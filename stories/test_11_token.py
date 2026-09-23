"""Story 11 — Token identity.

As an application server, I hand letter the end user's JWT and nothing I
say about who the user is counts for anything. (plan/23 T4) The database
runs in token mode: letter.identity = 'token', the issuer's public key in
letter.jwt_keys, both set per database by the superuser (D4).
"""
import time

import jwt
import pytest
import psycopg
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from helpers import ALICE, BOB, col, seed_basic, unset_user

ISSUER = "https://issuer.test"


def pem(pub):
    return pub.public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo).decode()


@pytest.fixture(scope="module")
def issuer():
    """The identity provider: a key pair; only its public half reaches the database."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def token(key, sub, **claims):
    now = int(time.time())
    return jwt.encode({"iss": ISSUER, "aud": "letter", "sub": sub, "iat": now, "exp": now + 300, **claims},
                      key, algorithm="RS256")


@pytest.fixture(scope="module")
def token_mode(story_db, app_rules, issuer):
    """Configured per database, by the superuser, for every new session."""
    from conftest import SUPER_DSN
    seed_basic(app_rules)
    from psycopg import sql
    with psycopg.connect(SUPER_DSN, autocommit=True) as su:
        for setting, value in (("letter.identity", "token"), ("letter.jwt_issuer", ISSUER),
                               ("letter.jwt_audience", "letter"), ("letter.jwt_keys", pem(issuer.public_key()))):
            su.execute(sql.SQL("ALTER DATABASE {} SET {} = {}").format(       # ALTER … SET takes no parameters
                sql.Identifier(story_db), sql.SQL(setting), sql.Literal(value)))
    return issuer


@pytest.fixture
def conn(story_db, token_mode):
    from conftest import _conninfo
    with psycopg.connect(_conninfo(story_db, "story_app"), autocommit=True) as c:
        yield c


def projects(c):
    return col(c, "SELECT name FROM projects ORDER BY name")


def test_a_request_presents_a_token(conn, token_mode):
    with conn.transaction():
        assert conn.execute("SELECT letter.login(%s)", (token(token_mode, ALICE),)).fetchone()[0] == ALICE
        assert projects(conn) == ["Alpha"]
    with conn.transaction():
        conn.execute("SELECT letter.login(%s)", (token(token_mode, BOB),))
        assert projects(conn) == ["Beta"]
    with pytest.raises(psycopg.Error) as e:                    # nobody between requests
        projects(conn)
    assert unset_user(e.value)


def test_the_app_cannot_be_anyone(conn):
    """SET letter.user_id is ignored in token mode: no token, no user."""
    conn.execute("SELECT set_config('letter.user_id', %s, false)", (ALICE,))
    assert conn.execute("SELECT letter.user_id()").fetchone()[0] is None
    with pytest.raises(psycopg.Error) as e:
        projects(conn)
    assert unset_user(e.value)
    assert conn.execute("SELECT letter.enforcing()").fetchone()[0] is True


@pytest.mark.parametrize("make, reason", [
    (lambda k: token(rsa.generate_private_key(public_exponent=65537, key_size=2048), ALICE), "bad signature"),
    (lambda k: token(k, ALICE, exp=int(time.time()) - 600), "expired"),
    (lambda k: token(k, ALICE, iss="https://evil.test"), "wrong issuer"),
    (lambda k: token(k, ALICE, aud="other"), "wrong audience"),
    (lambda k: jwt.encode({"sub": ALICE, "exp": int(time.time()) + 300}, "shared", algorithm="HS256"), "not accepted"),
])
def test_rejected_tokens(conn, token_mode, make, reason):
    with pytest.raises(psycopg.errors.InvalidAuthorizationSpecification) as e:
        conn.execute("SELECT letter.login(%s)", (make(token_mode),))
    assert str(e.value).startswith("letter: token rejected:") and reason in str(e.value)
    with pytest.raises(psycopg.Error) as e:
        projects(conn)
    assert unset_user(e.value)


def test_session_identity_until_logout(conn, token_mode):
    conn.execute("SELECT letter.login(%s, false)", (token(token_mode, ALICE),))
    assert projects(conn) == ["Alpha"]
    assert projects(conn) == ["Alpha"]
    conn.execute("SELECT letter.logout()")
    with pytest.raises(psycopg.Error):
        projects(conn)


def test_health(story_db, token_mode):
    from conftest import SUPER_DSN
    with psycopg.connect(SUPER_DSN.replace("dbname=postgres", f"dbname={story_db}"), autocommit=True) as su:
        rows = su.execute("SELECT severity, object FROM letter.check_health()").fetchall()
    assert ("info", "letter.identity") in rows
    assert [r for r in rows if r[0] == "error"] == []

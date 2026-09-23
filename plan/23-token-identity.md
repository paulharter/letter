# Letter — Token identity: `letter.login(jwt)` and the claims recipe

Drafted 2026-09-23 from the last "Known gaps" entry of plan `21`: *the user is whoever
the application says*. Today `letter.user_id` is a session setting the application
role sets, so a bug or an injection in the application can be anyone. This plan gives
a deployment the choice of a stronger perimeter: the application presents the end
user's JWT, letter verifies it against the issuer's **public key**, and the identity
enforcement uses cannot be set any other way.

Decisions already taken (Paul, 2026-09-23): asymmetric keys only — no HMAC, so no
secret ever sits in the database; the option is optional, the setting-based identity
stays the default.

---

## 1. Two architectures, two steps

**A. A proxy that has already verified the token** (PostgREST, Supabase). The proxy
checks the signature and exposes the claims to SQL (`request.jwt.claims`), and calls a
pre-request function. Letter needs no cryptography here, only the identity set from
the verified claims, transaction-local:

```sql
CREATE FUNCTION letter.user_from_claims(claim text DEFAULT 'sub') RETURNS text …
-- reads current_setting('request.jwt.claims', true) ->> claim, set_config('letter.user_id', …, true)
```
`db-pre-request = "letter.user_from_claims"` in PostgREST's config. A recipe and a
ten-line function; step T1.

**B. An application server holding a database role.** The server passes the raw JWT
it received from the client:

```python
with conn.transaction():
    conn.execute("SELECT letter.login(%s)", (bearer_token,))
    ...
```
Letter verifies it and sets the identity for the transaction. Under `letter.identity =
'token'` a plain `SET letter.user_id` is ignored by enforcement, so the application can
only be someone the issuer signed a token for. Steps T2–T4.

## 2. Semantics

- **Algorithms:** `RS256`, `RS384`, `RS512` (RSA PKCS#1 v1.5), `ES256`, `ES384`
  (ECDSA), `EdDSA` (Ed25519). `none` and every HMAC algorithm are refused. The
  token's `alg` must match the configured key's type (an RSA key never verifies an
  `ES256` token — no algorithm confusion).
- **Keys:** `letter.jwt_keys` — one or more PEM public keys (`-----BEGIN PUBLIC
  KEY-----` blocks, concatenated) so a rotation can overlap: a token verifies if any
  configured key verifies it; a `kid` header, when present and when keys are given as
  `kid=…` prefixed blocks, selects the key. Superuser-only (`PGC_SUSET`), set per
  database with `ALTER DATABASE … SET`, reloadable. Nothing secret.
- **Checks:** signature; `exp` (required) and `nbf` (if present) against the clock with
  `letter.jwt_leeway` seconds (default 30); `iss` equals `letter.jwt_issuer` when set;
  `aud` contains `letter.jwt_audience` when set. The user id is the claim
  `letter.jwt_claim` (default `sub`), which must be a non-empty string.
- **`letter.login(token text, local boolean DEFAULT true) → text`** returns the user
  id it set. `local` (the default, pool-safe) binds the identity to the transaction;
  `false` to the session until `letter.logout()` or disconnect. Errors are one voice:
  `letter: token rejected: <reason>` — expired, bad signature, wrong issuer, … — with
  SQLSTATE 28000 (invalid_authorization_specification).
- **`letter.identity`** (`PGC_SUSET`, default `setting`): `setting` — the identity is
  `letter.user_id`, as today; `token` — the identity is what `login()` set, and the
  GUC is ignored by enforcement (a stray `SET letter.user_id` neither helps nor hurts).
  `letter.user_id()`, `letter._user_id()`, `letter.enforcing()` and the triggers all
  read through the one choke point (`get_current_user_id()` / the barrier's user
  function), which is where the mode is applied; the barrier, the built-in roles, the
  walker and `visible_columns()` are untouched.
- **Bypass** is unchanged: an admin role with `letter.bypass = on` needs no identity.
- **No network.** Letter never fetches a JWKS and never checks revocation; keys are
  configured, rotation is a reload with both keys present. Documented.
- **Without OpenSSL** (`USE_OPENSSL` unset at build time): `login()` errors "letter
  was built without OpenSSL"; everything else works.

## 3. Changes

- `letter.c`: GUCs `letter.identity`, `letter.jwt_keys`, `letter.jwt_issuer`,
  `letter.jwt_audience`, `letter.jwt_claim`, `letter.jwt_leeway`; base64url decoder;
  JWT split and header/claims parse with PostgreSQL's JSON parser; verification with
  OpenSSL `EVP_DigestVerify*` (RSA, ECDSA — DER ↔ raw r‖s conversion — and Ed25519);
  `letter_token_user` (backend-local) with a transaction callback to clear a local
  identity at commit/abort; `get_current_user_id()` and `letter_require_user()` consult
  `letter.identity`; `letter_login`, `letter_logout`, `letter_user_from_claims`.
- `sql/letter--0.1.sql`: the three functions; `letter.user_id()` becomes C-backed so
  it follows the mode.
- Makefile: `SHLIB_LINK += $(shell $(PG_CONFIG) --libs)`? — no: PGXS links against
  the server, which already carries OpenSSL when built with it; `#include
  <openssl/evp.h>` under `#ifdef USE_OPENSSL`.
- Tests: `test/sql/token.sql` — keys and tokens generated once by
  `test/token/make_tokens.py` (checked in with the PEMs: a test key pair per
  algorithm, tokens valid / expired / not-yet-valid / wrong issuer / wrong audience /
  wrong key / tampered payload / `alg: none` / HS256 with the public key as secret /
  RSA key vs ES256 token / no `sub` / two keys with `kid`); `login()` under each; the
  mode switch: with `identity = token` a `SET letter.user_id` changes nothing;
  `local` dies at `COMMIT`/`ROLLBACK`, session identity survives; `logout()`;
  `enforcing()` in token mode; `check_health()` reports the mode and an unparseable
  key. `hook_read`: a read enforced under a token identity.
- Stories: `test_01_request_cycle.py` gains a token variant (`pyjwt` +
  `cryptography` in the venv): a request presents a token, a forged one is rejected,
  an expired one is rejected, a `SET letter.user_id` under token mode does not
  impersonate; `test_11_postgrest.py` (or a case in story 1): the claims recipe with
  `request.jwt.claims` set by hand the way PostgREST sets it.
- README: "Identity" section — the two architectures, the config, the recipe; the
  gaps entry becomes the description of the two perimeters.

## 4. Steps

- [x] **T1** — `letter.user_from_claims()` and the PostgREST recipe; README *(2026-09-23: hook_read case 10, story 1 case)*.
- [x] **T2** — Verification core: GUCs, base64url, JSON, OpenSSL verify for RSA /
  ECDSA / Ed25519, key set with `kid`; `letter.login()` returning the user id and
  the token checks; `test/sql/token.sql` with generated fixtures *(2026-09-23)*.
- [x] **T3** — Identity mode: `letter.identity`, the backend-local identity and its
  transaction scope, `logout()`, the choke points, `enforcing()`, `check_health()` *(2026-09-23; token.sql §6)*.
- [x] **T4** — Stories and README; PG16 run *(2026-09-23; story 11, README "Identity")*.

## 5. Decisions

- **D1 — asymmetric only** *(Paul, 2026-09-23)*: RSA, ECDSA, Ed25519; HMAC and `none`
  refused.
- **D2 — optional; the setting-based identity stays the default** *(Paul)*.
- **D3 — transaction-local by default** *(Paul, 2026-09-23)*: `login()` binds the identity to
  the transaction unless told otherwise — the pool-safe form of plan `21` finding 3.
- **D4 — the mode is a superuser setting per database** *(Paul, 2026-09-23)*: an application
  cannot switch itself back to `setting` mode.
- **D5 — no JWKS, no revocation** *(Paul, 2026-09-23)*: keys are configured; the database makes
  no network calls.

## 6. Stop-and-discuss triggers

1. OpenSSL not available through PGXS on a platform we care about (Homebrew builds
   carry it; check the PG16 build too).
2. A claim layout an issuer uses that the `sub`-string assumption cannot express
   (numeric `sub`, nested claims) — configuration, not code, if simple.
3. Anything that makes the identity readable or settable by a route other than
   `login()` in token mode.

---

## 0. Status — resume here

**2026-09-23: COMPLETE — T1–T4; D1–D5 decided.** T3: `letter.identity` (enum, SUSET);
the token-only store (`letter_token_user`, TopMemoryContext) set by `login()` alone,
cleared at commit/abort/prepare when local and on the rollback of the savepoint it was
set in; `get_current_user_id()` is the one choke point and reads the store in token
mode; `letter.user_id()` is C-backed and follows; `logout()`; `check_health()` reports
token mode, empty keys in token mode (error) and a key that does not parse
(`letter._jwt_keys_check()`). T4: story 11 (`pyjwt`: a request presents a token, `SET
letter.user_id` is ignored in token mode, five rejections, session identity until
`logout()`, health); README "Identity" (the default, the proxy recipe, token mode).
19 C suites green on PG 16 and 17; 71 story tests green.

**T1 ✅, T2 ✅.** `letter.login(token, local DEFAULT true)` verifies against
`letter.jwt_keys` (PEM public keys, `kid=` lines for rotation), refuses `none` and HMAC
by name, matches the key type to the algorithm (an RSA key is never tried against an
ES256 token; a P-256 key never against ES384), checks `exp` (required), `nbf`, `iss`
and `aud` (string or list) when configured, with `letter.jwt_leeway`; the user comes
from `letter.jwt_claim` and must be a non-empty string. It sets `letter.user_id`
through `set_config_option` (`GUC_ACTION_LOCAL` or `SET`) — in T2 the identity is still
the setting; T3 adds the token-only store and `letter.identity`. Fixtures: 24 tokens
and 5 keys from `test/token/make_tokens.py` (pyjwt in the stories venv; the HMAC
confusion token built by hand since pyjwt refuses to), expiring in 2100;
`test/sql/token.sql` has 19 cases. `SHLIB_LINK += -lcrypto`. Note: `local DEFAULT true`
implements proposed D3 ahead of the ruling — trivial to flip. Next: D3–D5, then T3. `letter.user_from_claims(claim, setting)` sets the identity for the transaction from a proxy's verified claims, NULL and unset without a subject; README "Behind PostgREST or Supabase". D1, D2 decided; D3–D5 proposed. Next: T2 (the verification core).

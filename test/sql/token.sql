-- Test: token identity (plan/23 T2) — letter.login(jwt) verifies a JWT
-- against configured public keys and sets the user.
--
-- Tokens and keys are generated once by test/token/make_tokens.py (pyjwt);
-- the good tokens expire in 2100. alice is the subject throughout; the
-- issuer is https://issuer.test, the audience 'letter'.

CREATE EXTENSION letter;
\i test/token/fixtures.sql

\set VERBOSITY terse
-- Nothing configured: nothing verifies.
SELECT letter.login(:'rs256_ok');

SELECT set_config('letter.jwt_keys', :'key_rsa_a', false) IS NOT NULL AS keys_set;
SET letter.jwt_issuer = 'https://issuer.test';
SET letter.jwt_audience = 'letter';

-- ============================================================
-- 1. A good token, for the session and for a transaction.
-- ============================================================
SELECT letter.login(:'rs256_ok', false);
SELECT letter.user_id();
RESET letter.user_id;
BEGIN;
SELECT letter.login(:'rs256_ok');
SELECT letter.user_id();
COMMIT;
SELECT letter.user_id() IS NULL AS gone_with_the_transaction;

-- ============================================================
-- 2. Every way a token is rejected.
-- ============================================================
SELECT letter.login(:'rs256_expired');
SELECT letter.login(:'rs256_nbf_future');
SELECT letter.login(:'rs256_wrong_iss');
SELECT letter.login(:'rs256_wrong_aud');
SELECT letter.login(:'rs256_wrong_key');
SELECT letter.login(:'rs256_tampered');
SELECT letter.login(:'rs256_no_sub');
SELECT letter.login(:'rs256_numeric_sub');
SELECT letter.login(:'rs256_no_exp');
SELECT letter.login(:'none_alg');
SELECT letter.login(:'hs256_pubkey');
SELECT letter.login(:'es256_ok');            -- an RSA key never verifies an ES256 token
SELECT letter.login(:'garbage');
SELECT letter.login(:'two_parts');
SELECT letter.login('');
SELECT letter.user_id() IS NULL AS still_nobody;

-- ============================================================
-- 3. The checks are configuration: the audience as a list; issuer and
--    audience unchecked when unset; the user from another claim.
-- ============================================================
SELECT letter.login(:'rs256_aud_list');
RESET letter.jwt_issuer;
RESET letter.jwt_audience;
SELECT letter.login(:'rs256_wrong_iss');
SELECT letter.login(:'rs256_wrong_aud');
SET letter.jwt_claim = 'uid';
SELECT letter.login(:'rs256_uid_claim');
SELECT letter.login(:'rs256_ok');            -- has no uid claim
RESET letter.jwt_claim;

-- ============================================================
-- 4. Every accepted algorithm, with the whole key set; a key of the
--    wrong type is skipped, not tried.
-- ============================================================
SELECT set_config('letter.jwt_keys', :'key_all', false) IS NOT NULL AS keys_set;
SELECT letter.login(:'rs256_ok'), letter.login(:'rs384_ok'), letter.login(:'rs512_ok');
SELECT letter.login(:'es256_ok'), letter.login(:'es384_ok'), letter.login(:'eddsa_ok');
SELECT set_config('letter.jwt_keys', :'key_ec_p256', false) IS NOT NULL AS keys_set;
SELECT letter.login(:'rs256_ok');
SELECT letter.login(:'es384_ok');            -- P-256 key, P-384 token

-- ============================================================
-- 5. Key rotation: two keys, chosen by kid; an unknown kid is refused
--    rather than tried against everything.
-- ============================================================
SELECT set_config('letter.jwt_keys', :'key_kid', false) IS NOT NULL AS keys_set;
SELECT letter.login(:'rs256_kid_a'), letter.login(:'rs256_kid_b');
SELECT letter.login(:'rs256_kid_unknown');
SELECT letter.login(:'rs256_ok');            -- no kid: every key is tried

-- A key that is not a key.
SELECT set_config('letter.jwt_keys', E'-----BEGIN PUBLIC KEY-----\nnot a key\n-----END PUBLIC KEY-----', false) IS NOT NULL AS keys_set;
SELECT letter.login(:'rs256_ok');

-- ============================================================
-- 6. Token mode (plan/23 D4): the current user is what login() verified
--    and nothing else — SET letter.user_id neither helps nor hurts. Local
--    identities die with the transaction, or with a rolled-back savepoint;
--    a session identity lasts until logout(). Enforcement follows.
-- ============================================================
SELECT set_config('letter.jwt_keys', :'key_rsa_a', false) IS NOT NULL AS keys_set;
SET letter.bypass = on;
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes VALUES (1, 'for any signed-in user');
SELECT letter.grant_global('select', 'public.notes', 'any_user', ARRAY['*']);
RESET letter.bypass;
SET letter.identity = token;
SET letter.user_id = 'mallory';
SELECT letter.user_id() IS NULL AS setting_ignored;
SELECT count(*) FROM notes;                  -- nobody: an error, as ever
SELECT letter.login(:'rs256_ok', false);
SELECT letter.user_id();
SELECT body FROM notes;
SET letter.user_id = 'mallory';
SELECT letter.user_id() AS still_alice;
SELECT letter.logout();
SELECT letter.user_id() IS NULL AS logged_out;
BEGIN;
SELECT letter.login(:'rs256_ok');
SELECT letter.user_id();
SAVEPOINT s;
SELECT letter.login(:'rs256_uid_claim') IS NOT NULL AS relogged;   -- sub is alice here too
ROLLBACK TO s;
SELECT letter.user_id() IS NULL AS savepoint_undid_it;
SELECT letter.login(:'rs256_ok');
COMMIT;
SELECT letter.user_id() IS NULL AS gone_with_the_transaction;
BEGIN;
SELECT letter.login(:'rs256_ok');
ROLLBACK;
SELECT letter.user_id() IS NULL AS gone_with_the_rollback;
SELECT severity, object, message FROM letter.check_health() WHERE object LIKE 'letter.%' ORDER BY 1, 2;
SET letter.jwt_keys = '';
SELECT severity, object, message FROM letter.check_health() WHERE object LIKE 'letter.jwt%' ORDER BY 1, 2;
SET letter.user_id = 'mallory';
SELECT letter.user_id() IS NULL AS still_nobody_in_token_mode;
RESET letter.identity;
SELECT letter.user_id() AS setting_again;     -- the GUC is the identity again: mallory
\set VERBOSITY default

RESET letter.user_id;
DROP TABLE notes;
DROP EXTENSION letter CASCADE;

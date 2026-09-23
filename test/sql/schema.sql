-- Test: extension creates the letter schema and core tables

CREATE EXTENSION letter;
SET letter.enforce_reads = off;   -- this test is not about the read hook

CREATE TABLE t (id int PRIMARY KEY);

-- Verify schema exists
SELECT nspname FROM pg_namespace WHERE nspname = 'letter';

-- Verify the core tables (and the _membership_signal table) exist
SELECT tablename FROM pg_tables
    WHERE schemaname = 'letter'
    ORDER BY tablename;

-- The five data tables are registered for pg_dump (plan/18 D6); the
-- _membership_signal table is not.
SELECT e::regclass::text AS dumped
    FROM (SELECT unnest(extconfig) AS e FROM pg_extension WHERE extname = 'letter') x
    ORDER BY 1;

-- Verify memberships table columns
SELECT column_name, data_type FROM information_schema.columns
    WHERE table_schema = 'letter' AND table_name = 'memberships'
    ORDER BY ordinal_position;

-- Verify grants table columns
SELECT column_name, data_type FROM information_schema.columns
    WHERE table_schema = 'letter' AND table_name = 'grants'
    ORDER BY ordinal_position;

-- Verify membership_rules table columns
SELECT column_name, data_type FROM information_schema.columns
    WHERE table_schema = 'letter' AND table_name = 'membership_rules'
    ORDER BY ordinal_position;

-- Verify membership_sources table columns
SELECT column_name, data_type FROM information_schema.columns
    WHERE table_schema = 'letter' AND table_name = 'membership_sources'
    ORDER BY ordinal_position;

-- Verify user_tables columns (plan/24 B8)
SELECT column_name, data_type FROM information_schema.columns
    WHERE table_schema = 'letter' AND table_name = 'user_tables'
    ORDER BY ordinal_position;

-- Verify the rules' CHECK constraint: must have role or role_column but not both
\set VERBOSITY terse
INSERT INTO letter.membership_rules (table_name, user_column, role, role_column, pk_column)
    VALUES ('t', 'user_id', 'admin', 'role_col', 'id');

INSERT INTO letter.membership_rules (table_name, user_column, pk_column)
    VALUES ('t', 'user_id', 'id');
\set VERBOSITY default

-- Verify FK cascade: deleting a rule cascades to membership_sources
INSERT INTO letter.membership_rules (table_name, user_column, role, pk_column)
    VALUES ('t', 'user_id', 'admin', 'id')
    RETURNING id \gset assign_

INSERT INTO letter.memberships (role, user_id) VALUES ('admin', 'user1') RETURNING id \gset role_

INSERT INTO letter.membership_sources (assignment_id, role_id, source_table, source_id, user_id)
    VALUES (:'assign_id', :'role_id', 't', '1', 'user1');

SELECT count(*) AS before_delete FROM letter.membership_sources;

DELETE FROM letter.membership_rules WHERE id = :'assign_id';

SELECT count(*) AS after_delete FROM letter.membership_sources;

-- Verify cleanup trigger also removed the membership
SELECT count(*) AS orphaned_memberships FROM letter.memberships WHERE id = :'role_id';

DROP TABLE t;
DROP EXTENSION letter CASCADE;

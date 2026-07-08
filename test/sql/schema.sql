-- Test: extension creates the letter schema and core tables

CREATE EXTENSION letter;

-- Verify schema exists
SELECT nspname FROM pg_namespace WHERE nspname = 'letter';

-- Verify the four core tables exist
SELECT tablename FROM pg_tables
    WHERE schemaname = 'letter'
    ORDER BY tablename;

-- Verify roles table columns
SELECT column_name, data_type FROM information_schema.columns
    WHERE table_schema = 'letter' AND table_name = 'roles'
    ORDER BY ordinal_position;

-- Verify grants table columns
SELECT column_name, data_type FROM information_schema.columns
    WHERE table_schema = 'letter' AND table_name = 'grants'
    ORDER BY ordinal_position;

-- Verify assignments table columns
SELECT column_name, data_type FROM information_schema.columns
    WHERE table_schema = 'letter' AND table_name = 'assignments'
    ORDER BY ordinal_position;

-- Verify role_assignments table columns
SELECT column_name, data_type FROM information_schema.columns
    WHERE table_schema = 'letter' AND table_name = 'role_assignments'
    ORDER BY ordinal_position;

-- Verify assignments CHECK constraint: must have role_name or role_column but not both
\set VERBOSITY terse
INSERT INTO letter.assignments (table_name, user_column, role_name, role_column)
    VALUES ('t', 'user_id', 'admin', 'role_col');

INSERT INTO letter.assignments (table_name, user_column)
    VALUES ('t', 'user_id');
\set VERBOSITY default

-- Verify FK cascade: deleting assignment cascades to role_assignments
INSERT INTO letter.assignments (table_name, user_column, role_name)
    VALUES ('test_table', 'user_id', 'admin')
    RETURNING id \gset assign_

INSERT INTO letter.roles (role, user_id) VALUES ('admin', 'user1') RETURNING id \gset role_

INSERT INTO letter.role_assignments (assignment_id, role_id, source_table, source_id, user_id)
    VALUES (:'assign_id', :'role_id', 'test_table', '1', 'user1');

SELECT count(*) AS before_delete FROM letter.role_assignments;

DELETE FROM letter.assignments WHERE id = :'assign_id';

SELECT count(*) AS after_delete FROM letter.role_assignments;

-- Verify cleanup trigger also removed the role
SELECT count(*) AS orphaned_roles FROM letter.roles WHERE id = :'role_id';

DROP EXTENSION letter CASCADE;

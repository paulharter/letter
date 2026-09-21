-- bench/barrier/views_or.sql — candidate fix for OR-shaped visibility (plan/16 §8 Q2):
-- a UNION ALL of mutually exclusive branches, each with a strict (or run-time
-- constant) visibility predicate, instead of one OR the planner cannot drive.

SET search_path = lx;

-- A second chain: role 'assignee' scoped directly to lx.tasks (using_path NULL,
-- direct FK comments.task_id). alice is assignee on two tasks outside her projects.
DELETE FROM roles WHERE role = 'assignee';
INSERT INTO roles (role, user_id, scope_table, scope_id) VALUES
    ('assignee', 'alice', 'lx.tasks', '55555'),
    ('assignee', 'alice', 'lx.tasks', '77777'),
    ('assignee', 'alice', 'lx.tasks', '165');        -- inside project 17: overlaps chain A
ANALYZE roles;

-- Unscoped-or-scoped, as UNION ALL. Branch 1 is gated by a run-time constant
-- (executes only for admins); branch 2 is strict and scope-driven.
CREATE OR REPLACE VIEW v_or_union WITH (security_barrier) AS
SELECT c.id, c.body
FROM comments c
WHERE (SELECT EXISTS (SELECT 1 FROM roles r WHERE r.user_id = current_setting('lx.uid')
                        AND r.role = 'admin' AND r.scope_table IS NULL))
UNION ALL
SELECT c.id,
       CASE WHEN t.project_id = ANY (ARRAY(SELECT r.scope_id::bigint FROM roles r
                 WHERE r.user_id = current_setting('lx.uid')
                   AND r.role = 'editor' AND r.scope_table = 'lx.projects'))
            THEN c.body END
FROM comments c
LEFT JOIN tasks t ON t.id = c.task_id
WHERE NOT (SELECT EXISTS (SELECT 1 FROM roles r WHERE r.user_id = current_setting('lx.uid')
                            AND r.role = 'admin' AND r.scope_table IS NULL))
  AND EXISTS (SELECT 1 FROM roles r
              WHERE r.user_id = current_setting('lx.uid')
                AND r.role IN ('editor', 'viewer') AND r.scope_table = 'lx.projects'
                AND r.scope_id::bigint = t.project_id);

-- Two chains as a plain OR (expected: full scan) ...
CREATE OR REPLACE VIEW v_2chain_or WITH (security_barrier) AS
SELECT c.id, c.body
FROM comments c
LEFT JOIN tasks t ON t.id = c.task_id
WHERE EXISTS (SELECT 1 FROM roles r WHERE r.user_id = current_setting('lx.uid')
                AND r.role IN ('editor', 'viewer') AND r.scope_table = 'lx.projects'
                AND r.scope_id::bigint = t.project_id)
   OR EXISTS (SELECT 1 FROM roles r WHERE r.user_id = current_setting('lx.uid')
                AND r.role = 'assignee' AND r.scope_table = 'lx.tasks'
                AND r.scope_id::bigint = c.task_id);

-- ... and as mutually exclusive UNION ALL branches (no de-duplication needed:
-- branch 2 excludes rows branch 1 already produced).
CREATE OR REPLACE VIEW v_2chain_union WITH (security_barrier) AS
SELECT c.id, c.body
FROM comments c
LEFT JOIN tasks t ON t.id = c.task_id
WHERE EXISTS (SELECT 1 FROM roles r WHERE r.user_id = current_setting('lx.uid')
                AND r.role IN ('editor', 'viewer') AND r.scope_table = 'lx.projects'
                AND r.scope_id::bigint = t.project_id)
UNION ALL
SELECT c.id, c.body
FROM comments c
LEFT JOIN tasks t ON t.id = c.task_id
WHERE EXISTS (SELECT 1 FROM roles r WHERE r.user_id = current_setting('lx.uid')
                AND r.role = 'assignee' AND r.scope_table = 'lx.tasks'
                AND r.scope_id::bigint = c.task_id)
  AND (t.project_id = ANY (ARRAY(SELECT r.scope_id::bigint FROM roles r
           WHERE r.user_id = current_setting('lx.uid')
             AND r.role IN ('editor', 'viewer') AND r.scope_table = 'lx.projects'))) IS NOT TRUE;

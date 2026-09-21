-- bench/barrier/views.sql — hand-written stand-ins for the barrier subquery the
-- planner hook will generate (plan/16 §3.1). Modelled grants, both scoped to
-- lx.projects via using_path = {task_id}:
--     editor : select body        viewer : select author
-- PK always visible; task_id has no grant -> always redacted.
-- The user id is read at execution time, so every plan here is user-independent.

SET search_path = lx;

-- Form A: user's scope sets as a single-row FROM item, referenced as Vars.
CREATE OR REPLACE VIEW v_from WITH (security_barrier) AS
SELECT c.id,
       NULL::bigint AS task_id,
       CASE WHEN t.project_id = ANY (u.editor_projects) THEN c.body   END AS body,
       CASE WHEN t.project_id = ANY (u.viewer_projects) THEN c.author END AS author
FROM comments c
LEFT JOIN tasks t ON t.id = c.task_id
CROSS JOIN (SELECT
    ARRAY(SELECT r.scope_id::bigint FROM roles r
          WHERE r.user_id = current_setting('lx.uid')
            AND r.role = 'editor' AND r.scope_table = 'lx.projects') AS editor_projects,
    ARRAY(SELECT r.scope_id::bigint FROM roles r
          WHERE r.user_id = current_setting('lx.uid')
            AND r.role = 'viewer' AND r.scope_table = 'lx.projects') AS viewer_projects
) u
WHERE t.project_id = ANY (u.editor_projects || u.viewer_projects);

-- Form B: scope sets as uncorrelated ARRAY sublinks (InitPlans), repeated inline.
CREATE OR REPLACE VIEW v_initplan WITH (security_barrier) AS
SELECT c.id,
       NULL::bigint AS task_id,
       CASE WHEN t.project_id = ANY (ARRAY(SELECT r.scope_id::bigint FROM roles r
                 WHERE r.user_id = current_setting('lx.uid')
                   AND r.role = 'editor' AND r.scope_table = 'lx.projects'))
            THEN c.body END AS body,
       CASE WHEN t.project_id = ANY (ARRAY(SELECT r.scope_id::bigint FROM roles r
                 WHERE r.user_id = current_setting('lx.uid')
                   AND r.role = 'viewer' AND r.scope_table = 'lx.projects'))
            THEN c.author END AS author
FROM comments c
LEFT JOIN tasks t ON t.id = c.task_id
WHERE t.project_id = ANY (ARRAY(SELECT r.scope_id::bigint FROM roles r
          WHERE r.user_id = current_setting('lx.uid')
            AND r.role IN ('editor', 'viewer') AND r.scope_table = 'lx.projects'));

-- Form C: row visibility as a semijoin against roles; columns via InitPlan arrays.
CREATE OR REPLACE VIEW v_semi WITH (security_barrier) AS
SELECT c.id,
       NULL::bigint AS task_id,
       CASE WHEN t.project_id = ANY (ARRAY(SELECT r.scope_id::bigint FROM roles r
                 WHERE r.user_id = current_setting('lx.uid')
                   AND r.role = 'editor' AND r.scope_table = 'lx.projects'))
            THEN c.body END AS body,
       CASE WHEN t.project_id = ANY (ARRAY(SELECT r.scope_id::bigint FROM roles r
                 WHERE r.user_id = current_setting('lx.uid')
                   AND r.role = 'viewer' AND r.scope_table = 'lx.projects'))
            THEN c.author END AS author
FROM comments c
LEFT JOIN tasks t ON t.id = c.task_id
WHERE EXISTS (SELECT 1 FROM roles r
              WHERE r.user_id = current_setting('lx.uid')
                AND r.role IN ('editor', 'viewer') AND r.scope_table = 'lx.projects'
                AND r.scope_id::bigint = t.project_id);

-- Form D (anti-pattern, plan/16 §3.2 rule 1): EXISTS per column in the CASE.
CREATE OR REPLACE VIEW v_exists_case WITH (security_barrier) AS
SELECT c.id,
       NULL::bigint AS task_id,
       CASE WHEN EXISTS (SELECT 1 FROM roles r
                 WHERE r.user_id = current_setting('lx.uid') AND r.role = 'editor'
                   AND r.scope_table = 'lx.projects' AND r.scope_id::bigint = t.project_id)
            THEN c.body END AS body,
       CASE WHEN EXISTS (SELECT 1 FROM roles r
                 WHERE r.user_id = current_setting('lx.uid') AND r.role = 'viewer'
                   AND r.scope_table = 'lx.projects' AND r.scope_id::bigint = t.project_id)
            THEN c.author END AS author
FROM comments c
LEFT JOIN tasks t ON t.id = c.task_id
WHERE EXISTS (SELECT 1 FROM roles r
              WHERE r.user_id = current_setting('lx.uid')
                AND r.role IN ('editor', 'viewer') AND r.scope_table = 'lx.projects'
                AND r.scope_id::bigint = t.project_id);

-- Wrong-side cast (plan/16 §3.2 rule 4): cast the row side instead of the role side.
CREATE OR REPLACE VIEW v_wrongcast WITH (security_barrier) AS
SELECT c.id, c.body
FROM comments c
LEFT JOIN tasks t ON t.id = c.task_id
WHERE EXISTS (SELECT 1 FROM roles r
              WHERE r.user_id = current_setting('lx.uid')
                AND r.role IN ('editor', 'viewer') AND r.scope_table = 'lx.projects'
                AND r.scope_id = t.project_id::text);

-- B1 baseline (plan/15 §9.4): an opaque per-row visibility function.
CREATE OR REPLACE FUNCTION b1_visible(p_task_id bigint, p_roles text[]) RETURNS boolean
LANGUAGE plpgsql STABLE AS $$
DECLARE pid bigint;
BEGIN
    SELECT project_id INTO pid FROM lx.tasks WHERE id = p_task_id;
    IF pid IS NULL THEN RETURN false; END IF;
    RETURN EXISTS (SELECT 1 FROM lx.roles r
                   WHERE r.user_id = current_setting('lx.uid') AND r.role = ANY (p_roles)
                     AND r.scope_table = 'lx.projects' AND r.scope_id = pid::text);
END $$;

CREATE OR REPLACE VIEW v_b1 WITH (security_barrier) AS
SELECT c.id,
       NULL::bigint AS task_id,
       CASE WHEN b1_visible(c.task_id, ARRAY['editor']) THEN c.body   END AS body,
       CASE WHEN b1_visible(c.task_id, ARRAY['viewer']) THEN c.author END AS author
FROM comments c
WHERE b1_visible(c.task_id, ARRAY['editor', 'viewer']);

-- OR-shaped visibility (plan/16 §8 Q2): form B plus an unscoped 'admin' select grant,
-- resolved at run time so the plan stays user-independent (§7 option a).
CREATE OR REPLACE VIEW v_or WITH (security_barrier) AS
SELECT c.id,
       CASE WHEN (SELECT EXISTS (SELECT 1 FROM roles r WHERE r.user_id = current_setting('lx.uid')
                                   AND r.role = 'admin' AND r.scope_table IS NULL))
              OR t.project_id = ANY (ARRAY(SELECT r.scope_id::bigint FROM roles r
                 WHERE r.user_id = current_setting('lx.uid')
                   AND r.role = 'editor' AND r.scope_table = 'lx.projects'))
            THEN c.body END AS body
FROM comments c
LEFT JOIN tasks t ON t.id = c.task_id
WHERE (SELECT EXISTS (SELECT 1 FROM roles r WHERE r.user_id = current_setting('lx.uid')
                        AND r.role = 'admin' AND r.scope_table IS NULL))
   OR t.project_id = ANY (ARRAY(SELECT r.scope_id::bigint FROM roles r
          WHERE r.user_id = current_setting('lx.uid')
            AND r.role IN ('editor', 'viewer') AND r.scope_table = 'lx.projects'));

-- Form E (recommended after the experiment — see RESULTS.md): semijoin for row
-- visibility, hashed IN-subplans for the per-column tests. No arrays anywhere.
CREATE OR REPLACE VIEW v_hashed WITH (security_barrier) AS
SELECT c.id,
       NULL::bigint AS task_id,
       CASE WHEN t.project_id IN (SELECT r.scope_id::bigint FROM roles r
                 WHERE r.user_id = current_setting('lx.uid')
                   AND r.role = 'editor' AND r.scope_table = 'lx.projects')
            THEN c.body END AS body,
       CASE WHEN t.project_id IN (SELECT r.scope_id::bigint FROM roles r
                 WHERE r.user_id = current_setting('lx.uid')
                   AND r.role = 'viewer' AND r.scope_table = 'lx.projects')
            THEN c.author END AS author
FROM comments c
LEFT JOIN tasks t ON t.id = c.task_id
WHERE t.project_id IN (SELECT r.scope_id::bigint FROM roles r
                       WHERE r.user_id = current_setting('lx.uid')
                         AND r.role IN ('editor', 'viewer') AND r.scope_table = 'lx.projects');

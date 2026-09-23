-- The story application (plan/21 §2): a project tracker. Run as story_admin.
-- A user signs up as themselves (any_user, plan/22; see app_rules.sql). Whoever
-- authors an org or a project owns it (plan/21 D7, D8); team membership
-- confers a role in a project, org membership a role in an org.
CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    email text NOT NULL UNIQUE,
    is_staff boolean NOT NULL DEFAULT false
);
CREATE TABLE orgs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id uuid NOT NULL REFERENCES users(id),
    name text NOT NULL,
    plan text NOT NULL DEFAULT 'free'
);
CREATE INDEX ON orgs (owner_id);
CREATE TABLE org_members (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role text NOT NULL DEFAULT 'org_member',
    UNIQUE (org_id, user_id)
);
CREATE INDEX ON org_members (org_id);
CREATE TABLE projects (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    owner_id uuid NOT NULL REFERENCES users(id),
    name text NOT NULL,
    status text NOT NULL DEFAULT 'active',
    budget integer,
    notes text
);
CREATE INDEX ON projects (org_id);
CREATE INDEX ON projects (owner_id);
CREATE TABLE team_members (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role text NOT NULL,
    UNIQUE (project_id, user_id)
);
CREATE INDEX ON team_members (project_id);
CREATE TABLE tasks (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    title text NOT NULL,
    status text NOT NULL DEFAULT 'draft',
    assignee_id uuid REFERENCES users(id),
    estimate integer
);
CREATE INDEX ON tasks (project_id);
CREATE TABLE comments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id uuid NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    author_id uuid NOT NULL REFERENCES users(id),
    body text NOT NULL,
    reviewed_by uuid REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON comments (task_id);

-- SQL-level access for the application role: letter decides the rest.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO story_app;

-- The story application's membership rules and grants. Run as story_admin.
-- Memberships come from the application's own writes (plan/21 D7): whoever
-- authors an org or a project owns it, and owners invite.

SELECT letter.assign('public.users',        'id',       role := 'user');                               -- every account: the global role 'user'
SELECT letter.assign('public.orgs',         'owner_id', role := 'org_admin', scope := 'public.orgs');   -- the author of an org runs it (D8)
SELECT letter.assign('public.org_members',  'user_id',  role_column := 'role', scope := 'public.orgs');
SELECT letter.assign('public.projects',     'owner_id', role := 'owner', scope := 'public.projects');   -- the author of a project owns it (D8)
SELECT letter.assign('public.team_members', 'user_id',  role_column := 'role', scope := 'public.projects');

-- Everyone signed in can see who else exists — names only — and can start an org they own.
SELECT letter.grant_global('select', 'public.users', 'user', ARRAY['id', 'name']);
SELECT letter.grant_global('insert', 'public.orgs',  'user', if := 'owner_id = letter.user_id()::uuid');

-- Orgs: admins run them and invite members; members see them and start projects in them.
SELECT letter.grant_scoped('select', 'public.orgs',        'org_admin',  ARRAY['*'],            'public.orgs');
SELECT letter.grant_scoped('update', 'public.orgs',        'org_admin',  ARRAY['name', 'plan'], 'public.orgs');
SELECT letter.grant_scoped('select', 'public.orgs',        'org_member', ARRAY['name', 'plan'], 'public.orgs');
SELECT letter.grant_scoped('select', 'public.org_members', 'org_admin',  ARRAY['*'],            'public.orgs');
SELECT letter.grant_scoped('insert', 'public.org_members', 'org_admin',  NULL,                  'public.orgs');
SELECT letter.grant_scoped('delete', 'public.org_members', 'org_admin',  NULL,                  'public.orgs');
SELECT letter.grant_scoped('insert', 'public.projects',    'org_admin',  NULL, 'public.orgs', if := 'owner_id = letter.user_id()::uuid');
SELECT letter.grant_scoped('insert', 'public.projects',    'org_member', NULL, 'public.orgs', if := 'owner_id = letter.user_id()::uuid');

-- Projects: the owner sees and runs everything, and manages the team.
SELECT letter.grant_scoped('select', 'public.projects',     'owner', ARRAY['*'],                                 'public.projects');
SELECT letter.grant_scoped('update', 'public.projects',     'owner', ARRAY['name', 'status', 'budget', 'notes'], 'public.projects');
SELECT letter.grant_scoped('delete', 'public.projects',     'owner', NULL,                                       'public.projects');
SELECT letter.grant_scoped('select', 'public.team_members', 'owner', ARRAY['*'],                                 'public.projects');
SELECT letter.grant_scoped('insert', 'public.team_members', 'owner', NULL,                                       'public.projects');
SELECT letter.grant_scoped('update', 'public.team_members', 'owner', ARRAY['role'],                              'public.projects');
SELECT letter.grant_scoped('delete', 'public.team_members', 'owner', NULL,                                       'public.projects');
SELECT letter.grant_scoped('select', 'public.tasks',        'owner', ARRAY['*'],                                 'public.projects');
SELECT letter.grant_scoped('select', 'public.comments',     'owner', ARRAY['*'],                                 'public.projects', ARRAY['task_id']);

-- Project roles: editor and viewer, scoped to the project.
SELECT letter.grant_scoped('select', 'public.projects', 'editor', ARRAY['*'],                       'public.projects');
SELECT letter.grant_scoped('select', 'public.projects', 'viewer', ARRAY['name', 'status'],          'public.projects');
SELECT letter.grant_scoped('update', 'public.projects', 'editor', ARRAY['name', 'status', 'notes'], 'public.projects');
SELECT letter.grant_scoped('select', 'public.tasks',    'editor', ARRAY['*'],                       'public.projects');
SELECT letter.grant_scoped('select', 'public.tasks',    'viewer', ARRAY['title', 'status'],         'public.projects');
SELECT letter.grant_scoped('insert', 'public.tasks',    'editor', NULL,                             'public.projects');
SELECT letter.grant_scoped('update', 'public.tasks',    'editor', ARRAY['title', 'status', 'assignee_id', 'estimate'], 'public.projects');
SELECT letter.grant_scoped('delete', 'public.tasks',    'editor', NULL,                             'public.projects');
SELECT letter.grant_scoped('select', 'public.comments', 'editor', ARRAY['*'],                       'public.projects', ARRAY['task_id']);
SELECT letter.grant_scoped('select', 'public.comments', 'viewer', ARRAY['body', 'created_at'],      'public.projects', ARRAY['task_id']);
SELECT letter.grant_scoped('insert', 'public.comments', 'editor', NULL, 'public.projects', ARRAY['task_id'],
                           if := 'author_id = letter.user_id()::uuid');                              -- you write as yourself

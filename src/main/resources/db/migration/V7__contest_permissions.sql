-- contest:create, contest:update and contest:delete let ADMIN and SYS_ROOT manage contests. t_permissions has
-- UNIQUE (name), so ON CONFLICT DO NOTHING also skips a permission made by hand under another id, and the grants are
-- matched by role name (live role ids differ from the V2 seed's), so replaying this changes nothing.
INSERT INTO public.t_permissions (id, created_at, created_by, updated_at, updated_by, description, name) VALUES
  ('a4000000-0000-0000-0000-000000000001', now(), 'SYS', now(), 'SYS', 'Create contests', 'contest:create'),
  ('a4000000-0000-0000-0000-000000000002', now(), 'SYS', now(), 'SYS', 'Update contests', 'contest:update'),
  ('a4000000-0000-0000-0000-000000000003', now(), 'SYS', now(), 'SYS', 'Delete contests', 'contest:delete')
ON CONFLICT DO NOTHING;

INSERT INTO public.t_roles_permissions (role_id, permission_id)
SELECT r.id, p.id FROM public.t_roles r, public.t_permissions p
WHERE r.name IN ('ADMIN', 'SYS_ROOT') AND p.name IN ('contest:create', 'contest:update', 'contest:delete')
ON CONFLICT DO NOTHING;

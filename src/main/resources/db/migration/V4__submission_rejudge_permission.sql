-- submission:rejudge lets ADMIN and SYS_ROOT judge a problem's submissions again. The permission is added only when
-- no permission of that name exists, and the grants are matched by role name (live role ids differ from the V2
-- seed's), so re-running over a database that already has them changes nothing.
INSERT INTO public.t_permissions (id, created_at, created_by, updated_at, updated_by, description, name)
SELECT 'a1000000-0000-0000-0000-00000000000f', now(), 'SYS', now(), 'SYS', 'Judge submissions again', 'submission:rejudge'
WHERE NOT EXISTS (SELECT 1 FROM public.t_permissions WHERE name = 'submission:rejudge');

INSERT INTO public.t_roles_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.t_roles r, public.t_permissions p
WHERE r.name IN ('ADMIN', 'SYS_ROOT')
  AND p.name = 'submission:rejudge'
  AND NOT EXISTS (SELECT 1 FROM public.t_roles_permissions rp WHERE rp.role_id = r.id AND rp.permission_id = p.id);

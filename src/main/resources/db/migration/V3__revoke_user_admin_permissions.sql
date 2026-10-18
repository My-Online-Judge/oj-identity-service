-- The USER role holds no admin permission. On the live identity-db it had judgeserver:read and permission:read
-- (granted on 2026-07-18 while the Roles page was being built, carried over by the split), which let every ordinary
-- user open /admin, the judge-server list and the permission catalog. Matched by name, so a database without the
-- grants is left unchanged.
DELETE FROM public.t_roles_permissions rp
USING public.t_roles r, public.t_permissions p
WHERE rp.role_id = r.id
  AND rp.permission_id = p.id
  AND r.name = 'USER'
  AND p.name IN ('judgeserver:read', 'permission:read');

-- SP12: one live account per username and per email, case-insensitively. Soft-deleted rows (status 2) are excluded.
-- Also one live account per Google id (sub, Google's stable identifier, by which a Google sign-in finds its account).
-- Resolve duplicates first: judge-deployment/migrations/sp12-dupes.sh lists them.
DO $$
DECLARE dupes text;
BEGIN
  SELECT string_agg(k, ', ') INTO dupes FROM (
    SELECT 'username ' || lower(username) AS k FROM public.t_users WHERE status <> 2 AND username IS NOT NULL
      GROUP BY lower(username) HAVING count(*) > 1
    UNION ALL
    SELECT 'email ' || lower(email) FROM public.t_users WHERE status <> 2 AND email IS NOT NULL
      GROUP BY lower(email) HAVING count(*) > 1
    UNION ALL
    SELECT 'google_id ' || google_id FROM public.t_users WHERE status <> 2 AND google_id IS NOT NULL
      GROUP BY google_id HAVING count(*) > 1) d;
  IF dupes IS NOT NULL THEN
    RAISE EXCEPTION 'V6: resolve duplicate users first (judge-deployment/migrations/sp12-dupes.sh): %', dupes;
  END IF;
END $$;
CREATE UNIQUE INDEX ux_users_username_lower ON public.t_users (lower(username)) WHERE status <> 2;
CREATE UNIQUE INDEX ux_users_email_lower ON public.t_users (lower(email)) WHERE status <> 2;
CREATE UNIQUE INDEX ux_users_google_id ON public.t_users (google_id) WHERE google_id IS NOT NULL AND status <> 2;
-- Refresh rotation keeps rotated rows for days; the per-user deletes and deleteRotatedBefore scan t_tokens without it.
CREATE INDEX IF NOT EXISTS ix_tokens_user_id ON public.t_tokens (user_id);

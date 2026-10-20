-- SP12: refresh tokens rotate (rotated_at marks a replaced one); tokens are stored as SHA-256 hex, hashed in place
-- so existing sessions keep working.
ALTER TABLE public.t_tokens ADD COLUMN rotated_at timestamp(6) without time zone;
UPDATE public.t_tokens SET token = encode(sha256(convert_to(token, 'UTF8')), 'hex') WHERE token IS NOT NULL;

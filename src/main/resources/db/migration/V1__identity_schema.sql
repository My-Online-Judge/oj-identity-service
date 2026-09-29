-- identity-db baseline: the eight identity tables exactly as they exist in oj-db after judge-api V14
-- (pg_dump --schema-only of the live schema, 2026-09-28), internal foreign keys kept. The data itself is
-- copied in by judge-deployment/migrations/sp1-identity.sh at cutover.


CREATE TABLE public.t_access_bans (
    id uuid NOT NULL,
    type character varying(10) NOT NULL,
    value character varying(128) NOT NULL,
    reason character varying(255),
    expires_at timestamp without time zone,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    created_by character varying(255),
    updated_by character varying(255)
);

CREATE TABLE public.t_login_attempts (
    id uuid NOT NULL,
    username character varying(64),
    ip character varying(45),
    device_hash character varying(128),
    user_agent character varying(512),
    success boolean NOT NULL,
    error_code character varying(64),
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    created_by character varying(255),
    updated_by character varying(255)
);

CREATE TABLE public.t_permissions (
    id uuid NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    created_by character varying(255),
    updated_at timestamp(6) without time zone NOT NULL,
    updated_by character varying(255),
    description character varying(255),
    name character varying(255)
);

CREATE TABLE public.t_roles (
    id uuid NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    created_by character varying(255),
    updated_at timestamp(6) without time zone NOT NULL,
    updated_by character varying(255),
    description character varying(255),
    name character varying(255)
);

CREATE TABLE public.t_roles_permissions (
    role_id uuid NOT NULL,
    permission_id uuid NOT NULL
);

CREATE TABLE public.t_tokens (
    id uuid NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    created_by character varying(255),
    updated_at timestamp(6) without time zone NOT NULL,
    updated_by character varying(255),
    expired boolean NOT NULL,
    revoked boolean NOT NULL,
    token text,
    token_type character varying(255),
    user_id uuid,
    ip character varying(45),
    device_hash character varying(128),
    user_agent character varying(512),
    CONSTRAINT t_tokens_token_type_check CHECK (((token_type)::text = ANY (ARRAY[('ACCESS'::character varying)::text, ('REFRESH'::character varying)::text])))
);

CREATE TABLE public.t_users (
    id uuid NOT NULL,
    created_at timestamp(6) without time zone NOT NULL,
    created_by character varying(255),
    updated_at timestamp(6) without time zone NOT NULL,
    updated_by character varying(255),
    email character varying(255),
    enabled_mfa boolean,
    password character varying(255),
    status integer,
    username character varying(255),
    last_login timestamp(6) without time zone,
    avatar character varying(255),
    google_id character varying(255),
    name character varying(255),
    last_login_ip character varying(45),
    last_login_device_hash character varying(128)
);

CREATE TABLE public.t_users_roles (
    user_id uuid NOT NULL,
    role_id uuid NOT NULL
);

ALTER TABLE ONLY public.t_access_bans
    ADD CONSTRAINT t_access_bans_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.t_login_attempts
    ADD CONSTRAINT t_login_attempts_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.t_permissions
    ADD CONSTRAINT t_permissions_name_key UNIQUE (name);

ALTER TABLE ONLY public.t_permissions
    ADD CONSTRAINT t_permissions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.t_roles_permissions
    ADD CONSTRAINT t_roles_permissions_pkey PRIMARY KEY (role_id, permission_id);

ALTER TABLE ONLY public.t_roles
    ADD CONSTRAINT t_roles_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.t_tokens
    ADD CONSTRAINT t_tokens_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.t_users
    ADD CONSTRAINT t_users_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.t_users_roles
    ADD CONSTRAINT t_users_roles_pkey PRIMARY KEY (user_id, role_id);

ALTER TABLE ONLY public.t_tokens
    ADD CONSTRAINT ukdjdnp60wf0lq8erni3suse1np UNIQUE (token);

ALTER TABLE ONLY public.t_access_bans
    ADD CONSTRAINT uq_access_bans_type_value UNIQUE (type, value);

CREATE INDEX idx_login_attempts_ip_created ON public.t_login_attempts USING btree (ip, created_at DESC);

CREATE INDEX idx_login_attempts_username_created ON public.t_login_attempts USING btree (username, created_at DESC);

ALTER TABLE ONLY public.t_users_roles
    ADD CONSTRAINT fk4tbnlvd7naivo2om0ma842821 FOREIGN KEY (role_id) REFERENCES public.t_roles(id);

ALTER TABLE ONLY public.t_tokens
    ADD CONSTRAINT fk4yapf70j8ywq6xye5ypmr4a9g FOREIGN KEY (user_id) REFERENCES public.t_users(id);

ALTER TABLE ONLY public.t_roles_permissions
    ADD CONSTRAINT fk_roles_permissions_permission FOREIGN KEY (permission_id) REFERENCES public.t_permissions(id);

ALTER TABLE ONLY public.t_roles_permissions
    ADD CONSTRAINT fk_roles_permissions_role FOREIGN KEY (role_id) REFERENCES public.t_roles(id);

ALTER TABLE ONLY public.t_users_roles
    ADD CONSTRAINT fkfxgldwdsgyl221kqaum2l0dm9 FOREIGN KEY (user_id) REFERENCES public.t_users(id);

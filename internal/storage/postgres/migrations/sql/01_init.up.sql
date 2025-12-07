CREATE TABLE IF NOT EXISTS domain_keys (
    id           BIGSERIAL PRIMARY KEY,
    app_id       TEXT        NOT NULL,
    date         TIMESTAMPTZ NULL,
    domain_name  TEXT        NOT NULL,
    expire       BIGINT      NOT NULL,
    file         TEXT        NOT NULL,
    fqdn         TEXT        NOT NULL,
    key          TEXT        NOT NULL,
    last_error   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS domain_keys_app_file_fqdn_uq
    ON domain_keys (app_id, file, fqdn);

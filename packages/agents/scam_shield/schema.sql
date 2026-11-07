-- Knowledge base schema. The code is public; the data stays in a private database.

CREATE TABLE IF NOT EXISTS sources (
    id          text PRIMARY KEY,
    name        text NOT NULL,
    home_url    text NOT NULL,
    licence     text NOT NULL,
    attribution text NOT NULL
);

CREATE TABLE IF NOT EXISTS source_documents (
    id           bigserial PRIMARY KEY,
    source_id    text NOT NULL REFERENCES sources (id),
    url          text NOT NULL UNIQUE,
    title        text NOT NULL,
    published_on date,
    content      text NOT NULL,
    content_hash text NOT NULL,
    -- Used by the eval set, so patterns must never be extracted from it.
    eval_holdout boolean NOT NULL DEFAULT false,
    fetched_at   timestamptz NOT NULL DEFAULT now(),
    extracted_at timestamptz
);

CREATE TABLE IF NOT EXISTS scam_variants (
    id            bigserial PRIMARY KEY,
    document_id   bigint NOT NULL REFERENCES source_documents (id) ON DELETE CASCADE,
    title         text NOT NULL,
    scam_type     text NOT NULL,
    summary       text NOT NULL,
    warning_signs text NOT NULL,
    first_seen    date,
    created_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (document_id, title)
);

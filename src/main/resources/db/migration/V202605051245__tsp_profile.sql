CREATE TABLE "tsp_profile" (
    "uuid"        UUID        NOT NULL,
    "name"        VARCHAR     NOT NULL,
    "description" TEXT,
    "enabled"     BOOLEAN     NOT NULL DEFAULT FALSE,
    "i_author"    VARCHAR,
    "i_cre"       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "i_upd"       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY ("uuid"),
    UNIQUE ("name")
);

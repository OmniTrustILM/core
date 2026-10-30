CREATE TABLE "list_view" (
    "uuid"         UUID         NOT NULL,
    "user_uuid"    UUID         NOT NULL,
    "resource"     VARCHAR      NOT NULL,
    "name"         VARCHAR(255) NOT NULL,
    "default_view" BOOLEAN      NOT NULL DEFAULT FALSE,
    "columns"      JSONB        NOT NULL,
    "filters"      JSONB,
    "sort"         JSONB,
    "i_author"     VARCHAR,
    "i_cre"        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    "i_upd"        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY ("uuid"),
    CONSTRAINT "uk_list_view_user_resource_name" UNIQUE ("user_uuid", "resource", "name")
);

-- Every read is "the views this user has for this listing", and the orphan sweep is "the views this user has".
CREATE INDEX "idx_list_view_user_resource" ON "list_view" ("user_uuid", "resource");

-- At most one default per user and resource. A partial unique index is the only shape that expresses "unique among
-- the rows where the flag is set", so it has no counterpart on the entity and is absent from the entity-generated
-- test schema, which is why ListViewServiceITest creates it itself; ListViewWriter clears the previous default
-- before writing the new one, and this backstops a write that bypasses it.
CREATE UNIQUE INDEX "uk_list_view_single_default" ON "list_view" ("user_uuid", "resource") WHERE "default_view";

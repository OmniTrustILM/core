-- What one CBOM's asset ingest had to tell the producer about the document, and what it could not turn into an asset.
-- The extraction already computed both -- a dropped value, a withheld digest, an inlined secret, a component that
-- could not be keyed -- and then discarded them at the boundary, so a document could be refused with no record of
-- why and ingested with no record of what it cost. Rows are rolled up per distinct message rather than per
-- component: one document reports the same finding for thousands of components, and the count is the useful part.
CREATE TABLE "cbom_ingest_finding"
(
    "uuid"           UUID        NOT NULL,
    "cbom_uuid"      UUID        NOT NULL,
    -- FINDING is what the producer should hear; SKIP is a component that yielded no asset at all.
    "kind"           TEXT        NOT NULL,
    -- One component that raised it, as an example; NULL when the finding is about the document rather than a
    -- component. Producer text, like crypto_asset.name -- never a value, only a name.
    "component_name" TEXT,
    -- Shaped by Core and operator-visible. A finding names the member it is about, never the member's value.
    "detail"         TEXT        NOT NULL,
    -- How many components raised this exact message.
    "occurrences"    INT         NOT NULL,
    "recorded_at"    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY ("uuid"),
    -- CASCADE, unlike crypto_asset_source's RESTRICT: a finding is a statement about one document and means nothing
    -- once that document is gone, where a source carries inventory provenance that must not vanish silently.
    CONSTRAINT "cbom_ingest_finding_to_cbom_key" FOREIGN KEY ("cbom_uuid") REFERENCES "cbom" ("uuid") ON DELETE CASCADE,
    -- The arbiter of the upsert, and what makes a redone ingest converge instead of duplicating its own report.
    CONSTRAINT "uq_cbom_ingest_finding" UNIQUE ("cbom_uuid", "kind", "detail"),
    CONSTRAINT "ck_cbom_ingest_finding_kind" CHECK ("kind" IN ('FINDING', 'SKIP')),
    CONSTRAINT "ck_cbom_ingest_finding_occurrences" CHECK ("occurrences" >= 0),
    -- The backstop for the bound the writer applies. detail is a column of the unique index above, and a btree tuple
    -- wider than about 2704 bytes is refused by the index; the text is producer-derived and otherwise unbounded.
    CONSTRAINT "ck_cbom_ingest_finding_detail_length" CHECK (length("detail") <= 512),
    CONSTRAINT "ck_cbom_ingest_finding_component_name_length" CHECK (length("component_name") <= 1024)
);

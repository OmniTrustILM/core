-- Cryptographic asset inventory (ilm#299 section 3): the deduplicated cross-CBOM asset table, the many-to-many link
-- back to every source CBOM with its retained payload and capped evidence, the duplicate-repair alias table, and the
-- per-CBOM asset-sync state. No GIN, no CREATE EXTENSION and no partitioning in v1: the hot filters are typed columns
-- with btree indexes, and only the variable cryptoProperties long tail is JSONB.

CREATE TABLE "crypto_asset" (
    "uuid"                      UUID PRIMARY KEY,
    -- Hash over the identity preimage. Plain UNIQUE, so it can arbitrate ON CONFLICT on the ingest upsert.
    -- Never leaves the database: the preimage is low-entropy, so the key falls to a dictionary attack (core#2070).
    "identity_key"              TEXT        NOT NULL,
    -- The identity rule-set generation that keyed this row. Deliberately NOT part of the preimage: including it would
    -- re-key every row on a rule-set bump. Recorded instead, so 'ruleset_version < current' finds rows to re-key.
    "ruleset_version"           INT         NOT NULL,

    -- Typed identity and filter columns, holding the canonical normalized spelling rather than any one producer's raw
    -- text: the row is a deduplicated view over every producer that reported the asset, so it has no single raw
    -- spelling, and storing the last writer's made a filter answer depend on sync order. The producers' own spellings
    -- are retained per source. All but asset_type are producer-derived and nullable: a CycloneDX value this Core
    -- version has never seen must be stored, not rejected, and a crypto component may carry no cryptoProperties at
    -- all (the UNROUTABLE backstop asset type).
    "asset_type"                TEXT        NOT NULL,
    "name"                      TEXT,
    "oid"                       TEXT,
    "algorithm_family"          TEXT,
    "primitive"                 TEXT,
    "parameter_set"             TEXT,
    "curve"                     TEXT,
    "mode"                      TEXT,
    "padding"                   TEXT,
    "variant"                   TEXT,
    -- The safety rule that forced this row to stay a separate row (refuted certificate digest, bare-CN subject,
    -- refuted OID). NULL = no guard. crypto_asset_alias refuses to absorb or target a guarded row.
    "identity_guard"            TEXT,

    -- Merge bookkeeping. merged_crypto_properties is byte-for-byte one retained per-source payload -- the richest one --
    -- never a synthesised object, which is what makes an alias exactly reversible. Deliberately unindexed.
    "merged_crypto_properties"  JSONB,
    "properties_leaf_count"     INT         NOT NULL DEFAULT 0,
    "properties_hash"           TEXT,
    -- Which retained per-source payload the merged view was adopted from. FK added below, after the source table
    -- exists, with ON DELETE SET NULL so the pointer can never outlive the row it names.
    "properties_source_uuid"    UUID,
    "source_count"              INT         NOT NULL DEFAULT 0,

    -- PQC verdict, stamped with the PQC rule-set generation that produced it and the fields the rule actually read.
    "pqc_verdict"               TEXT,
    "pqc_rule_id"               TEXT,
    "pqc_reason"                TEXT,
    "pqc_ruleset_version"       INT,
    "pqc_evaluated_fields"      JSONB,
    -- Two timestamps, because the contract asks two different questions. pqc_decided_at is when the verdict *value*
    -- was decided and only moves when it changes; pqc_evaluated_at advances on every evaluation, including one that
    -- re-confirms the same verdict. Neither is derivable from i_upd, which moves on every identity refresh.
    "pqc_decided_at"            TIMESTAMPTZ,
    "pqc_evaluated_at"          TIMESTAMPTZ,

    "i_author"                  TEXT,
    "i_cre"                     TIMESTAMPTZ NOT NULL,
    "i_upd"                     TIMESTAMPTZ NOT NULL,
    CONSTRAINT "uq_crypto_asset_identity_key" UNIQUE ("identity_key"),
    -- The hash is the merged payload's fingerprint; one without the other is a bug, not a state.
    CONSTRAINT "ck_crypto_asset_properties_pair"
        CHECK (("merged_crypto_properties" IS NULL) = ("properties_hash" IS NULL)),
    CONSTRAINT "ck_crypto_asset_source_count" CHECK ("source_count" >= 0),
    CONSTRAINT "ck_crypto_asset_properties_leaf_count" CHECK ("properties_leaf_count" >= 0),
    -- These three columns hold Java enum constant names. Without a CHECK, a value no constant parses is accepted at
    -- write time and fails later at read time, on a row nothing can trace back to the statement that wrote it. Adding
    -- an enum constant now needs a migration, which is the point: a new constant is a contract change.
    CONSTRAINT "ck_crypto_asset_asset_type" CHECK ("asset_type" IN
        ('ALGORITHM', 'CERTIFICATE', 'PROTOCOL', 'RELATED_CRYPTO_MATERIAL', 'UNROUTABLE')),
    CONSTRAINT "ck_crypto_asset_identity_guard" CHECK ("identity_guard" IN
        ('REFUTED_CERTIFICATE_DIGEST', 'BARE_CN_SUBJECT', 'REFUTED_OID')),
    CONSTRAINT "ck_crypto_asset_pqc_verdict" CHECK ("pqc_verdict" IN
        ('READY', 'NOT_READY', 'NOT_APPLICABLE', 'UNKNOWN')),
    -- Eleven producer-supplied TEXT columns are indexed, and a btree tuple wider than roughly 2704 bytes is refused by
    -- the index rather than by validation -- an error the ingest path cannot attribute to a field. The two columns a
    -- producer can realistically make long are bounded here, where the error names the column that caused it: a
    -- dotted-decimal object identifier at 255, and a component name at 1024, which is far above any real CycloneDX
    -- name and far below the point where a row becomes a document store. The remaining nine are short by construction
    -- -- an algorithm family, a primitive, a curve -- and bounding them would buy nothing.
    --
    -- These count characters, not bytes, so the index limit is not formally unreachable: 1024 characters outside the
    -- Basic Multilingual Plane is 4096 bytes. Every realistic name is ASCII or near it, so this bounds the case that
    -- happens; octet_length would bound the case that cannot.
    CONSTRAINT "ck_crypto_asset_oid_length" CHECK (length("oid") <= 255),
    CONSTRAINT "ck_crypto_asset_name_length" CHECK (length("name") <= 1024)
);

CREATE TABLE "crypto_asset_source" (
    "uuid"                        UUID PRIMARY KEY,
    "asset_uuid"                  UUID        NOT NULL,
    "cbom_uuid"                   UUID        NOT NULL,
    -- The source's own cryptoProperties, retained verbatim. Retaining it per source is what makes the merge, and an
    -- alias built on top of it, exactly reversible.
    "original_crypto_properties"  JSONB,
    "properties_leaf_count"       INT         NOT NULL DEFAULT 0,
    "properties_hash"             TEXT,
    -- Capped occurrence evidence. Capping DROPS an occurrence's additionalContext outright and never truncates it:
    -- the 1.7 schema documents that field as "e.g. a code snippet", and at a secret-scanner finding the snippet is the
    -- secret line -- a truncated secret is still a secret.
    "evidence"                    JSONB,
    -- Occurrences seen, including the ones capping dropped, so the gap against the retained array is visible.
    "occurrence_count"            INT         NOT NULL DEFAULT 0,
    "first_seen_at"               TIMESTAMPTZ NOT NULL,
    "last_seen_at"                TIMESTAMPTZ NOT NULL,
    CONSTRAINT "uq_crypto_asset_source" UNIQUE ("asset_uuid", "cbom_uuid"),
    CONSTRAINT "ck_crypto_asset_source_occurrence_count" CHECK ("occurrence_count" >= 0),
    CONSTRAINT "ck_crypto_asset_source_properties_leaf_count" CHECK ("properties_leaf_count" >= 0),
    -- A source reference has no meaning without its asset.
    CONSTRAINT "crypto_asset_source_to_crypto_asset_key" FOREIGN KEY ("asset_uuid")
        REFERENCES "crypto_asset" ("uuid") ON DELETE CASCADE,
    -- RESTRICT, not CASCADE: dropping a CBOM row must not silently erase inventory provenance. The delete path must
    -- therefore detach this CBOM's sources first -- CryptoAssetSourceWriter.detachCbom over
    -- CryptoAssetSourceRepository.findAssetUuidsByCbomUuid -- and then record a cbom_tombstone so the next sync does
    -- not simply re-ingest the document. Neither is wired into CbomServiceImpl yet: nothing writes crypto_asset_source
    -- until asset ingest lands, so today every CBOM has zero sources and deletes unimpeded. The ingest ticket owns
    -- that wiring, and it is not optional -- without it the first CBOM to acquire a source becomes undeletable
    -- through the API, refused by this constraint with no endpoint able to detach.
    CONSTRAINT "crypto_asset_source_to_cbom_key" FOREIGN KEY ("cbom_uuid")
        REFERENCES "cbom" ("uuid") ON DELETE RESTRICT
);

-- Deferred to here because the two tables reference each other. ON DELETE SET NULL keeps the pointer honest: a row
-- with a merged payload and a NULL pointer is exactly the set a re-election sweep must repair, and it is findable. A
-- dangling uuid would be indistinguishable from a valid one.
ALTER TABLE "crypto_asset"
    ADD CONSTRAINT "crypto_asset_to_properties_source_key" FOREIGN KEY ("properties_source_uuid")
        REFERENCES "crypto_asset_source" ("uuid") ON DELETE SET NULL;

CREATE TABLE "crypto_asset_alias" (
    "uuid"          UUID PRIMARY KEY,
    -- The key of the row that was absorbed. No FK: by the time the alias exists that row is gone, so a reference
    -- would be unsatisfiable.
    "absorbed_key"  TEXT        NOT NULL,
    "canonical_key" TEXT        NOT NULL,
    "reason"        TEXT,
    "decided_by"    TEXT,
    "decided_at"    TIMESTAMPTZ NOT NULL,
    CONSTRAINT "uq_crypto_asset_alias_absorbed" UNIQUE ("absorbed_key"),
    CONSTRAINT "ck_crypto_asset_alias_not_self" CHECK ("absorbed_key" <> "canonical_key"),
    -- An alias pointing at an asset that no longer exists is a lie.
    CONSTRAINT "crypto_asset_alias_to_canonical_key" FOREIGN KEY ("canonical_key")
        REFERENCES "crypto_asset" ("identity_key") ON DELETE CASCADE
);

-- A deleted CBOM, remembered. No FK to cbom: the referenced row is exactly the one that no longer exists. The primary
-- key IS the deleted CBOM's own uuid, so a deletion cannot be tombstoned twice.
CREATE TABLE "cbom_tombstone" (
    "uuid"          UUID PRIMARY KEY,
    "serial_number" TEXT        NOT NULL,
    "version"       INT         NOT NULL,
    "deleted_at"    TIMESTAMPTZ NOT NULL,
    "deleted_by"    TEXT,
    CONSTRAINT "uq_cbom_tombstone_serial_version" UNIQUE ("serial_number", "version")
);

-- Existing header-only rows correctly read as PENDING: their assets have never been ingested. A constant DEFAULT on
-- ADD COLUMN is metadata-only, so this does not rewrite the table.
ALTER TABLE "cbom"
    ADD COLUMN "asset_sync_state" TEXT NOT NULL DEFAULT 'PENDING',
    -- Shaped by us, never a driver message: this string is operator-visible.
    ADD COLUMN "asset_sync_error" TEXT,
    ADD COLUMN "assets_synced_at" TIMESTAMPTZ,
    ADD CONSTRAINT "ck_cbom_asset_sync_state" CHECK ("asset_sync_state" IN
        ('PENDING', 'IN_PROGRESS', 'SYNCED', 'FAILED'));

-- Btree per filter column. No lower(name) / lower(oid) expression index: FilterPredicatesBuilder never emits lower()
-- -- it applies LIKE to the column itself -- so the planner could not choose one, and infix matching would need a
-- trigram index, which v1 excludes. An expression index that no query can reach costs writes and buys nothing.
CREATE INDEX "idx_crypto_asset_asset_type" ON "crypto_asset" ("asset_type");
CREATE INDEX "idx_crypto_asset_name" ON "crypto_asset" ("name");
CREATE INDEX "idx_crypto_asset_oid" ON "crypto_asset" ("oid");
CREATE INDEX "idx_crypto_asset_algorithm_family" ON "crypto_asset" ("algorithm_family");
CREATE INDEX "idx_crypto_asset_primitive" ON "crypto_asset" ("primitive");
CREATE INDEX "idx_crypto_asset_parameter_set" ON "crypto_asset" ("parameter_set");
CREATE INDEX "idx_crypto_asset_curve" ON "crypto_asset" ("curve");
CREATE INDEX "idx_crypto_asset_mode" ON "crypto_asset" ("mode");
CREATE INDEX "idx_crypto_asset_padding" ON "crypto_asset" ("padding");
CREATE INDEX "idx_crypto_asset_variant" ON "crypto_asset" ("variant");
CREATE INDEX "idx_crypto_asset_pqc_verdict" ON "crypto_asset" ("pqc_verdict");
CREATE INDEX "idx_crypto_asset_pqc_ruleset_version" ON "crypto_asset" ("pqc_ruleset_version");
CREATE INDEX "idx_crypto_asset_ruleset_version" ON "crypto_asset" ("ruleset_version");
CREATE INDEX "idx_crypto_asset_source_count" ON "crypto_asset" ("source_count");
-- Not a filter column: without it, the ON DELETE SET NULL check scans crypto_asset once per deleted source row.
CREATE INDEX "idx_crypto_asset_properties_source" ON "crypto_asset" ("properties_source_uuid");

-- uq_crypto_asset_source leads with asset_uuid, so it serves neither the RESTRICT check on a cbom delete nor
-- per-CBOM detach, both of which lead with cbom_uuid.
CREATE INDEX "idx_crypto_asset_source_cbom" ON "crypto_asset_source" ("cbom_uuid");

-- Without it, the ON DELETE CASCADE check scans crypto_asset_alias once per deleted asset.
CREATE INDEX "idx_crypto_asset_alias_canonical" ON "crypto_asset_alias" ("canonical_key");

CREATE INDEX "idx_cbom_asset_sync_state" ON "cbom" ("asset_sync_state");
CREATE INDEX "idx_cbom_assets_synced_at" ON "cbom" ("assets_synced_at");

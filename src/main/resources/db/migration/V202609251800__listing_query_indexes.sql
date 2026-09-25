-- Indexes for the lookups every inventory listing page makes, and two duplicate unique constraints dropped from
-- certificate. ListingQueryIndexesMigrationITest pins each index to its lookup.
--
-- CREATE INDEX blocks writes to its table while it builds; Flyway's transaction rules out CONCURRENTLY. At 3.8M
-- attribute mappings the script takes ~6.5 s, most of it on attribute_content_2_object.

-- Attribute filters, the attribute sort key and the field catalogue walk definition -> content items -> mappings.
-- object_type and object_uuid in the mapping index let those lookups run index-only.
CREATE INDEX "idx_attribute_content_item_definition"
    ON "attribute_content_item" ("attribute_definition_uuid");
CREATE INDEX "idx_attribute_content_2_object_item"
    ON "attribute_content_2_object" ("attribute_content_item_uuid", "object_type", "object_uuid");

-- A restricted user's access check, every listing page's row and group fetch, and the group and owner filters look
-- associations up by object, group or owner.
CREATE INDEX "idx_group_association_object" ON "group_association" ("object_uuid", "resource");
CREATE INDEX "idx_group_association_group" ON "group_association" ("group_uuid", "resource", "object_uuid");
CREATE INDEX "idx_owner_association_object" ON "owner_association" ("object_uuid");
CREATE INDEX "idx_owner_association_owner" ON "owner_association" ("owner_username", "resource", "object_uuid");

-- The key listing's default order and the certificate expiry sort. Other certificate sort columns stay unindexed on
-- purpose: validation rewrites certificate rows, so each index costs one more write per validated certificate.
CREATE INDEX "idx_cryptographic_key_item_created_at" ON "cryptographic_key_item" ("created_at");
CREATE INDEX "idx_certificate_not_after" ON "certificate" ("not_after");

-- Duplicates of certificate_pkey and certificate_fingerprint_key, each an extra write per certificate change. No foreign
-- key depends on them: the primary key predates certificate_uuid_unique, so foreign keys into certificate bind to
-- certificate_pkey, and none references fingerprint.
ALTER TABLE "certificate" DROP CONSTRAINT IF EXISTS "certificate_uuid_unique";
ALTER TABLE "certificate" DROP CONSTRAINT IF EXISTS "certificate_fingerprint_key1";

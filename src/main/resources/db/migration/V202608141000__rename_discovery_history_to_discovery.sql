-- The table holds the live discovery run, not an archive of finished ones — "history" was a misnomer.
-- Constraint names follow so they keep naming the objects they constrain.
ALTER TABLE "discovery_history" RENAME TO "discovery";

ALTER TABLE "discovery" RENAME CONSTRAINT "discovery_history_pkey" TO "discovery_pkey";

ALTER TABLE "discovery_certificate"
    RENAME CONSTRAINT "discovery_certificate_to_discovery_history_key" TO "discovery_certificate_to_discovery_key";

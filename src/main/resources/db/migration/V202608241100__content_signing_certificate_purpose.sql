-- Per-profile certificate-purpose constraints for CONTENT_SIGNING profiles.
ALTER TABLE "signing_profile_version"
    ADD COLUMN "require_non_repudiation"          BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN "required_extended_key_usage_oids" TEXT[];

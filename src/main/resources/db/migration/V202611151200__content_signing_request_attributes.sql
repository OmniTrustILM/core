-- Allowed request attributes name the groups and attributes a formatting connector declares.
-- The stored parameter groups predate those names. Every profile therefore starts with none allowed.
-- Formatting attribute values replace the default parameters. The stored defaults are therefore dropped.
ALTER TABLE "signing_profile_version"
    DROP COLUMN "allowed_request_parameter_groups",
    DROP COLUMN "default_signature_parameters",
    ADD COLUMN "allowed_request_attributes" TEXT[] NOT NULL DEFAULT '{}';

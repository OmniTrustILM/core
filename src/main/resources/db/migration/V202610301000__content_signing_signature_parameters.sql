-- Request-parameter permission and defaults for CONTENT_SIGNING profiles.
ALTER TABLE "signing_profile_version"
    ADD COLUMN "allowed_request_parameter_groups" TEXT[],
    ADD COLUMN "default_signature_parameters"     JSONB;

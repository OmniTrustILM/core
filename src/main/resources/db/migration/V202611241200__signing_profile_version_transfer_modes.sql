-- The formatting connector names the transfer modes a content-signing profile's values allow when the profile is saved.
ALTER TABLE "signing_profile_version"
    ADD COLUMN "transfer_modes" TEXT[] NOT NULL DEFAULT '{}';

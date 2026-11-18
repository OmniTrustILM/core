-- A content-signing Signing Profile fixes the level of every signature it produces.
ALTER TABLE "signing_profile_version" RENAME COLUMN "max_signature_level" TO "signature_level";

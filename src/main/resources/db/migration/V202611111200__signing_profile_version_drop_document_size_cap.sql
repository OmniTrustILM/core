-- The column was never actually used. Signing behaves as before without it.
ALTER TABLE "signing_profile_version" DROP COLUMN "document_size_cap";

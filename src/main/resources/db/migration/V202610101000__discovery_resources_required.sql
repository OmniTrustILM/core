-- The discovery listing filters every run on what it targeted, whichever generation drove it. A v1 run can target
-- certificates only, and until now stored no resources at all.
UPDATE "discovery"
SET "resources" = ARRAY['CERTIFICATE']
WHERE "resources" IS NULL OR cardinality("resources") = 0;

ALTER TABLE "discovery" ALTER COLUMN "resources" SET NOT NULL;

-- Opt-in notification data categories on the parent profile. Null or empty means no
-- enrichment, so existing profiles keep today's behavior without a backfill.
ALTER TABLE "notification_profile"
    ADD COLUMN "event_data_categories" TEXT[];

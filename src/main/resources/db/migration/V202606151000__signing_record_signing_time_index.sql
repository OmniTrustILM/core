-- Signing Records dashboard statistics filter and bucket by signing_time across all profiles
-- (last-24h / last-7d counts and the volume-over-time series). The existing
-- idx_sr_profile_signing_time leads with signing_profile_uuid, so it cannot serve a
-- profile-independent signing_time range scan; add a standalone index for that access path.
CREATE INDEX idx_sr_signing_time
    ON "signing_record" ("signing_time");

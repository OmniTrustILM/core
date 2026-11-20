ALTER TABLE "discovery"
    ADD COLUMN "window_mode" TEXT,
    ADD COLUMN "window_lookback" TEXT,
    ADD COLUMN "discover_since" TIMESTAMP WITH TIME ZONE;

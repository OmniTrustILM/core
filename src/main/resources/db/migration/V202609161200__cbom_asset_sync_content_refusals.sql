-- How many times this CBOM's asset ingest refused the document for something the document itself says.
--
-- Every refusal reason the asset ingest had before the duplicated-bom-ref rule was transient -- a cluster lock, a
-- document read, a database error -- so the backlog needed neither an attempt counter nor a terminal state: it puts a
-- FAILED row back on the retry list once cbom.sync.ingest-retry-after has passed, and the next attempt could genuinely
-- differ. A refusal derived from the document's content cannot: the same bytes produce the same verdict, and the
-- producer's fix is a new version, which is a new row. Without a bound such a document is re-read over HTTP,
-- re-extracted and re-refused every run for ever, and takes one of cbom.sync.max-ingest-documents slots each time.
--
-- A counter rather than a flag, because the two content-derived refusals are not equally deterministic: a repeated
-- bom-ref is a pure function of the bytes, while an unavailable document scope is raised by an extraction that failed
-- and could have failed for a reason of the moment. One bound covers both, and it is only ever incremented by those
-- two refusals -- a transient failure leaves it alone and keeps retrying exactly as before.
ALTER TABLE "cbom" ADD COLUMN "asset_sync_content_refusals" INT NOT NULL DEFAULT 0;
ALTER TABLE "cbom"
    ADD CONSTRAINT "ck_cbom_asset_sync_content_refusals" CHECK ("asset_sync_content_refusals" >= 0);

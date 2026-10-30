package com.otilm.core.events.handlers.discovery;

import java.util.List;

/**
 * What one content group's import produced.
 *
 * @param certificateContentId the group's identity, and the only exact basis for counting gaps per certificate rather
 * than per row — a group that rolled back has no certificate UUID at all, because the certificate does not exist
 * @param committed false when the import transaction rolled back or never ran; the orchestrator merges key entries only
 * from committed groups
 */
public record GroupImportResult(Long certificateContentId, List<DiscoveryCertificateResult> rowResults,
        List<KeyQueueEntry> keyEntries, boolean committed) {
}

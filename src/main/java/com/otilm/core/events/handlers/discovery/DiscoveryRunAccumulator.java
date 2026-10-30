package com.otilm.core.events.handlers.discovery;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Holds a discovery run's per-row outcomes on the orchestrator thread.
 *
 * <p>
 * Not thread-safe by design: results arrive one group at a time on the thread consuming the parallel stream, so
 * synchronisation here would only mask a caller that had moved off it.
 */
public class DiscoveryRunAccumulator {

    private final Map<UUID, DiscoveryCertificateResult> resultsByRow = new LinkedHashMap<>();
    private final Map<UUID, List<UUID>> rowsByCertificate = new LinkedHashMap<>();
    private final Map<UUID, List<String>> keyFailureReasons = new LinkedHashMap<>();
    private final Set<Long> contentIdsWithInventoryGap = new LinkedHashSet<>();
    private final Set<Long> contentIdsNotAttempted = new LinkedHashSet<>();
    private final Set<Long> contentIdsWithKeyGap = new LinkedHashSet<>();
    private long bookkeepingFailures;
    private boolean validationNotQueued;

    public void accept(GroupImportResult group) {
        group.rowResults().forEach(result -> resultsByRow.put(result.discoveryCertificateUuid(), result));
        if (hasInventoryGap(group)) {
            contentIdsWithInventoryGap.add(group.certificateContentId());
        }
        if (hasOutcome(group, DiscoveryCertificateOutcome.NOT_ATTEMPTED)) {
            contentIdsNotAttempted.add(group.certificateContentId());
        }
        // A group can arrive already classified as a key gap when its import committed but its result never reached
        // the orchestrator. There is no certificate UUID to key that on, so it is counted by content instead.
        if (hasOutcome(group, DiscoveryCertificateOutcome.KEY_ASSOCIATION_FAILED)) {
            contentIdsWithKeyGap.add(group.certificateContentId());
        }
        if (group.committed()) {
            group
                    .keyEntries()
                    .forEach(entry -> rowsByCertificate
                            .computeIfAbsent(entry.certificateUuid(), key -> new ArrayList<>())
                            .addAll(entry.discoveryCertificateUuids()));
        }
    }

    /**
     * Re-classifies a committed certificate's rows once its key association has failed. Group results are immutable and
     * classified at import time, so a row that imported cleanly and only later lost its key has to be replaced rather
     * than mutated.
     *
     * <p>
     * A certificate whose group never committed has no rows registered here, so a late failure for it is ignored rather
     * than overwriting its rollback reason.
     */
    public void failKeyAssociation(UUID certificateUuid, String reason) {
        List<UUID> rows = rowsByCertificate.get(certificateUuid);
        if (rows == null) {
            return;
        }
        keyFailureReasons.computeIfAbsent(certificateUuid, key -> new ArrayList<>()).add(reason);
        // A hybrid certificate can fail both its primary and its alternative key; aggregate so the second
        // reason does not overwrite the first.
        String aggregated = String.join("; ", keyFailureReasons.get(certificateUuid));
        rows
                .forEach(row -> resultsByRow
                        .put(row, new DiscoveryCertificateResult(row,
                                DiscoveryCertificateOutcome.KEY_ASSOCIATION_FAILED, aggregated)));
    }

    public void recordBookkeepingFailure() {
        bookkeepingFailures++;
    }

    public void recordValidationNotQueued() {
        validationNotQueued = true;
    }

    public List<DiscoveryCertificateResult> results() {
        return List.copyOf(resultsByRow.values());
    }

    /**
     * Every certificate count is per certificate, not per row: a certificate found on ten hosts is one certificate, so
     * a failed or unattempted group counts once however many rows it carried. The status message says "certificate(s)"
     * for all of them, so mixing units here would make it lie.
     */
    public DiscoveryRunCounts counts() {
        return new DiscoveryRunCounts(contentIdsWithInventoryGap.size(),
                (long) keyFailureReasons.size() + contentIdsWithKeyGap.size(), contentIdsNotAttempted.size(),
                bookkeepingFailures, validationNotQueued);
    }

    private static boolean hasInventoryGap(GroupImportResult group) {
        return hasOutcome(group, DiscoveryCertificateOutcome.IMPORT_ROLLED_BACK,
                DiscoveryCertificateOutcome.ENTITY_CREATION_FAILED);
    }

    private static boolean hasOutcome(GroupImportResult group, DiscoveryCertificateOutcome... outcomes) {
        return group.rowResults().stream().anyMatch(result -> Arrays.asList(outcomes).contains(result.outcome()));
    }
}

package com.otilm.core.events.handlers.discovery;

import com.otilm.api.model.core.discovery.DiscoveryMessageSeverity;
import com.otilm.core.model.discovery.DiscoveryMessageCode;
import com.otilm.core.model.discovery.DiscoveryMessageDraft;
import java.util.ArrayList;
import java.util.List;

/**
 * The independent reasons a discovery reports a warning. Each contributes its own sentence to the status message, so
 * two simultaneous partial failures are both visible rather than the first hiding the rest.
 *
 * @param inventoryGaps certificates the connector reported that are absent from the inventory
 * @param keyGaps certificates imported without a public key association
 * @param notAttempted rows that never reached a verdict
 * @param bookkeepingFailures writes of per-certificate detail that themselves failed, leaving the persisted detail
 * knowingly incomplete
 * @param validationNotQueued the certificates imported but validation of them was never requested -- its own flag,
 * since a whole run left unvalidated is nothing like an unrecorded per-certificate reason
 */
public record DiscoveryRunCounts(long inventoryGaps, long keyGaps, long notAttempted, long bookkeepingFailures,
        boolean validationNotQueued) {

    public boolean allClear() {
        return inventoryGaps == 0 && keyGaps == 0 && notAttempted == 0 && bookkeepingFailures == 0
                && !validationNotQueued;
    }

    /**
     * One run message per reason this unit of work fell short, in a fixed order. Empty when nothing did.
     *
     * <p>
     * A v2 {@code PROCESS} batch counts only itself, so each of these carries its own count as occurrences rather than
     * inside its text: every batch reporting the same kind of gap aggregates onto one row, where embedding the count
     * would mint a distinct message per batch and bury the run's first one.
     */
    public List<DiscoveryMessageDraft> describeGaps() {
        return gaps()
                .stream()
                .map(gap -> new DiscoveryMessageDraft(DiscoveryMessageSeverity.WARNING, gap.code(), gap.message(),
                        gap.count()))
                .toList();
    }

    /**
     * The same reasons as counted sentences, for the v1 pass — which counts a whole run in one go and turns them into
     * its final status message, where a count that is not in the text has nowhere else to appear.
     */
    public List<String> renderGaps() {
        return gaps().stream().map(Gap::sentence).toList();
    }

    /**
     * The kinds of gap, listed once so the aggregated message and the counted sentence cannot drift apart.
     */
    private List<Gap> gaps() {
        List<Gap> gaps = new ArrayList<>();
        if (inventoryGaps > 0) {
            gaps
                    .add(new Gap(DiscoveryMessageCode.INVENTORY_GAP,
                            "A discovered certificate could not be imported into the inventory.",
                            "%d certificate(s) could not be imported into the inventory.".formatted(inventoryGaps),
                            inventoryGaps));
        }
        if (keyGaps > 0) {
            gaps
                    .add(new Gap(DiscoveryMessageCode.KEY_ASSOCIATION_GAP,
                            "A certificate was imported without all of its public keys associated.",
                            "%d certificate(s) were imported without all of their public keys associated."
                                    .formatted(keyGaps),
                            keyGaps));
        }
        if (notAttempted > 0) {
            gaps
                    .add(new Gap(DiscoveryMessageCode.CERTIFICATE_NOT_PROCESSED,
                            "A discovered certificate could not be processed to a result.",
                            "%d certificate(s) could not be processed to a result.".formatted(notAttempted),
                            notAttempted));
        }
        if (bookkeepingFailures > 0) {
            gaps
                    .add(new Gap(DiscoveryMessageCode.BOOKKEEPING_INCOMPLETE,
                            "Some per-certificate detail could not be recorded.",
                            "Some per-certificate detail could not be recorded.", bookkeepingFailures));
        }
        if (validationNotQueued) {
            gaps
                    .add(new Gap(DiscoveryMessageCode.VALIDATION_NOT_REQUESTED,
                            "Validation of the discovered certificates could not be requested.",
                            "Validation of the discovered certificates could not be requested.", 1));
        }
        return gaps;
    }

    private record Gap(DiscoveryMessageCode code, String message, String sentence, long count) {
    }

    /**
     * Whether any gap points at rows that carry a reason of their own. A bookkeeping failure means the detail never got
     * written, and validation never being requested says nothing about any individual row — pointing a reader at the
     * certificate list for either would contradict the sentence before it.
     */
    public boolean hasPerCertificateDetail() {
        return inventoryGaps + keyGaps + notAttempted > 0;
    }
}

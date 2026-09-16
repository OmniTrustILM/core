package com.otilm.core.service.impl;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What a run's counters have to say before the CBOM sync calls the repository sick rather than its documents.
 *
 * <p>
 * The verdict decides whether a run charges every failed read to the {@code cbom_sync_skip} retry budget or charges
 * nothing and is skipped, so getting it wrong in one direction writes an estate off and in the other holds the
 * watermark for ever. Tested as a pure function of the counters: a run that produces a thousand deferred entries is the
 * only other way to reach the charge cap, and it would prove less about which arm fired.
 */
class CbomSyncOutageVerdictTest {

    /** As the hourly pass sees a genuine outage: no read answered, and more than one document was left in the air. */
    @Test
    void anHourlyRunWhereNoReadAnsweredIsAnOutage() {
        assertThat(verdict(2, 2, 0, 0, false)).isTrue();
    }

    /** One document failing alone is that document's failure; a run must never hold the watermark for one entry. */
    @Test
    void oneDeferredDocumentIsNeverAnOutage() {
        assertThat(verdict(1, 1, 0, 0, false)).isFalse();
    }

    /** A read that answered proves the repository serves documents, whatever the rest of the run did. */
    @Test
    void aRunWithAnySuccessfulReadIsNotAnOutage() {
        assertThat(verdict(2, 2, 1, 0, false)).isFalse();
    }

    /**
     * The scope-aware arm. A whole-listing pass over an estate Core is in step with reads no documents at all, so "not
     * one read answered" is what a healthy reconciliation looks like. Recognising entries it holds is the evidence that
     * the listing -- and so the repository -- is being served.
     */
    @Test
    void aWholeListingRunThatRecognisedEntriesItHoldsIsNotAnOutage() {
        assertThat(verdict(2, 2, 0, 1, true)).isFalse();
    }

    /** And when it recognised nothing either, it has the same evidence the hourly pass acts on. */
    @Test
    void aWholeListingRunThatRecognisedNothingIsAnOutage() {
        assertThat(verdict(2, 2, 0, 0, true)).isTrue();
    }

    /**
     * The counter is {@code alreadyStored}, not the aggregate {@code duplicates} the summary line reports: that one
     * also counts an identity the feed offered twice within one run, which a whole-listing pass from {@code after = 0}
     * meets readily. This is the case a single repeated listing entry used to flip -- charging the whole estate.
     */
    @Test
    void aRepeatedListingEntryIsNotEvidenceThatCoreHoldsAnything() {
        assertThat(verdict(2, 2, 0, 0, true))
                .describedAs("a repeat raises duplicates and not alreadyStored, so the verdict is unmoved")
                .isTrue();
    }

    /**
     * The cap, which the other arms cannot reach. Beyond this many failed reads in one run the shared cause is the
     * repository, not that many individually broken documents -- and here every other arm says "charge them": reads
     * answered, so the run looks healthy by the original rule.
     */
    @Test
    void aRunThatWouldChargeMoreThanTheCapIsAnOutageWhateverElseItSaw() {
        assertThat(verdict(1_000, 1_000, 5, 50, true)).isTrue();
        assertThat(verdict(1_000, 1_000, 5, 50, false)).isTrue();
    }

    /** One below it is charged, so the bound is the bound and not an approximation of one. */
    @Test
    void aRunOneBelowTheCapIsStillCharged() {
        assertThat(verdict(999, 999, 5, 50, true)).isFalse();
    }

    private static boolean verdict(int deferred, int feedDeferred, int successfulReads, int alreadyStored,
            boolean wholeListing) {
        return CbomServiceImpl.looksLikeOutage(deferred, feedDeferred, successfulReads, alreadyStored, wholeListing);
    }
}

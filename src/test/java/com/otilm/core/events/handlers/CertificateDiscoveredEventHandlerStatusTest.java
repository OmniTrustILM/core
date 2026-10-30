package com.otilm.core.events.handlers;

import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.events.data.DiscoveryResult;
import com.otilm.core.events.handlers.discovery.DiscoveryRunCounts;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateDiscoveredEventHandlerStatusTest {

    private static final String ORIGINAL = "Downloaded 100 % of discovered certificates from provider (7 / 7)";
    private static final String TRAILER = "See the discovery certificate list for per-certificate detail.";

    @Test
    void cleanRunReportsProcessingAndKeepsTheOriginalMessage() {
        DiscoveryResult result = CertificateDiscoveredEventHandler
                .decideFinalStatus(new DiscoveryRunCounts(0, 0, 0, 0, false), ORIGINAL);

        assertThat(result.getDiscoveryStatus()).isEqualTo(DiscoveryStatus.PROCESSING);
        assertThat(result.getMessage()).isEqualTo(ORIGINAL);
    }

    @Test
    void inventoryGapsAloneAreReported() {
        DiscoveryResult result = CertificateDiscoveredEventHandler
                .decideFinalStatus(new DiscoveryRunCounts(3, 0, 0, 0, false), ORIGINAL);

        assertThat(result.getDiscoveryStatus()).isEqualTo(DiscoveryStatus.WARNING);
        assertThat(result.getMessage())
                .isEqualTo("3 certificate(s) could not be imported into the inventory. " + TRAILER);
    }

    @Test
    void keyGapsAloneAreReported() {
        DiscoveryResult result = CertificateDiscoveredEventHandler
                .decideFinalStatus(new DiscoveryRunCounts(0, 2, 0, 0, false), ORIGINAL);

        assertThat(result.getMessage())
                .isEqualTo("2 certificate(s) were imported without all of their public keys associated. " + TRAILER);
    }

    /**
     * No condition may take precedence over another: a run that hit several of them has to report all of them, not
     * whichever one the status logic happens to check first.
     */
    @Test
    void everyConditionContributesAndNoneMasksAnother() {
        DiscoveryResult result = CertificateDiscoveredEventHandler
                .decideFinalStatus(new DiscoveryRunCounts(3, 2, 1, 4, false), ORIGINAL);

        assertThat(result.getDiscoveryStatus()).isEqualTo(DiscoveryStatus.WARNING);
        assertThat(result.getMessage())
                .isEqualTo("3 certificate(s) could not be imported into the inventory. "
                        + "2 certificate(s) were imported without all of their public keys associated. "
                        + "1 certificate(s) could not be processed to a result. "
                        + "Some per-certificate detail could not be recorded. " + TRAILER);
    }

    @Test
    void aBookkeepingFailureAloneStillWarns() {
        DiscoveryResult result = CertificateDiscoveredEventHandler
                .decideFinalStatus(new DiscoveryRunCounts(0, 0, 0, 1, false), ORIGINAL);

        assertThat(result.getDiscoveryStatus())
                .as("the persisted detail is knowingly incomplete, so the run is not clean")
                .isEqualTo(DiscoveryStatus.WARNING);
        assertThat(result.getMessage())
                .as("no row carries a reason to go and read, so the pointer would contradict the sentence")
                .isEqualTo("Some per-certificate detail could not be recorded.");
    }

    /**
     * Its own sentence rather than a bookkeeping failure: the consequence is a whole run of unvalidated certificates,
     * which the per-certificate wording described neither accurately nor visibly.
     */
    @Test
    void validationNotQueuedIsReportedOnItsOwnTerms() {
        DiscoveryResult result = CertificateDiscoveredEventHandler
                .decideFinalStatus(new DiscoveryRunCounts(0, 0, 0, 0, true), ORIGINAL);

        assertThat(result.getDiscoveryStatus()).isEqualTo(DiscoveryStatus.WARNING);
        assertThat(result.getMessage()).isEqualTo("Validation of the discovered certificates could not be requested.");
        assertThat(result.getMessage()).doesNotContain("per-certificate detail could not be recorded");
    }

    /**
     * The pointer to the certificate list appears only when some row actually carries a reason. A run whose only fault
     * was the bookkeeping write has nothing there to read, and one whose only fault was validation never being
     * requested has nothing per-certificate at all.
     */
    @Test
    void thePointerToTheListAppearsOnlyWhenARowCarriesAReason() {
        assertThat(CertificateDiscoveredEventHandler
                .decideFinalStatus(new DiscoveryRunCounts(0, 0, 0, 1, true), ORIGINAL)
                .getMessage()).doesNotContain(TRAILER);
        assertThat(CertificateDiscoveredEventHandler
                .decideFinalStatus(new DiscoveryRunCounts(0, 0, 1, 1, true), ORIGINAL)
                .getMessage()).endsWith(TRAILER);
    }

    @Test
    void notAttemptedAloneStillWarns() {
        DiscoveryResult result = CertificateDiscoveredEventHandler
                .decideFinalStatus(new DiscoveryRunCounts(0, 0, 5, 0, false), ORIGINAL);

        assertThat(result.getDiscoveryStatus()).isEqualTo(DiscoveryStatus.WARNING);
        assertThat(result.getMessage()).isEqualTo("5 certificate(s) could not be processed to a result. " + TRAILER);
    }
}

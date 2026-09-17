package com.otilm.core.cbom.sync;

import com.otilm.api.model.core.settings.UtilsSettingsDto;
import java.time.Duration;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CbomSyncPolicyTest {

    @Test
    void theDefaultsAreTheDocumentedOnes() {
        assertThat(CbomSyncPolicy.DEFAULTS.overlap()).isEqualTo(Duration.ofSeconds(60));
        assertThat(CbomSyncPolicy.DEFAULTS.skippedRetryRuns()).isEqualTo(3);
        assertThat(CbomSyncPolicy.DEFAULTS.maxIngestDocuments()).isEqualTo(50);
        assertThat(CbomSyncPolicy.DEFAULTS.maxAttempts()).isEqualTo(4);
    }

    @Test
    void aMissingSettingsSectionMeansTheDefaults() {
        assertThat(CbomSyncPolicy.fromSettings(null)).isEqualTo(CbomSyncPolicy.DEFAULTS);
    }

    @Test
    void anUnsetValueTakesItsDefaultWhileTheOthersAreTaken() {
        UtilsSettingsDto utils = new UtilsSettingsDto();
        utils.setCbomSyncSkippedRetryRuns(0);

        CbomSyncPolicy policy = CbomSyncPolicy.fromSettings(utils);

        assertThat(policy.overlap()).isEqualTo(CbomSyncPolicy.DEFAULT_OVERLAP);
        assertThat(policy.skippedRetryRuns()).isZero();
        assertThat(policy.maxAttempts()).isEqualTo(1);
        assertThat(policy.maxIngestDocuments()).isEqualTo(CbomSyncPolicy.DEFAULT_MAX_INGEST_DOCUMENTS);
    }

    @Test
    void setValuesAreTakenAndTheOverlapIsReadAsSeconds() {
        UtilsSettingsDto utils = new UtilsSettingsDto();
        utils.setCbomSyncOverlapSeconds(120);
        utils.setCbomSyncSkippedRetryRuns(1);
        utils.setCbomSyncMaxIngestDocuments(0);

        CbomSyncPolicy policy = CbomSyncPolicy.fromSettings(utils);

        assertThat(policy).isEqualTo(new CbomSyncPolicy(Duration.ofMinutes(2), 1, 0));
    }

    @Test
    void aNegativeValueIsRefused() {
        assertThatThrownBy(() -> new CbomSyncPolicy(Duration.ofSeconds(-1), 3, 50))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("overlap");
        assertThatThrownBy(() -> new CbomSyncPolicy(null, 3, 50))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("overlap");
        assertThatThrownBy(() -> new CbomSyncPolicy(Duration.ZERO, -1, 50))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("retry budget");
        assertThatThrownBy(() -> new CbomSyncPolicy(Duration.ZERO, 3, -1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ingest budget");
    }

    @Test
    void aValueAboveTheContractCapIsRefused() {
        assertThatThrownBy(
                () -> new CbomSyncPolicy(Duration.ofSeconds(UtilsSettingsDto.MAX_CBOM_SYNC_OVERLAP_SECONDS + 1L), 3,
                        50))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("overlap");
        assertThatThrownBy(
                () -> new CbomSyncPolicy(Duration.ZERO, UtilsSettingsDto.MAX_CBOM_SYNC_SKIPPED_RETRY_RUNS + 1, 50))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("retry budget");
        assertThatThrownBy(
                () -> new CbomSyncPolicy(Duration.ZERO, 3, UtilsSettingsDto.MAX_CBOM_SYNC_MAX_INGEST_DOCUMENTS + 1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ingest budget");
    }

    @Test
    void theCapsThemselvesAreAccepted() {
        CbomSyncPolicy atTheCaps = new CbomSyncPolicy(
                Duration.ofSeconds(UtilsSettingsDto.MAX_CBOM_SYNC_OVERLAP_SECONDS),
                UtilsSettingsDto.MAX_CBOM_SYNC_SKIPPED_RETRY_RUNS, UtilsSettingsDto.MAX_CBOM_SYNC_MAX_INGEST_DOCUMENTS);

        assertThat(atTheCaps.maxAttempts()).isEqualTo(1 + UtilsSettingsDto.MAX_CBOM_SYNC_SKIPPED_RETRY_RUNS);
    }
}

package com.otilm.core.cbom.sync;

import com.otilm.api.model.core.settings.UtilsSettingsDto;
import java.time.Duration;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CbomSyncPolicyTest {

    /** The defaults with one component replaced, so a bound test names only the value it is about. */
    private static CbomSyncPolicy withOverlap(Duration overlap) {
        return policy(overlap, CbomSyncPolicy.DEFAULT_SKIPPED_RETRY_RUNS, CbomSyncPolicy.DEFAULT_MAX_INGEST_DOCUMENTS,
                CbomSyncPolicy.DEFAULT_SKIP_RETENTION_DAYS, CbomSyncPolicy.DEFAULT_PAGE_SIZE,
                CbomSyncPolicy.DEFAULT_ASSET_BATCH_SIZE, CbomSyncPolicy.DEFAULT_INGEST_RETRY_AFTER);
    }

    private static CbomSyncPolicy withSkippedRetryRuns(int skippedRetryRuns) {
        return policy(CbomSyncPolicy.DEFAULT_OVERLAP, skippedRetryRuns, CbomSyncPolicy.DEFAULT_MAX_INGEST_DOCUMENTS,
                CbomSyncPolicy.DEFAULT_SKIP_RETENTION_DAYS, CbomSyncPolicy.DEFAULT_PAGE_SIZE,
                CbomSyncPolicy.DEFAULT_ASSET_BATCH_SIZE, CbomSyncPolicy.DEFAULT_INGEST_RETRY_AFTER);
    }

    private static CbomSyncPolicy withMaxIngestDocuments(int maxIngestDocuments) {
        return policy(CbomSyncPolicy.DEFAULT_OVERLAP, CbomSyncPolicy.DEFAULT_SKIPPED_RETRY_RUNS, maxIngestDocuments,
                CbomSyncPolicy.DEFAULT_SKIP_RETENTION_DAYS, CbomSyncPolicy.DEFAULT_PAGE_SIZE,
                CbomSyncPolicy.DEFAULT_ASSET_BATCH_SIZE, CbomSyncPolicy.DEFAULT_INGEST_RETRY_AFTER);
    }

    private static CbomSyncPolicy withSkipRetentionDays(int skipRetentionDays) {
        return policy(CbomSyncPolicy.DEFAULT_OVERLAP, CbomSyncPolicy.DEFAULT_SKIPPED_RETRY_RUNS,
                CbomSyncPolicy.DEFAULT_MAX_INGEST_DOCUMENTS, skipRetentionDays, CbomSyncPolicy.DEFAULT_PAGE_SIZE,
                CbomSyncPolicy.DEFAULT_ASSET_BATCH_SIZE, CbomSyncPolicy.DEFAULT_INGEST_RETRY_AFTER);
    }

    private static CbomSyncPolicy withPageSize(int pageSize) {
        return policy(CbomSyncPolicy.DEFAULT_OVERLAP, CbomSyncPolicy.DEFAULT_SKIPPED_RETRY_RUNS,
                CbomSyncPolicy.DEFAULT_MAX_INGEST_DOCUMENTS, CbomSyncPolicy.DEFAULT_SKIP_RETENTION_DAYS, pageSize,
                CbomSyncPolicy.DEFAULT_ASSET_BATCH_SIZE, CbomSyncPolicy.DEFAULT_INGEST_RETRY_AFTER);
    }

    private static CbomSyncPolicy withAssetBatchSize(int assetBatchSize) {
        return policy(CbomSyncPolicy.DEFAULT_OVERLAP, CbomSyncPolicy.DEFAULT_SKIPPED_RETRY_RUNS,
                CbomSyncPolicy.DEFAULT_MAX_INGEST_DOCUMENTS, CbomSyncPolicy.DEFAULT_SKIP_RETENTION_DAYS,
                CbomSyncPolicy.DEFAULT_PAGE_SIZE, assetBatchSize, CbomSyncPolicy.DEFAULT_INGEST_RETRY_AFTER);
    }

    private static CbomSyncPolicy withIngestRetryAfter(Duration ingestRetryAfter) {
        return policy(CbomSyncPolicy.DEFAULT_OVERLAP, CbomSyncPolicy.DEFAULT_SKIPPED_RETRY_RUNS,
                CbomSyncPolicy.DEFAULT_MAX_INGEST_DOCUMENTS, CbomSyncPolicy.DEFAULT_SKIP_RETENTION_DAYS,
                CbomSyncPolicy.DEFAULT_PAGE_SIZE, CbomSyncPolicy.DEFAULT_ASSET_BATCH_SIZE, ingestRetryAfter);
    }

    private static CbomSyncPolicy policy(Duration overlap, int skippedRetryRuns, int maxIngestDocuments,
            int skipRetentionDays, int pageSize, int assetBatchSize, Duration ingestRetryAfter) {
        return new CbomSyncPolicy(overlap, skippedRetryRuns, maxIngestDocuments, skipRetentionDays, pageSize,
                CbomSyncPolicy.DEFAULT_ASSET_INGEST_ENABLED, assetBatchSize, ingestRetryAfter);
    }

    @Test
    void theDefaultsAreTheDocumentedOnes() {
        assertThat(CbomSyncPolicy.DEFAULTS.overlap()).isEqualTo(Duration.ofSeconds(60));
        assertThat(CbomSyncPolicy.DEFAULTS.skippedRetryRuns()).isEqualTo(3);
        assertThat(CbomSyncPolicy.DEFAULTS.maxIngestDocuments()).isEqualTo(50);
        assertThat(CbomSyncPolicy.DEFAULTS.skipRetentionDays()).isEqualTo(90);
        assertThat(CbomSyncPolicy.DEFAULTS.pageSize()).isEqualTo(1000);
        assertThat(CbomSyncPolicy.DEFAULTS.assetIngestEnabled()).isTrue();
        assertThat(CbomSyncPolicy.DEFAULTS.assetBatchSize()).isEqualTo(100);
        assertThat(CbomSyncPolicy.DEFAULTS.ingestRetryAfter()).isEqualTo(Duration.ofMinutes(30));
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
        utils.setCbomSyncAssetIngestEnabled(false);

        CbomSyncPolicy policy = CbomSyncPolicy.fromSettings(utils);

        assertThat(policy.overlap()).isEqualTo(CbomSyncPolicy.DEFAULT_OVERLAP);
        assertThat(policy.skippedRetryRuns()).isZero();
        assertThat(policy.maxAttempts()).isEqualTo(1);
        assertThat(policy.maxIngestDocuments()).isEqualTo(CbomSyncPolicy.DEFAULT_MAX_INGEST_DOCUMENTS);
        assertThat(policy.skipRetentionDays()).isEqualTo(CbomSyncPolicy.DEFAULT_SKIP_RETENTION_DAYS);
        assertThat(policy.pageSize()).isEqualTo(CbomSyncPolicy.DEFAULT_PAGE_SIZE);
        assertThat(policy.assetIngestEnabled()).isFalse();
        assertThat(policy.assetBatchSize()).isEqualTo(CbomSyncPolicy.DEFAULT_ASSET_BATCH_SIZE);
        assertThat(policy.ingestRetryAfter()).isEqualTo(CbomSyncPolicy.DEFAULT_INGEST_RETRY_AFTER);
    }

    @Test
    void setValuesAreTakenAndTheDurationsAreReadAsSeconds() {
        UtilsSettingsDto utils = new UtilsSettingsDto();
        utils.setCbomSyncOverlapSeconds(120);
        utils.setCbomSyncSkippedRetryRuns(1);
        utils.setCbomSyncMaxIngestDocuments(0);
        utils.setCbomSyncSkipRetentionDays(30);
        utils.setCbomSyncPageSize(250);
        utils.setCbomSyncAssetIngestEnabled(true);
        utils.setCbomSyncAssetBatchSize(25);
        utils.setCbomSyncIngestRetryAfterSeconds(60);

        CbomSyncPolicy policy = CbomSyncPolicy.fromSettings(utils);

        assertThat(policy)
                .isEqualTo(new CbomSyncPolicy(Duration.ofMinutes(2), 1, 0, 30, 250, true, 25, Duration.ofMinutes(1)));
    }

    @Test
    void aValueBelowItsFloorIsRefused() {
        assertThatThrownBy(() -> withOverlap(Duration.ofSeconds(-1)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("overlap");
        assertThatThrownBy(() -> withOverlap(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("overlap");
        assertThatThrownBy(() -> withSkippedRetryRuns(-1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("retry budget");
        assertThatThrownBy(() -> withMaxIngestDocuments(-1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ingest budget");
        assertThatThrownBy(() -> withSkipRetentionDays(0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("retention");
        assertThatThrownBy(() -> withPageSize(0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("page size");
        assertThatThrownBy(() -> withAssetBatchSize(0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("asset batch size");
        assertThatThrownBy(() -> withIngestRetryAfter(Duration.ofSeconds(-1)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ingest retry window");
        assertThatThrownBy(() -> withIngestRetryAfter(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ingest retry window");
    }

    @Test
    void aValueAboveTheContractCapIsRefused() {
        assertThatThrownBy(() -> withOverlap(Duration.ofSeconds(UtilsSettingsDto.MAX_CBOM_SYNC_OVERLAP_SECONDS + 1L)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("overlap");
        assertThatThrownBy(() -> withSkippedRetryRuns(UtilsSettingsDto.MAX_CBOM_SYNC_SKIPPED_RETRY_RUNS + 1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("retry budget");
        assertThatThrownBy(() -> withMaxIngestDocuments(UtilsSettingsDto.MAX_CBOM_SYNC_MAX_INGEST_DOCUMENTS + 1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ingest budget");
        assertThatThrownBy(() -> withSkipRetentionDays(UtilsSettingsDto.MAX_CBOM_SYNC_SKIP_RETENTION_DAYS + 1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("retention");
        assertThatThrownBy(() -> withPageSize(UtilsSettingsDto.MAX_CBOM_SYNC_PAGE_SIZE + 1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("page size");
        assertThatThrownBy(() -> withAssetBatchSize(UtilsSettingsDto.MAX_CBOM_SYNC_ASSET_BATCH_SIZE + 1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("asset batch size");
        assertThatThrownBy(() -> withIngestRetryAfter(
                Duration.ofSeconds(UtilsSettingsDto.MAX_CBOM_SYNC_INGEST_RETRY_AFTER_SECONDS + 1L)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ingest retry window");
    }

    /**
     * The bound the settings API refuses on the way in is the bound this refuses, on every value -- so a policy the
     * settings service builds from a stored value it accepted can never fail construction here.
     */
    @Test
    void theContractBoundsAreAccepted() {
        assertThat(withOverlap(Duration.ofSeconds(UtilsSettingsDto.MAX_CBOM_SYNC_OVERLAP_SECONDS)).overlap())
                .isEqualTo(Duration.ofSeconds(UtilsSettingsDto.MAX_CBOM_SYNC_OVERLAP_SECONDS));
        assertThat(withSkippedRetryRuns(UtilsSettingsDto.MAX_CBOM_SYNC_SKIPPED_RETRY_RUNS).skippedRetryRuns())
                .isEqualTo(UtilsSettingsDto.MAX_CBOM_SYNC_SKIPPED_RETRY_RUNS);
        assertThat(withMaxIngestDocuments(UtilsSettingsDto.MAX_CBOM_SYNC_MAX_INGEST_DOCUMENTS).maxIngestDocuments())
                .isEqualTo(UtilsSettingsDto.MAX_CBOM_SYNC_MAX_INGEST_DOCUMENTS);
        assertThat(withSkippedRetryRuns(UtilsSettingsDto.MAX_CBOM_SYNC_SKIPPED_RETRY_RUNS).maxAttempts())
                .isEqualTo(1 + UtilsSettingsDto.MAX_CBOM_SYNC_SKIPPED_RETRY_RUNS);
        assertThat(withSkipRetentionDays(UtilsSettingsDto.MIN_CBOM_SYNC_SKIP_RETENTION_DAYS).skipRetentionDays())
                .isEqualTo(UtilsSettingsDto.MIN_CBOM_SYNC_SKIP_RETENTION_DAYS);
        assertThat(withSkipRetentionDays(UtilsSettingsDto.MAX_CBOM_SYNC_SKIP_RETENTION_DAYS).skipRetentionDays())
                .isEqualTo(UtilsSettingsDto.MAX_CBOM_SYNC_SKIP_RETENTION_DAYS);
        assertThat(withPageSize(UtilsSettingsDto.MIN_CBOM_SYNC_PAGE_SIZE).pageSize())
                .isEqualTo(UtilsSettingsDto.MIN_CBOM_SYNC_PAGE_SIZE);
        assertThat(withPageSize(UtilsSettingsDto.MAX_CBOM_SYNC_PAGE_SIZE).pageSize())
                .isEqualTo(UtilsSettingsDto.MAX_CBOM_SYNC_PAGE_SIZE);
        assertThat(withAssetBatchSize(UtilsSettingsDto.MIN_CBOM_SYNC_ASSET_BATCH_SIZE).assetBatchSize())
                .isEqualTo(UtilsSettingsDto.MIN_CBOM_SYNC_ASSET_BATCH_SIZE);
        assertThat(withAssetBatchSize(UtilsSettingsDto.MAX_CBOM_SYNC_ASSET_BATCH_SIZE).assetBatchSize())
                .isEqualTo(UtilsSettingsDto.MAX_CBOM_SYNC_ASSET_BATCH_SIZE);
        assertThat(withIngestRetryAfter(Duration.ZERO).ingestRetryAfter()).isEqualTo(Duration.ZERO);
        assertThat(withIngestRetryAfter(Duration.ofSeconds(UtilsSettingsDto.MAX_CBOM_SYNC_INGEST_RETRY_AFTER_SECONDS))
                .ingestRetryAfter())
                .isEqualTo(Duration.ofSeconds(UtilsSettingsDto.MAX_CBOM_SYNC_INGEST_RETRY_AFTER_SECONDS));
    }
}

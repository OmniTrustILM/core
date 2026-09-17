package com.otilm.core.config;

import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CbomSyncPropertiesTest {

    @Test
    void theDefaultValuesBindWhenNoPropertyIsSet() {
        Binder binder = new Binder(new MapConfigurationPropertySource(Map.of()));
        CbomSyncProperties bound = binder.bindOrCreate("cbom.sync", Bindable.of(CbomSyncProperties.class));
        assertThat(bound).isEqualTo(properties(1000));
    }

    /**
     * The kill switch. An ingest budget of 0 (a platform setting) disables only the backlog pass, so it cannot stop a
     * newly stored CBOM from acquiring {@code crypto_asset_source} rows -- and a CBOM that has them cannot be deleted
     * through the API until the deletion lifecycle lands. This is the value that covers both passes.
     */
    @Test
    void assetIngestIsOnByDefaultAndCanBeTurnedOff() {
        Binder defaults = new Binder(new MapConfigurationPropertySource(Map.of()));
        assertThat(defaults.bindOrCreate("cbom.sync", Bindable.of(CbomSyncProperties.class)).assetIngestEnabled())
                .isTrue();

        Binder off = new Binder(new MapConfigurationPropertySource(Map.of("cbom.sync.asset-ingest-enabled", "false")));
        assertThat(off.bindOrCreate("cbom.sync", Bindable.of(CbomSyncProperties.class)).assetIngestEnabled()).isFalse();
    }

    @Test
    void aPageSizeOutsideTheRepositoryContractIsRefused() {
        assertThatThrownBy(() -> properties(0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cbom.sync.page-size");
        assertThatThrownBy(() -> properties(1001))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cbom.sync.page-size");
    }

    @Test
    void theIngestTunablesBindTheirDocumentedDefaults() {
        Binder binder = new Binder(new MapConfigurationPropertySource(Map.of()));
        CbomSyncProperties bound = binder.bindOrCreate("cbom.sync", Bindable.of(CbomSyncProperties.class));
        assertThat(bound.assetBatchSize()).isEqualTo(100);
        assertThat(bound.ingestRetryAfter()).isEqualTo(Duration.ofMinutes(30));
    }

    @Test
    void aBareIngestRetryNumberBindsAsSecondsLikeTheOverlap() {
        Binder binder = new Binder(new MapConfigurationPropertySource(Map.of("cbom.sync.ingest-retry-after", "90")));
        CbomSyncProperties bound = binder.bindOrCreate("cbom.sync", Bindable.of(CbomSyncProperties.class));
        assertThat(bound.ingestRetryAfter()).isEqualTo(Duration.ofSeconds(90));
    }

    @Test
    void anUnusableIngestBoundIsRefused() {
        Duration retryAfter = Duration.ofMinutes(30);
        assertThatThrownBy(() -> new CbomSyncProperties(1000, true, 0, retryAfter))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cbom.sync.asset-batch-size");
        assertThatThrownBy(() -> new CbomSyncProperties(1000, true, 100, Duration.ofSeconds(-1)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cbom.sync.ingest-retry-after");
    }

    /**
     * The values this test does not vary, so a new bound cannot be added without a test naming it. The operator policy
     * (overlap, retry budget, ingest budget) is not bound here at all: it is a platform setting, see
     * CbomSyncPolicyTest.
     */
    private static CbomSyncProperties properties(int pageSize) {
        return new CbomSyncProperties(pageSize, true, 100, Duration.ofMinutes(30));
    }
}

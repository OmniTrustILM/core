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
    void theDocumentedDefaultsAreAccepted() {
        CbomSyncProperties p = new CbomSyncProperties(1000, Duration.ofSeconds(60), 3);
        assertThat(p.maxAttempts()).isEqualTo(4);
    }

    @Test
    void theDefaultValuesBindWhenNoPropertyIsSet() {
        Binder binder = new Binder(new MapConfigurationPropertySource(Map.of()));
        CbomSyncProperties bound = binder.bindOrCreate("cbom.sync", Bindable.of(CbomSyncProperties.class));
        assertThat(bound).isEqualTo(new CbomSyncProperties(1000, Duration.ofSeconds(60), 3));
    }

    @Test
    void aBareOverlapNumberBindsAsSeconds() {
        // Without @DurationUnit Spring reads a unitless duration as milliseconds, so CBOM_SYNC_OVERLAP=60 would bind
        // as 60 ms and toSeconds() would round it away to no overlap at all.
        Binder binder = new Binder(new MapConfigurationPropertySource(Map.of("cbom.sync.overlap", "60")));
        CbomSyncProperties bound = binder.bindOrCreate("cbom.sync", Bindable.of(CbomSyncProperties.class));
        assertThat(bound.overlap()).isEqualTo(Duration.ofSeconds(60));
    }

    @Test
    void anOverlapWithAUnitSuffixStillBindsByThatUnit() {
        Binder binder = new Binder(new MapConfigurationPropertySource(Map.of("cbom.sync.overlap", "2m")));
        CbomSyncProperties bound = binder.bindOrCreate("cbom.sync", Bindable.of(CbomSyncProperties.class));
        assertThat(bound.overlap()).isEqualTo(Duration.ofSeconds(120));
    }

    @Test
    void zeroRetryRunsMeansAFailedEntryIsWrittenOffAtOnce() {
        assertThat(new CbomSyncProperties(1, Duration.ZERO, 0).maxAttempts()).isEqualTo(1);
    }

    @Test
    void aPageSizeOutsideTheRepositoryContractIsRefused() {
        Duration overlap = Duration.ofSeconds(60);
        assertThatThrownBy(() -> new CbomSyncProperties(0, overlap, 3))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cbom.sync.page-size");
        assertThatThrownBy(() -> new CbomSyncProperties(1001, overlap, 3))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cbom.sync.page-size");
    }

    @Test
    void aNegativeOverlapOrRetryBudgetIsRefused() {
        Duration negative = Duration.ofSeconds(-1);
        Duration overlap = Duration.ofSeconds(60);
        assertThatThrownBy(() -> new CbomSyncProperties(1000, negative, 3))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cbom.sync.overlap");
        assertThatThrownBy(() -> new CbomSyncProperties(1000, null, 3))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cbom.sync.overlap");
        assertThatThrownBy(() -> new CbomSyncProperties(1000, overlap, -1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cbom.sync.skipped-retry-runs");
    }
}

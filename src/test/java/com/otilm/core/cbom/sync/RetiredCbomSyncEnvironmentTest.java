package com.otilm.core.cbom.sync;

import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RetiredCbomSyncEnvironmentTest {

    @Test
    void anEnvironmentThatSetsNoneOfThemIsSilent() {
        assertThat(RetiredCbomSyncEnvironment.stillSet(name -> null)).isEmpty();
        assertThat(RetiredCbomSyncEnvironment.stillSet(name -> "")).isEmpty();
        assertThat(RetiredCbomSyncEnvironment.stillSet(name -> "  ")).isEmpty();
    }

    /** Both halves of the move are named: core#2265's three and core#2268's four. */
    @Test
    void everyRetiredVariableIsReported() {
        assertThat(RetiredCbomSyncEnvironment.stillSet(name -> "set"))
                .containsExactlyElementsOf(RetiredCbomSyncEnvironment.RETIRED_VARIABLES);
        assertThat(RetiredCbomSyncEnvironment.RETIRED_VARIABLES)
                .contains("CBOM_SYNC_OVERLAP", "CBOM_SYNC_SKIPPED_RETRY_RUNS", "CBOM_SYNC_MAX_INGEST_DOCUMENTS",
                        "CBOM_SYNC_PAGE_SIZE", "CBOM_SYNC_ASSET_INGEST_ENABLED", "CBOM_SYNC_ASSET_BATCH_SIZE",
                        "CBOM_SYNC_INGEST_RETRY_AFTER");
    }

    /** The kill switch is the sharp case: its old value said "off", and ignoring it leaves ingest on. */
    @Test
    void onlyTheVariablesActuallySetAreReported() {
        Map<String, String> environment = Map.of("CBOM_SYNC_ASSET_INGEST_ENABLED", "false", "PATH", "/usr/bin");

        assertThat(RetiredCbomSyncEnvironment.stillSet(environment::get))
                .containsExactly("CBOM_SYNC_ASSET_INGEST_ENABLED");
    }
}

package com.otilm.core.mapper.discovery;

import com.otilm.api.model.client.discovery.DiscoveryDetailDto;
import com.otilm.core.dao.entity.Discovery;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The counts a detail response carries that the run row does not hold. Each comes from a table of its own, so the
 * mapper takes them from the caller; they are all longs, so a set handed over in the wrong order would still compile.
 */
class DiscoveryDtoMapperTest {

    @Test
    void everyCountLandsOnTheFieldThatNamesIt() {
        DiscoveryDetailDto dto = DiscoveryDtoMapper
                .toDetailDto(run(), new DiscoveryDtoMapper.DetailCounts(3, 11, 7, 2));

        assertThat(dto.getRunMessageCount()).isEqualTo(3);
        assertThat(dto.getItemsNewlyDiscovered()).isEqualTo(11);
        assertThat(dto.getItemsProcessed()).isEqualTo(7);
        assertThat(dto.getItemsFailed()).isEqualTo(2);
    }

    @Test
    void aRunThatFoundOnlyKnownItems_reportsNoneNewRatherThanNothingAtAll() {
        DiscoveryDetailDto dto = DiscoveryDtoMapper.toDetailDto(run(), new DiscoveryDtoMapper.DetailCounts(0, 0, 0, 0));

        // A re-scan of a known host stages items and adds none. The field is primitive and REQUIRED precisely so
        // that answer is on the wire as 0, rather than absent and read as "not reported".
        assertThat(dto.getItemsNewlyDiscovered()).isZero();
        assertThat(dto.getItemsProcessed()).isZero();
        assertThat(dto.getItemsFailed()).isZero();
    }

    private static Discovery run() {
        Discovery run = new Discovery();
        run.setUuid(UUID.randomUUID());
        run.setConnectorUuid(UUID.randomUUID());
        return run;
    }
}

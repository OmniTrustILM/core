package com.otilm.core.model.cbom;

import com.otilm.core.dao.entity.Cbom;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CbomHeaderCountsTest {

    @Test
    void absentStatisticsCountAsZero() {
        assertThat(CbomHeaderCounts.from(null)).isEqualTo(CbomHeaderCounts.ZERO);
        assertThat(CbomHeaderCounts.from(new CryptoStatsDto())).isEqualTo(CbomHeaderCounts.ZERO);
    }

    @Test
    void aPartiallyFilledStatisticsObjectCountsWhatItHas() {
        CryptoAssetCountDto five = new CryptoAssetCountDto();
        five.setTotal(5);
        CryptoAssetsDto assets = new CryptoAssetsDto();
        assets.setAlgorithms(five);
        assets.setCertificates(new CryptoAssetCountDto()); // total null
        assets.setTotal(5);
        CryptoStatsDto stats = new CryptoStatsDto();
        stats.setCryptoAssets(assets);

        assertThat(CbomHeaderCounts.from(stats)).isEqualTo(new CbomHeaderCounts(5, 0, 0, 0, 5));
    }

    @Test
    void appliesEveryCountToTheRow() {
        Cbom cbom = new Cbom();
        new CbomHeaderCounts(1, 2, 3, 4, 10).applyTo(cbom);

        assertThat(cbom.getAlgorithmsCount()).isEqualTo(1);
        assertThat(cbom.getCertificatesCount()).isEqualTo(2);
        assertThat(cbom.getProtocolsCount()).isEqualTo(3);
        assertThat(cbom.getCryptoMaterialCount()).isEqualTo(4);
        assertThat(cbom.getTotalAssetsCount()).isEqualTo(10);
    }
}

package com.otilm.core.integration.api.web;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.web.CryptographicAssetController;
import com.otilm.api.interfaces.core.web.StatisticsController;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.dashboard.CryptographicAssetStatisticsDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetDetailDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.core.auth.ContextRefreshListener;
import com.otilm.core.cbom.asset.AssetRowKeys;
import com.otilm.core.cbom.asset.CryptoAssetIdentityFields;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.auth.ResourceSyncRequestDto;
import com.otilm.core.service.writer.cbom.CryptoAssetWriter;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The cryptographic asset inventory endpoints exist so the contract ratified in interfaces#909 is served by a real
 * bean, and core#2145 finished the job: list, searchable-fields, detail and statistics are all real reads over the
 * deduplicated cross-CBOM asset projection now, with no operation left refusing. The resource still reaches the auth
 * service with its list and detail actions, so roles can be defined against it independently of which operations exist.
 */
class CryptographicAssetControllerITest extends BaseSpringBootTest {

    @Autowired
    private CryptographicAssetController cryptographicAssetController;

    @Autowired
    private StatisticsController statisticsController;

    @Autowired
    private ContextRefreshListener contextRefreshListener;

    @Autowired
    private CryptoAssetWriter assetWriter;

    @Test
    void everyInventoryOperationIsServed() throws NotFoundException {
        PaginationResponseDto<CryptographicAssetDto> page = cryptographicAssetController
                .listCryptographicAssets(new SearchRequestDto());
        assertThat(page.getItems()).isEmpty();
        assertThat(page.getTotalItems()).isZero();

        assertThat(cryptographicAssetController.getSearchableFieldInformation()).isNotEmpty();

        UUID seededUuid = seedOneAsset();
        CryptographicAssetDetailDto detail = cryptographicAssetController.getCryptographicAsset(seededUuid);
        assertThat(detail.getUuid()).isEqualTo(seededUuid);

        CryptographicAssetStatisticsDto statistics = statisticsController.getCryptographicAssetStatistics();
        assertThat(statistics).isNotNull();
        // BaseSpringBootTest truncates before each test and this method seeds exactly one asset above, so the count
        // is deterministic, not merely non-negative.
        assertThat(statistics.getTotalAssets()).isEqualTo(1L);
    }

    @Test
    void theResourceIsRegisteredWithItsReadActions() {
        ResourceSyncRequestDto synced = contextRefreshListener
                .getResources()
                .stream()
                .filter(resource -> resource.getName().getCode().equals(Resource.CRYPTO_ASSET.getCode()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Resource not synced: " + Resource.CRYPTO_ASSET.getCode()));

        assertThat(synced.getActions()).contains(ResourceAction.LIST.getCode(), ResourceAction.DETAIL.getCode());
        assertThat(synced.getListObjectsEndpoint())
                .describedAs("the one auth-sync behaviour @AuthEndpoint adds: the advertised object listing route")
                .isEqualTo("/v1/cryptoAssets");
    }

    private UUID seedOneAsset() {
        CryptoAssetIdentityFields fields = new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM,
                "aes-256-gcm", null, null, null, null, null, null, null, null);
        return assetWriter.upsertIdentity(AssetRowKeys.forFields(fields), fields, null);
    }
}

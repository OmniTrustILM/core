package com.otilm.core.service.impl;

import com.otilm.api.model.core.cbom.CbomContributedAssetDto;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.core.model.cbom.CryptoAssetListRow;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** How a CBOM-scoped page joins its inventory rows to that CBOM's refs. */
class CryptographicAssetServiceImplContributedRowsTest {

    /**
     * The page and the refs are read in separate statements, so the CBOM's source row for a paged asset can be
     * withdrawn in between. That asset is no longer the CBOM's contribution and is left out, rather than served with no
     * refs as though every ref it had were unstorable; a contribution whose refs really are empty is still served.
     */
    @Test
    void aRowWhoseSourceWasWithdrawnAfterThePageWasReadIsLeftOut() {
        CryptoAssetListRow linked = row("aes-256");
        CryptoAssetListRow withdrawn = row("rsa-2048");
        CryptoAssetListRow unlinked = row("sha-256");
        Map<UUID, List<String>> bomRefsByAsset = Map.of(linked.uuid(), List.of("a1", "a2"), unlinked.uuid(), List.of());

        List<CbomContributedAssetDto> rows = CryptographicAssetServiceImpl
                .contributedRows(List.of(linked, withdrawn, unlinked), bomRefsByAsset);

        assertThat(rows).extracting(CbomContributedAssetDto::getUuid).containsExactly(linked.uuid(), unlinked.uuid());
        assertThat(rows)
                .extracting(CbomContributedAssetDto::getBomRefs)
                .containsExactly(List.of("a1", "a2"), List.of());
    }

    private static CryptoAssetListRow row(String name) {
        return new CryptoAssetListRow(UUID.randomUUID(), name, null, CryptographicAssetType.ALGORITHM, null, 1, null,
                1);
    }
}

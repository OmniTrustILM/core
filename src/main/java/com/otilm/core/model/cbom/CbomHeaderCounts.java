package com.otilm.core.model.cbom;

import com.otilm.core.dao.entity.Cbom;

/**
 * The five per-CBOM asset counts the {@code cbom} row carries, as the repository feed reports them.
 *
 * <p>
 * Every count is advisory: legacy objects hold a shallow count and, in paged mode, an object whose statistics could not
 * be read arrives with {@code cryptoStats: null}. Such an entry is still stored -- with zero counts, left for the asset
 * ingest recount -- so the whole shape is null-tolerant and never throws.
 */
public record CbomHeaderCounts(int algorithms, int certificates, int protocols, int cryptoMaterial, int totalAssets) {

    public static final CbomHeaderCounts ZERO = new CbomHeaderCounts(0, 0, 0, 0, 0);

    public static CbomHeaderCounts from(CryptoStatsDto stats) {
        if (stats == null || stats.getCryptoAssets() == null) {
            return ZERO;
        }
        CryptoAssetsDto assets = stats.getCryptoAssets();
        return new CbomHeaderCounts(total(assets.getAlgorithms()), total(assets.getCertificates()),
                total(assets.getProtocols()), total(assets.getRelatedCryptoMaterials()),
                assets.getTotal() == null ? 0 : assets.getTotal());
    }

    public void applyTo(Cbom cbom) {
        cbom.setAlgorithmsCount(algorithms);
        cbom.setCertificatesCount(certificates);
        cbom.setProtocolsCount(protocols);
        cbom.setCryptoMaterialCount(cryptoMaterial);
        cbom.setTotalAssetsCount(totalAssets);
    }

    private static int total(CryptoAssetCountDto count) {
        return count == null || count.getTotal() == null ? 0 : count.getTotal();
    }
}

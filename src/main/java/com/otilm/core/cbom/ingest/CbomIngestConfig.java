package com.otilm.core.cbom.ingest;

import com.otilm.core.cbom.asset.identity.AssetNormalizer;
import com.otilm.core.cbom.asset.identity.CbomAssetExtractor;
import com.otilm.core.cbom.asset.identity.CryptoAssetIdentity;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * The extractor as an injectable bean, over the same ratified tables the PQC evaluator uses.
 *
 * <p>
 * Not {@code @Lazy}, and deliberately so rather than by oversight: {@link CbomAssetIngestService} is eager and
 * constructor-injects this bean, which would build it at refresh whatever this declaration said. The tables therefore
 * load at boot, and an artifact that fails to load refuses the application rather than the first ingest.
 */
@Configuration
public class CbomIngestConfig {

    @Bean
    public CbomAssetExtractor cbomAssetExtractor(AssetNormalizer assetNormalizer) {
        return new CbomAssetExtractor(new CryptoAssetIdentity(assetNormalizer));
    }
}

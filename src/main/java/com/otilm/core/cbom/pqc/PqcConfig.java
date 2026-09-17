package com.otilm.core.cbom.pqc;

import com.otilm.core.cbom.asset.identity.AssetNormalizer;
import com.otilm.core.cbom.asset.identity.IdentityTables;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;

/**
 * The ratified tables are a classpath resource; loading them once is what makes {@link PqcEvaluator} injectable.
 *
 * <p>
 * Lazy, as is the evaluator, so that a caller reaching for either builds the tables only when it needs them.
 *
 * <p>
 * It no longer follows that an artifact which fails to load fails the sweep rather than the application: since
 * core#2073 the eager {@code CbomAssetIngestService} constructor-injects {@code CbomAssetExtractor}, which is built
 * over this bean at refresh, so the tables load at boot and a bad artifact refuses the application. {@code Lazy} is
 * kept because it still describes every other path, and {@code CbomIngestConfig} states the eager one where it is made.
 */
@Configuration
public class PqcConfig {

    @Bean
    @Lazy
    public AssetNormalizer assetNormalizer() {
        return new AssetNormalizer(IdentityTables.load());
    }
}

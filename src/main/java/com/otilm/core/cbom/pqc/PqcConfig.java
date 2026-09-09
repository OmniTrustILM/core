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
 * Lazy, as is the evaluator, so that an artifact that fails to load fails the sweep that asks for it rather than
 * refusing the whole application at boot. A caller that wants to keep that property injects the evaluator lazily too.
 */
@Configuration
public class PqcConfig {

    @Bean
    @Lazy
    public AssetNormalizer assetNormalizer() {
        return new AssetNormalizer(IdentityTables.load());
    }
}

package com.otilm.core.key.normalization;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.util.MutationFuzzing;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;

class JceksSealedKeyFuzzTest {

    private static final KeyNormalizer NORMALIZER = new KeyNormalizer();

    private static final long SEED = 1L;

    private static final int MUTANTS = 500;

    private static byte[] sealedKey;

    @BeforeAll
    static void sealedKey() throws Exception {
        KeyFiles.registerProviders();
        sealedKey = SecretKeyFiles.sealedKey(SecretKeyFiles.jceks(SecretKeyFiles.aes(256)));
    }

    @Test
    void describe_endsEveryMutantOfASealedKeyInADescriptionOrARefusal() {
        // given
        Passphrase passphrase = KeyFiles.passphrase();

        // when, then
        assertThatCode(() -> MutationFuzzing
                .assertOnlyDefinedOutcomes(sealedKey, SEED, MUTANTS,
                        mutant -> NORMALIZER.describe(mutant, passphrase, DerivationBudget.forFile()),
                        ValidationException.class::isInstance))
                .doesNotThrowAnyException();
    }
}

package com.otilm.core.key.normalization;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.util.MutationFuzzing;
import java.security.KeyPair;
import java.util.stream.Stream;
import org.bouncycastle.openssl.PKCS8Generator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.junit.jupiter.api.Named.named;

class KeyNormalizerFuzzTest {

    private static final KeyNormalizer NORMALIZER = new KeyNormalizer();

    private static final long SEED = 1L;

    private static final int MUTANTS = 500;

    @BeforeAll
    static void providers() {
        KeyFiles.registerProviders();
    }

    @ParameterizedTest
    @MethodSource("validFiles")
    void describe_endsEveryMutantInADescriptionOrARefusal(byte[] file) {
        // given
        Passphrase passphrase = KeyFiles.passphrase();

        // when, then
        assertThatCode(() -> MutationFuzzing
                .assertOnlyDefinedOutcomes(file, SEED, MUTANTS,
                        mutant -> NORMALIZER.describe(mutant, passphrase, DerivationBudget.forFile()),
                        ValidationException.class::isInstance))
                .doesNotThrowAnyException();
    }

    static Stream<Named<byte[]>> validFiles() throws Exception {
        KeyPair ec = KeyFiles.ec();
        return Stream
                .of(named("plain PKCS#8", KeyFiles.pkcs8(ec)),
                        named("encrypted PKCS#8",
                                KeyFiles.encrypted(ec, PKCS8Generator.AES_256_CBC, PKCS8Generator.PRF_HMACSHA256)),
                        named("traditional encrypted PEM", KeyFiles.traditional(KeyFiles.rsa(), "AES-256-CBC")));
    }
}

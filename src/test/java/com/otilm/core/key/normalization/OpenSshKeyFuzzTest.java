package com.otilm.core.key.normalization;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.util.MutationFuzzing;
import java.io.IOException;
import java.io.InputStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.junit.jupiter.api.Named.named;

class OpenSshKeyFuzzTest {

    private static final KeyNormalizer NORMALIZER = new KeyNormalizer();

    private static final long SEED = 1L;

    private static final int MUTANTS = 300;

    private static final Passphrase PASSPHRASE = new Passphrase("openssh-test-passphrase".toCharArray());

    @BeforeAll
    static void providers() {
        KeyFiles.registerProviders();
    }

    @ParameterizedTest
    @MethodSource("validFiles")
    void describe_endsEveryMutantInADescriptionOrARefusal(byte[] file) {
        // when, then
        assertThatCode(() -> MutationFuzzing
                .assertOnlyDefinedOutcomes(file, SEED, MUTANTS,
                        mutant -> NORMALIZER.describe(mutant, PASSPHRASE, DerivationBudget.forFile()),
                        ValidationException.class::isInstance))
                .doesNotThrowAnyException();
    }

    static Stream<Named<byte[]>> validFiles() throws IOException {
        return Stream.of(named("plain RSA", fixture("rsa-plain")), named("bcrypt RSA", fixture("rsa-bcrypt")));
    }

    private static byte[] fixture(String name) throws IOException {
        try (InputStream in = OpenSshKeyFuzzTest.class.getClassLoader().getResourceAsStream("key/openssh/" + name)) {
            return in.readAllBytes();
        }
    }
}

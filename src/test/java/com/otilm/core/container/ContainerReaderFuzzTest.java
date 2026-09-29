package com.otilm.core.container;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.container.ContainerFixtures.Chain;
import com.otilm.core.util.MutationFuzzing;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static com.otilm.core.container.ContainerFixtures.LF;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.junit.jupiter.api.Named.named;

class ContainerReaderFuzzTest {

    private static final long SEED = 1L;

    private static final int MUTANTS = 500;

    private static ContainerReader reader;

    @BeforeAll
    static void fixtures() {
        ContainerFixtures.registerProviders();
        reader = ContainerFixtures.reader();
    }

    @ParameterizedTest
    @MethodSource("validFiles")
    void read_endsEveryMutantInEntriesOrARefusal(byte[] file) {
        // given
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when, then
        assertThatCode(() -> MutationFuzzing
                .assertOnlyDefinedOutcomes(file, SEED, MUTANTS, mutant -> reader.read(mutant, passphrase),
                        ValidationException.class::isInstance))
                .doesNotThrowAnyException();
    }

    static Stream<Named<byte[]>> validFiles() throws Exception {
        Chain chain = ContainerFixtures.rsaChain();
        return Stream
                .of(named("PEM bundle of a chain and an encrypted key",
                        ContainerFixtures
                                .pem(LF, chain.leaf(), chain.intermediate(), chain.root(),
                                        ContainerFixtures.encryptedPrivateKeyBlock(chain.leafKey()))),
                        named("DER PKCS#7", ContainerFixtures.pkcs7(chain.root(), chain.intermediate(), chain.leaf())));
    }
}

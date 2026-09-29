package com.otilm.core.container;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.container.ContainerFixtures.Chain;
import com.otilm.core.util.MutationFuzzing;
import java.util.stream.Stream;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static com.otilm.core.container.ContainerFixtures.PASSPHRASE;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.junit.jupiter.api.Named.named;

class Pkcs12FormatFuzzTest {

    private static final long SEED = 1L;

    private static final int MUTANTS = 500;

    private static ContainerReader reader;

    @BeforeAll
    static void fixtures() {
        ContainerFixtures.registerProviders();
        reader = Pkcs12Fixtures.reader();
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

    /**
     * A file with a MAC, whose mutants the MAC mostly refuses, and the same file without one, whose mutants reach its
     * safes, bags and key.
     */
    static Stream<Named<byte[]>> validFiles() throws Exception {
        Chain chain = ContainerFixtures.rsaChain();
        return Stream
                .of(named("a shrouded key and an encrypted certificate safe under a MAC",
                        file(chain).mac(PASSPHRASE, NISTObjectIdentifiers.id_sha256).build()),
                        named("a shrouded key and an encrypted certificate safe without a MAC", file(chain).build()));
    }

    private static Pkcs12Fixtures.Builder file(Chain chain) throws Exception {
        byte[] localKeyId = {1};
        return Pkcs12Fixtures
                .builder()
                .shroudedKeyBag(chain.leafKey().getPrivate(), PASSPHRASE, "leaf", localKeyId)
                .encryptedSafe(PASSPHRASE, Pkcs12Fixtures.PBES2_AES_256)
                .certBag(chain.leaf(), "leaf", localKeyId)
                .certBag(chain.intermediate(), null, null)
                .certBag(chain.root(), null, null);
    }
}

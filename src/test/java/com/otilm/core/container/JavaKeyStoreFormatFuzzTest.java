package com.otilm.core.container;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.container.ContainerFixtures.Chain;
import com.otilm.core.key.normalization.JavaKeyStoreFixtures;
import com.otilm.core.key.normalization.KeyNormalizer;
import com.otilm.core.util.MutationFuzzing;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import javax.crypto.KeyGenerator;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static com.otilm.core.container.ContainerFixtures.PASSPHRASE;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.junit.jupiter.api.Named.named;

class JavaKeyStoreFormatFuzzTest {

    private static final long SEED = 1L;

    private static final int MUTANTS = 500;

    private static final int DIGEST_LENGTH = 20;

    private static ContainerReader reader;

    @BeforeAll
    static void fixtures() {
        ContainerFixtures.registerProviders();
        reader = new ContainerReader(List.of(new JavaKeyStoreFormat(), new PemFormat(), new DerFormat()),
                new ContainerAssembler(new KeyNormalizer()));
    }

    @ParameterizedTest
    @MethodSource("validStores")
    void read_endsEveryMutantInEntriesOrARefusal(byte[] store) {
        // given
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when, then
        assertThatCode(() -> MutationFuzzing
                .assertOnlyDefinedOutcomes(store, SEED, MUTANTS, mutant -> reader.read(mutant, passphrase),
                        ValidationException.class::isInstance))
                .doesNotThrowAnyException();
    }

    /**
     * Each mutant is digested again under the passphrase before it is read, as the holder of the passphrase could make
     * it, so that it passes the integrity check and reaches the keys and certificates.
     */
    @ParameterizedTest
    @MethodSource("validStores")
    void read_endsEveryMutantThatVerifiesInEntriesOrARefusal(byte[] store) {
        // given
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when, then
        assertThatCode(() -> MutationFuzzing
                .assertOnlyDefinedOutcomes(store, SEED, MUTANTS, mutant -> reader.read(verifying(mutant), passphrase),
                        ValidationException.class::isInstance))
                .doesNotThrowAnyException();
    }

    static Stream<Named<byte[]>> validStores() throws Exception {
        Chain chain = ContainerFixtures.rsaChain();
        KeyStore.PrivateKeyEntry key = new KeyStore.PrivateKeyEntry(chain.leafKey().getPrivate(),
                new X509Certificate[]{jca(chain.leaf()), jca(chain.intermediate()), jca(chain.root())});
        KeyGenerator aes = KeyGenerator.getInstance("AES");
        aes.init(256);
        return Stream
                .of(named("JKS of a key and its chain", JavaKeyStoreFixtures.jks(PASSPHRASE, Map.of("leaf", key))),
                        named("JCEKS of an AES secret key", JavaKeyStoreFixtures
                                .jceks(PASSPHRASE, Map.of("aes", new KeyStore.SecretKeyEntry(aes.generateKey())))));
    }

    private static X509Certificate jca(X509CertificateHolder certificate) throws Exception {
        return new JcaX509CertificateConverter().getCertificate(certificate);
    }

    /** The mutant with its last bytes replaced by the digest of the rest, when it is long enough to hold a digest. */
    private static byte[] verifying(byte[] mutant) throws GeneralSecurityException {
        return mutant.length < DIGEST_LENGTH ? mutant : JavaKeyStoreFixtures.redigested(mutant, PASSPHRASE);
    }
}

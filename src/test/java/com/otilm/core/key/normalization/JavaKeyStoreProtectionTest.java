package com.otilm.core.key.normalization;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.core.secret.Passphrase;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Stream;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.PBEParameter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Named.named;

class JavaKeyStoreProtectionTest {

    private static final KeyNormalizer NORMALIZER = new KeyNormalizer();

    private static KeyPair rsa;

    private static KeyPair ec;

    @BeforeAll
    static void keys() throws GeneralSecurityException {
        KeyFiles.registerProviders();
        rsa = KeyFiles.rsa();
        ec = KeyFiles.ec();
    }

    @ParameterizedTest
    @MethodSource("keyPairs")
    void describe_opensAKeyAJavaKeyStoreProtects(KeyPair keyPair) throws Exception {
        // given
        byte[] protectedKey = JavaKeyStoreFixtures.firstProtectedKey(jks(keyPair));

        // when
        KeyDescription description = NORMALIZER
                .describe(protectedKey, KeyFiles.passphrase(), DerivationBudget.forFile());

        // then
        assertThat(description.supported()).isTrue();
        assertThat(description.type()).isEqualTo(KeyRequestType.KEY_PAIR);
        assertThat(description.subjectPublicKeyInfo()).isEqualTo(keyPair.getPublic().getEncoded());
    }

    @ParameterizedTest
    @MethodSource("keyPairs")
    void describe_opensAKeyAJceKeyStoreProtects(KeyPair keyPair) throws Exception {
        // given
        byte[] protectedKey = JavaKeyStoreFixtures.firstProtectedKey(jceks(keyPair));

        // when
        KeyDescription description = NORMALIZER
                .describe(protectedKey, KeyFiles.passphrase(), DerivationBudget.forFile());

        // then
        assertThat(description.supported()).isTrue();
        assertThat(description.type()).isEqualTo(KeyRequestType.KEY_PAIR);
        assertThat(description.subjectPublicKeyInfo()).isEqualTo(keyPair.getPublic().getEncoded());
    }

    @Test
    void describe_refusesAJavaKeyStoreKeyUnderAnotherPassphrase() throws Exception {
        // given
        byte[] protectedKey = JavaKeyStoreFixtures.firstProtectedKey(jks(rsa));
        Passphrase wrong = new Passphrase("not the passphrase".toCharArray());
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.describe(protectedKey, wrong, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    @Test
    void describe_refusesAJavaKeyStoreKeyWhoseCheckDoesNotMatch() throws Exception {
        // given
        byte[] protectedKey = JavaKeyStoreFixtures.firstProtectedKey(jks(rsa));
        byte[] tampered = flipCheckByte(protectedKey);
        Passphrase passphrase = KeyFiles.passphrase();
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.describe(tampered, passphrase, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    @Test
    void describe_chargesAJceKeyStoreKeysIterations() throws Exception {
        // given
        byte[] protectedKey = JavaKeyStoreFixtures.firstProtectedKey(jceks(rsa));
        byte[] rebuilt = withIterations(protectedKey, 9_000_001);
        Passphrase passphrase = KeyFiles.passphrase();
        DerivationBudget budget = DerivationBudget.forFile();
        budget.charge(BigInteger.valueOf(1_000_000));

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.describe(rebuilt, passphrase, budget));

        // then
        assertThat(refusal.getMessage())
                .isEqualTo(KeyFileRefusal.LIMIT_EXCEEDED.formatted("key derivation iteration", 10_000_000));
    }

    @Test
    void describe_refusesAJceKeyStoreKeyUnderAnotherPassphrase() throws Exception {
        // given
        byte[] protectedKey = JavaKeyStoreFixtures.firstProtectedKey(jceks(rsa));
        Passphrase wrong = new Passphrase("not the passphrase".toCharArray());
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.describe(protectedKey, wrong, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    @Test
    void describe_refusesAJceKeyStoreKeyUnderANonAsciiPassphrase() throws Exception {
        // given
        byte[] protectedKey = JavaKeyStoreFixtures.firstProtectedKey(jceks(rsa));
        Passphrase nonAscii = new Passphrase("pässwörd 漢字".toCharArray());
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.describe(protectedKey, nonAscii, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    @Test
    void describe_refusesAJavaKeyStoreEnvelopeShorterThanItsSaltAndCheck() throws Exception {
        // given
        byte[] tooShort = new EncryptedPrivateKeyInfo(new AlgorithmIdentifier(JavaKeyStoreProtection.JKS), new byte[39])
                .getEncoded();
        Passphrase passphrase = KeyFiles.passphrase();
        DerivationBudget budget = DerivationBudget.forFile();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> NORMALIZER.describe(tooShort, passphrase, budget));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    @Test
    void describe_opensAJavaKeyStoreKeyUnderANonAsciiPassphrase() throws Exception {
        // given
        char[] passphrase = "pässwörd 漢字".toCharArray();
        byte[] protectedKey = JavaKeyStoreFixtures.firstProtectedKey(jks(rsa, passphrase));

        // when
        KeyDescription description = NORMALIZER
                .describe(protectedKey, new Passphrase(passphrase), DerivationBudget.forFile());

        // then
        assertThat(description.subjectPublicKeyInfo()).isEqualTo(rsa.getPublic().getEncoded());
    }

    @Test
    void describe_opensAJavaKeyStoreKeyUnderABudgetAlreadySpent() throws Exception {
        // given
        byte[] protectedKey = JavaKeyStoreFixtures.firstProtectedKey(jks(rsa));
        DerivationBudget budget = DerivationBudget.forFile();
        budget.charge(BigInteger.valueOf(DerivationBudget.FILE_ITERATIONS));

        // when
        KeyDescription description = NORMALIZER.describe(protectedKey, KeyFiles.passphrase(), budget);

        // then
        assertThat(description.subjectPublicKeyInfo()).isEqualTo(rsa.getPublic().getEncoded());
    }

    @Test
    void firstProtectedKey_skipsATrustedCertificateEntryToFindTheKey() throws Exception {
        // given
        Map<String, KeyStore.Entry> entries = new LinkedHashMap<>();
        entries.put("certificate", new KeyStore.TrustedCertificateEntry(selfSigned(ec)));
        entries.put("key", new KeyStore.PrivateKeyEntry(rsa.getPrivate(), new Certificate[]{selfSigned(rsa)}));
        byte[] store = JavaKeyStoreFixtures.jks(KeyFiles.PASSPHRASE, entries);

        // when
        byte[] protectedKey = JavaKeyStoreFixtures.firstProtectedKey(store);

        // then
        KeyDescription description = NORMALIZER
                .describe(protectedKey, KeyFiles.passphrase(), DerivationBudget.forFile());
        assertThat(description.subjectPublicKeyInfo()).isEqualTo(rsa.getPublic().getEncoded());
    }

    @Test
    void normalize_protectsAJavaKeyStoreKeyInThePinnedProfile() throws Exception {
        // given
        byte[] protectedKey = JavaKeyStoreFixtures.firstProtectedKey(jks(ec));

        // when
        NormalizedKey key = NORMALIZER
                .normalize(protectedKey, KeyFiles.passphrase(), KeyRequestType.KEY_PAIR, DerivationBudget.forFile());

        // then
        assertThat(key.subjectPublicKeyInfo()).isEqualTo(ec.getPublic().getEncoded());
        assertThat(KeyFiles.opened(key)).isEqualTo(ec.getPrivate().getEncoded());
    }

    static Stream<Named<KeyPair>> keyPairs() {
        return Stream.of(named("RSA", rsa), named("EC", ec));
    }

    private static byte[] jks(KeyPair keyPair) throws Exception {
        return jks(keyPair, KeyFiles.PASSPHRASE);
    }

    private static byte[] jks(KeyPair keyPair, char[] storePassword) throws Exception {
        return JavaKeyStoreFixtures.jks(storePassword, entries(keyPair));
    }

    private static byte[] jceks(KeyPair keyPair) throws Exception {
        return JavaKeyStoreFixtures.jceks(KeyFiles.PASSPHRASE, entries(keyPair));
    }

    private static Map<String, KeyStore.Entry> entries(KeyPair keyPair) throws Exception {
        Certificate[] chain = {selfSigned(keyPair)};
        return Map.of("alias", new KeyStore.PrivateKeyEntry(keyPair.getPrivate(), chain));
    }

    /** A self-signed certificate for the key pair, only so a {@code PrivateKeyEntry} has the chain it demands. */
    private static X509Certificate selfSigned(KeyPair keyPair) throws Exception {
        X500Name subject = new X500Name("CN=JavaKeyStoreProtectionTest");
        Date start = new Date();
        Date end = new Date(start.getTime() + 365L * 86_400_000);
        String signatureAlgorithm = "EC".equals(keyPair.getPrivate().getAlgorithm())
                ? "SHA256withECDSA"
                : "SHA256withRSA";
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(new JcaX509v3CertificateBuilder(subject, BigInteger.ONE, start, end, subject,
                        keyPair.getPublic()).build(signer));
    }

    /** The same envelope, with the last byte of its trailing check digest flipped, its encrypted key untouched. */
    private static byte[] flipCheckByte(byte[] protectedKey) throws Exception {
        EncryptedPrivateKeyInfo envelope = EncryptedPrivateKeyInfo.getInstance(protectedKey);
        byte[] encryptedData = envelope.getEncryptedData().clone();
        encryptedData[encryptedData.length - 1] ^= 0x01;
        return new EncryptedPrivateKeyInfo(envelope.getEncryptionAlgorithm(), encryptedData).getEncoded();
    }

    /** The same JCEKS envelope, its iteration count replaced, its own protection and salt otherwise unchanged. */
    private static byte[] withIterations(byte[] protectedKey, int iterations) throws Exception {
        EncryptedPrivateKeyInfo envelope = EncryptedPrivateKeyInfo.getInstance(protectedKey);
        PBEParameter original = PBEParameter.getInstance(envelope.getEncryptionAlgorithm().getParameters());
        AlgorithmIdentifier protection = new AlgorithmIdentifier(envelope.getEncryptionAlgorithm().getAlgorithm(),
                new PBEParameter(original.getSalt(), iterations));
        return new EncryptedPrivateKeyInfo(protection, envelope.getEncryptedData()).getEncoded();
    }
}

package com.otilm.core.container;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.client.inspection.InspectedEntryKind;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.container.ContainerFixtures.Chain;
import com.otilm.core.key.normalization.DerivationBudget;
import com.otilm.core.key.normalization.JavaKeyStoreFixtures;
import com.otilm.core.key.normalization.KeyDescription;
import com.otilm.core.key.normalization.KeyFileRefusal;
import com.otilm.core.key.normalization.KeyNormalizer;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.PBEParameter;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;

import static com.otilm.core.container.ContainerFixtures.PASSPHRASE;
import static com.otilm.core.container.ContainerFixtures.sha256;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class JavaKeyStoreFormatTest {

    private static final char[] OTHER_PASSPHRASE = "a passphrase of its own".toCharArray();

    private static final char[] EMPTY_PASSPHRASE = new char[0];

    /** The iterations the JDK derives the protection of a JCEKS key with by default. */
    private static final int JDK_JCEKS_ITERATIONS = 200_000;

    /** As many JCEKS keys as a file's budget derives once, but not twice. */
    private static final int KEYS_OVER_HALF_THE_BUDGET = DerivationBudget.FILE_ITERATIONS / (2 * JDK_JCEKS_ITERATIONS)
            + 1;

    private static final int JKS_MAGIC = 0xFEEDFEED;

    private static final int PRIVATE_KEY_TAG = 1;

    private static final String X509 = "X.509";

    private static final String JCEKS_PROTECTION = "1.3.6.1.4.1.42.2.19.1";

    private static final int DIGEST_LENGTH = 20;

    /** The magic number and version a Java serialization stream, such as a sealed key, starts with. */
    private static final int STREAM_HEADER_LENGTH = 4;

    /** What a serialization stream holds where it holds nothing: never the object a sealed key starts with. */
    private static final int TC_NULL = 0x70;

    /** Where the version stands: after the magic number. */
    private static final int VERSION_AT = Integer.BYTES;

    /** Where the number of entries stands: after the magic number and the version. */
    private static final int COUNT_AT = 2 * Integer.BYTES;

    /** Where a store's first entry starts: after the magic number, the version and the number of entries. */
    private static final int FIRST_ENTRY = 3 * Integer.BYTES;

    /** Where the length of the first entry's alias stands: after the entry's tag. */
    private static final int ALIAS_AT = FIRST_ENTRY + Integer.BYTES;

    private static final String LEAF = "leaf";

    /** Where the length of the first entry's protected key stands, when the entry is a key named {@value #LEAF}. */
    private static final int KEY_LENGTH_AT = ALIAS_AT + Short.BYTES + LEAF.length() + Long.BYTES;

    private static ContainerReader reader;

    private static Chain chain;

    private static KeyStore.PrivateKeyEntry leafEntry;

    private static KeyStore.SecretKeyEntry aesEntry;

    /** A JKS store of the leaf's key and chain. */
    private static byte[] keyStore;

    /** A JKS store of the leaf's key, stored without a chain. */
    private static byte[] chainlessStore;

    /** A JCEKS store of an AES secret key. */
    private static byte[] secretKeyStore;

    private static byte[] emptyStore;

    @BeforeAll
    static void fixtures() throws Exception {
        ContainerFixtures.registerProviders();
        reader = reader(new KeyNormalizer());
        chain = ContainerFixtures.rsaChain();
        leafEntry = new KeyStore.PrivateKeyEntry(chain.leafKey().getPrivate(),
                jca(chain.leaf(), chain.intermediate(), chain.root()));
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        aesEntry = new KeyStore.SecretKeyEntry(generator.generateKey());
        keyStore = JavaKeyStoreFixtures.jks(PASSPHRASE, Map.of(LEAF, leafEntry));
        byte[] protectedKey = JavaKeyStoreFixtures.firstProtectedKey(keyStore);
        chainlessStore = store("JKS", PASSPHRASE, entries -> entries.setKeyEntry(LEAF, protectedKey, null));
        secretKeyStore = JavaKeyStoreFixtures.jceks(PASSPHRASE, Map.of("aes", aesEntry));
        emptyStore = JavaKeyStoreFixtures.jks(PASSPHRASE, Map.of());
    }

    @Test
    void read_readsAJksKeyAndChain() throws Exception {
        // given
        byte[] protectedKey = JavaKeyStoreFixtures.firstProtectedKey(keyStore);

        // when
        Container container = reader.read(keyStore, ContainerFixtures.passphrase());

        // then
        assertThat(container.digest()).isEqualTo(sha256(keyStore));
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.KEY_PAIR_WITH_CHAIN);
            assertThat(entry.alias()).isEqualTo(LEAF);
            assertThat(entry.reference()).isEqualTo(sha256(chain.leafKey().getPublic().getEncoded()));
            assertThat(entry.keyFile()).isEqualTo(protectedKey);
            assertThat(entry.leaf()).isEqualTo(chain.leaf());
            assertThat(entry.issuers()).containsExactly(chain.intermediate(), chain.root());
        });
    }

    @Test
    void read_readsAJksTruststore() throws Exception {
        // given
        byte[] store = JavaKeyStoreFixtures
                .jks(PASSPHRASE,
                        Map
                                .of("root", trusted(chain.root()), "intermediate", trusted(chain.intermediate()), LEAF,
                                        trusted(chain.leaf())));

        // when
        Container container = reader.read(store, ContainerFixtures.passphrase());

        // then
        assertThat(container.entries())
                .allSatisfy(entry -> assertThat(entry).isInstanceOf(CertificateEntry.class))
                .map(entry -> tuple(alias(entry), ((CertificateEntry) entry).certificate()))
                .containsExactlyInAnyOrder(tuple("root", chain.root()), tuple("intermediate", chain.intermediate()),
                        tuple(LEAF, chain.leaf()));
    }

    @Test
    void read_readsAJceksPrivateKey() throws Exception {
        // given
        byte[] store = JavaKeyStoreFixtures.jceks(PASSPHRASE, Map.of(LEAF, leafEntry));

        // when
        Container container = reader.read(store, ContainerFixtures.passphrase());

        // then
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.KEY_PAIR_WITH_CHAIN);
            assertThat(entry.alias()).isEqualTo(LEAF);
            assertThat(EncryptedPrivateKeyInfo.getInstance(entry.keyFile()).getEncryptionAlgorithm().getAlgorithm())
                    .hasToString(JCEKS_PROTECTION);
            assertThat(entry.leaf()).isEqualTo(chain.leaf());
            assertThat(entry.issuers()).containsExactly(chain.intermediate(), chain.root());
        });
    }

    @Test
    void read_readsAJceksAesSecretKey() throws Exception {
        // given
        byte[] sealedKey = onlyEntryContent(secretKeyStore);

        // when
        Container container = reader.read(secretKeyStore, ContainerFixtures.passphrase());

        // then
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.SECRET_KEY);
            assertThat(entry.alias()).isEqualTo("aes");
            assertThat(entry.reference()).isEqualTo(sha256(sealedKey));
            assertThat(entry.keyFile()).isEqualTo(sealedKey);
            assertThat(entry.description().type()).isEqualTo(KeyRequestType.SECRET);
            assertThat(entry.description().algorithm()).isEqualTo(KeyAlgorithm.AES);
            assertThat(entry.description().length()).isEqualTo(256);
            assertThat(entry.leaf()).isNull();
        });
    }

    @Test
    void read_listsAnAesKeyOfAnotherLengthAsAnUnsupportedSecretKey() throws Exception {
        // given
        KeyStore.SecretKeyEntry odd = new KeyStore.SecretKeyEntry(new SecretKeySpec(new byte[5], "AES"));
        byte[] store = JavaKeyStoreFixtures.jceks(PASSPHRASE, Map.of("odd", odd, "aes", aesEntry));

        // when
        Container container = reader.read(store, ContainerFixtures.passphrase());

        // then
        assertThat(container.entries())
                .allSatisfy(entry -> assertThat(entry.kind()).isEqualTo(InspectedEntryKind.SECRET_KEY))
                .map(entry -> {
                    KeyDescription description = ((KeyEntry) entry).description();
                    return tuple(alias(entry), description.algorithm(), description.length(),
                            description.unsupportedAlgorithm());
                })
                .containsExactlyInAnyOrder(tuple("odd", null, 0, NISTObjectIdentifiers.aes.getId()),
                        tuple("aes", KeyAlgorithm.AES, 256, null));
    }

    @Test
    void read_listsASealedAesKeyInAPrivateKeyEntryAsASecretKey() throws Exception {
        // given
        byte[] sealedKey = onlyEntryContent(secretKeyStore);
        // a JCEKS store takes a private key's protected bytes as they are, which a JKS store checks; the two lay out a
        // private-key entry alike
        byte[] jceks = store("JCEKS", PASSPHRASE, entries -> entries.setKeyEntry("aes", sealedKey, null));
        byte[] store = redigested(withInt(jceks, 0, JKS_MAGIC));

        // when
        Container container = reader.read(store, ContainerFixtures.passphrase());

        // then
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.SECRET_KEY);
            assertThat(entry.secret()).isTrue();
            assertThat(entry.description().algorithm()).isEqualTo(KeyAlgorithm.AES);
            assertThat(entry.reference()).isEqualTo(sha256(sealedKey));
        });
    }

    @Test
    void read_readsAVersionOneStore() throws Exception {
        // given
        byte[] store = versionOne(keyStore);

        // when
        Container container = reader.read(store, ContainerFixtures.passphrase());

        // then
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.KEY_PAIR_WITH_CHAIN);
            assertThat(entry.alias()).isEqualTo(LEAF);
            assertThat(entry.issuers()).containsExactly(chain.intermediate(), chain.root());
        });
    }

    @Test
    void read_readsEveryEntryOfAJceksStore() throws Exception {
        // given
        X509CertificateHolder other = ContainerFixtures.selfSigned(ContainerFixtures.ec(), "CN=Other");
        byte[] store = JavaKeyStoreFixtures
                .jceks(PASSPHRASE, Map.of(LEAF, leafEntry, "other", trusted(other), "aes", aesEntry));

        // when
        Container container = reader.read(store, ContainerFixtures.passphrase());

        // then
        assertThat(container.entries())
                .extracting(ContainerEntry::kind, JavaKeyStoreFormatTest::alias)
                .containsExactlyInAnyOrder(tuple(InspectedEntryKind.KEY_PAIR_WITH_CHAIN, LEAF),
                        tuple(InspectedEntryKind.CERTIFICATE, "other"), tuple(InspectedEntryKind.SECRET_KEY, "aes"));
    }

    @Test
    void read_readsAKeyWithoutAChain() {
        // when
        Container container = reader.read(chainlessStore, ContainerFixtures.passphrase());

        // then
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.PRIVATE_KEY);
            assertThat(entry.alias()).isEqualTo(LEAF);
            assertThat(entry.reference()).isEqualTo(sha256(chain.leafKey().getPublic().getEncoded()));
        });
    }

    @Test
    void read_readsAnEmptyStoreAsNoEntries() {
        // when
        Container container = reader.read(emptyStore, ContainerFixtures.passphrase());

        // then
        assertThat(container.entries()).isEmpty();
    }

    @ParameterizedTest
    @MethodSource("storesUnderAnEmptyPassphrase")
    void read_opensTheKeysOfAStoreProtectedWithAnEmptyPassphraseWithoutOne(byte[] store,
            List<InspectedEntryKind> kinds) {
        // when
        Container container = reader.read(store, null);

        // then
        assertThat(container.entries()).extracting(ContainerEntry::kind).containsExactlyInAnyOrderElementsOf(kinds);
    }

    @Test
    void read_asksTheKeystoreFormatBeforeThePemOne() throws Exception {
        // given
        X509CertificateHolder armored = ContainerFixtures
                .selfSigned(ContainerFixtures.ec(), "CN=a\n-----BEGIN CERTIFICATE-----");
        byte[] store = JavaKeyStoreFixtures.jks(PASSPHRASE, Map.of("armored", trusted(armored)));
        Passphrase passphrase = ContainerFixtures.passphrase();

        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(DerFormat.class,
                PemFormat.class, JavaKeyStoreFormat.class, KeyNormalizer.class, ContainerAssembler.class,
                ContainerReader.class)) {
            // when
            Container container = context.getBean(ContainerReader.class).read(store, passphrase);

            // then
            assertThat(new PemFormat().recognizes(store)).isTrue();
            assertThat(container.entries())
                    .singleElement()
                    .isInstanceOfSatisfying(CertificateEntry.class,
                            entry -> assertThat(entry.certificate()).isEqualTo(armored));
        }
    }

    @ParameterizedTest
    @MethodSource("wrongPassphrases")
    void read_refusesAWrongPassphraseAsAnIntegrityFailure(Passphrase passphrase) {
        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(keyStore, passphrase));

        // then
        assertThat(refusal.getMessage()).isEqualTo(ContainerRefusal.INTEGRITY_FAILED);
    }

    @ParameterizedTest
    @MethodSource("keysUnderAPassphraseOfTheirOwn")
    void read_refusesAStoreWhoseKeyHasItsOwnPassword(byte[] store) {
        // given
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(store, passphrase));

        // then
        assertThat(refusal.getMessage()).isEqualTo(ContainerRefusal.TWO_PASSPHRASES);
    }

    @Test
    void read_overwritesTheKeysItCopiedWhenItRefusesTheStore() throws Exception {
        // given
        ContainerFixtures.RecordingNormalizer normalizer = new ContainerFixtures.RecordingNormalizer();
        ContainerReader recording = reader(normalizer);
        byte[] store = store("JKS", PASSPHRASE, entries -> {
            entries.setEntry("first", leafEntry, new KeyStore.PasswordProtection(PASSPHRASE));
            entries.setEntry("second", leafEntry, new KeyStore.PasswordProtection(OTHER_PASSPHRASE));
        });
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> recording.read(store, passphrase));

        // then
        assertThat(refusal.getMessage()).isEqualTo(ContainerRefusal.TWO_PASSPHRASES);
        assertThat(normalizer.described()).isNotEmpty().allSatisfy(keyFile -> assertThat(keyFile).containsOnly(0));
    }

    @ParameterizedTest
    @MethodSource("storesOfTwoKeys")
    void read_describesEachKeyOnce(byte[] store) {
        // given
        ContainerFixtures.RecordingNormalizer normalizer = new ContainerFixtures.RecordingNormalizer();
        ContainerReader recording = reader(normalizer);
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        Container container = recording.read(store, passphrase);

        // then
        assertThat(container.entries()).hasSize(2);
        assertThat(normalizer.described()).hasSize(2);
    }

    @Test
    void read_readsAJceksStoreWhoseKeysTheBudgetDerivesOnceButNotTwice() throws Exception {
        // given
        assertThat(JavaKeyStoreFixtures.sealedKeyIterations(onlyEntryContent(secretKeyStore)))
                .as("the iterations the JDK seals a key with, which the number of keys assumes")
                .isEqualTo(BigInteger.valueOf(JDK_JCEKS_ITERATIONS));
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        Map<String, KeyStore.Entry> keys = new HashMap<>();
        for (int index = 0; index < KEYS_OVER_HALF_THE_BUDGET; index++) {
            keys.put("aes-" + index, new KeyStore.SecretKeyEntry(generator.generateKey()));
        }
        byte[] store = JavaKeyStoreFixtures.jceks(PASSPHRASE, keys);

        // when
        Container container = reader.read(store, ContainerFixtures.passphrase());

        // then
        assertThat(container.entries())
                .hasSize(KEYS_OVER_HALF_THE_BUDGET)
                .allSatisfy(entry -> assertThat(entry.kind()).isEqualTo(InspectedEntryKind.SECRET_KEY));
    }

    @Test
    void read_refusesASecretKeyInAJks() throws Exception {
        // given
        byte[] store = redigested(withInt(secretKeyStore, 0, JKS_MAGIC));
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(store, passphrase));

        // then
        assertThat(refusal.getMessage()).isEqualTo(ContainerRefusal.entryUnsupported("3").getMessage());
    }

    @Test
    void read_refusesAnEntryOfAnUnknownTag() throws Exception {
        // given
        byte[] store = redigested(withInt(keyStore, FIRST_ENTRY, 7));
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(store, passphrase));

        // then
        assertThat(refusal.getMessage()).isEqualTo(ContainerRefusal.entryUnsupported("7").getMessage());
    }

    @Test
    void read_refusesACertificateOfAnotherType() throws Exception {
        // given
        byte[] store = redigested(withByte(keyStore, certificateLengthAt(keyStore) - 1, '0'));
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(store, passphrase));

        // then
        assertThat(refusal.getMessage()).isEqualTo(ContainerRefusal.entryUnsupported("X.500").getMessage());
    }

    @ParameterizedTest
    @MethodSource({"layoutsTheJdkDoesNotWrite", "lengthsPastTheEnd"})
    void read_refusesALayoutTheJdkDoesNotWrite(byte[] store) {
        // given
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(store, passphrase));

        // then
        assertThat(refusal.getMessage()).isEqualTo(ContainerRefusal.NOT_SUPPORTED_FORMAT);
    }

    @Test
    void read_refusesMoreKeysThanTheLimitBeforeOpeningAny() throws Exception {
        // given
        KeyStore.PrivateKeyEntry key = new KeyStore.PrivateKeyEntry(chain.leafKey().getPrivate(), jca(chain.leaf()));
        byte[] store = store("JKS", PASSPHRASE, entries -> {
            for (int index = 0; index <= ContainerLimits.MAXIMUM_OTHER_ENTRIES; index++) {
                entries.setEntry("key-" + index, key, new KeyStore.PasswordProtection(OTHER_PASSPHRASE));
            }
        });
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(store, passphrase));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.limitExceeded("entry count", 100).getMessage());
    }

    @ParameterizedTest
    @MethodSource("moreCertificatesThanTheLimit")
    void read_refusesMoreCertificatesThanTheLimitBeforeOpeningAKey(byte[] store) {
        // given
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(store, passphrase));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.limitExceeded("certificate count", 200).getMessage());
    }

    @Test
    void read_refusesAKeyDemandingMoreDerivationThanTheFileMayTake() throws Exception {
        // given
        AlgorithmIdentifier protection = new AlgorithmIdentifier(new ASN1ObjectIdentifier(JCEKS_PROTECTION),
                new PBEParameter(new byte[8], DerivationBudget.FILE_ITERATIONS + 1));
        byte[] protectedKey = new EncryptedPrivateKeyInfo(protection, new byte[16]).getEncoded();
        byte[] store = store("JCEKS", PASSPHRASE, entries -> entries.setKeyEntry("key", protectedKey, null));
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(store, passphrase));

        // then
        assertThat(refusal.getMessage())
                .isEqualTo(KeyFileRefusal
                        .limitExceeded("key derivation iteration", DerivationBudget.FILE_ITERATIONS)
                        .getMessage());
    }

    static Stream<Arguments> storesUnderAnEmptyPassphrase() throws Exception {
        byte[] jks = JavaKeyStoreFixtures.jks(EMPTY_PASSPHRASE, Map.of(LEAF, leafEntry));
        byte[] jceks = JavaKeyStoreFixtures.jceks(EMPTY_PASSPHRASE, Map.of(LEAF, leafEntry, "aes", aesEntry));
        return Stream
                .of(arguments(named("JKS", jks), List.of(InspectedEntryKind.KEY_PAIR_WITH_CHAIN)),
                        arguments(named("JCEKS", jceks),
                                List.of(InspectedEntryKind.KEY_PAIR_WITH_CHAIN, InspectedEntryKind.SECRET_KEY)));
    }

    static Stream<Named<Passphrase>> wrongPassphrases() {
        return Stream.of(named("another passphrase", new Passphrase(OTHER_PASSPHRASE)), named("no passphrase", null));
    }

    static Stream<Named<byte[]>> storesOfTwoKeys() throws Exception {
        KeyPair ec = ContainerFixtures.ec();
        KeyStore.PrivateKeyEntry ecEntry = new KeyStore.PrivateKeyEntry(ec.getPrivate(),
                jca(ContainerFixtures.selfSigned(ec, "CN=EC")));
        return Stream
                .of(named("JKS of two private keys",
                        JavaKeyStoreFixtures.jks(PASSPHRASE, Map.of(LEAF, leafEntry, "ec", ecEntry))),
                        named("JCEKS of a private key and a secret key",
                                JavaKeyStoreFixtures.jceks(PASSPHRASE, Map.of(LEAF, leafEntry, "aes", aesEntry))));
    }

    static Stream<Named<byte[]>> keysUnderAPassphraseOfTheirOwn() throws Exception {
        KeyStore.PasswordProtection own = new KeyStore.PasswordProtection(OTHER_PASSPHRASE);
        return Stream
                .of(named("a JKS private key",
                        store("JKS", PASSPHRASE, entries -> entries.setEntry(LEAF, leafEntry, own))),
                        named("a JCEKS private key",
                                store("JCEKS", PASSPHRASE, entries -> entries.setEntry(LEAF, leafEntry, own))),
                        named("a JCEKS secret key",
                                store("JCEKS", PASSPHRASE, entries -> entries.setEntry("aes", aesEntry, own))));
    }

    static Stream<Named<byte[]>> lengthsPastTheEnd() throws Exception {
        int keyBytesLeft = keyStore.length - KEY_LENGTH_AT - Integer.BYTES;
        return Stream
                .of(named("a protected key one byte longer than what is left",
                        redigested(withInt(keyStore, KEY_LENGTH_AT, keyBytesLeft + 1))),
                        named("a certificate as long as a length can state",
                                redigested(withInt(keyStore, certificateLengthAt(keyStore), Integer.MAX_VALUE))),
                        named("an alias longer than what is left", redigested(withShort(keyStore, ALIAS_AT, 0xFFFF))));
    }

    static Stream<Named<byte[]>> layoutsTheJdkDoesNotWrite() throws Exception {
        return Stream
                .of(named("a version other than 1 and 2", redigested(withInt(emptyStore, VERSION_AT, 3))),
                        named("a negative entry count", redigested(withInt(emptyStore, COUNT_AT, -1))),
                        named("fewer entries than it holds", redigested(withInt(keyStore, COUNT_AT, 0))),
                        named("more entries than it holds", redigested(withInt(emptyStore, COUNT_AT, 301))),
                        named("a negative length", redigested(withInt(keyStore, KEY_LENGTH_AT, -1))),
                        named("a negative chain length",
                                redigested(withInt(chainlessStore, chainLengthAt(chainlessStore), -1))),
                        named("an alias that is not modified UTF-8",
                                redigested(withByte(keyStore, ALIAS_AT + Short.BYTES, 0xFF))),
                        named("bytes after the digest", Arrays.copyOf(keyStore, keyStore.length + 1)),
                        named("a digest cut short", Arrays.copyOf(keyStore, keyStore.length - 1)),
                        named("a sealed key the JDK does not write",
                                redigested(withByte(secretKeyStore,
                                        onlyEntryContentAt(secretKeyStore) + STREAM_HEADER_LENGTH, TC_NULL))),
                        named("a sealed key cut short",
                                digested(Arrays.copyOf(secretKeyStore, onlyEntryContentAt(secretKeyStore) + 16))));
    }

    /**
     * Stores of more certificates than a file may hold, beside a key under a passphrase of its own, which would refuse
     * the store as protected with two passphrases were it opened first.
     */
    static Stream<Named<byte[]>> moreCertificatesThanTheLimit() throws Exception {
        KeyStore.PasswordProtection own = new KeyStore.PasswordProtection(OTHER_PASSPHRASE);
        X509Certificate root = jca(chain.root())[0];
        X509Certificate[] longChain = new X509Certificate[ContainerLimits.MAXIMUM_CERTIFICATES + 1];
        Arrays.fill(longChain, root);
        longChain[0] = jca(chain.leaf())[0];
        return Stream.of(named("trusted certificates", store("JKS", PASSPHRASE, entries -> {
            entries.setEntry(LEAF, leafEntry, own);
            for (int index = 0; index <= ContainerLimits.MAXIMUM_CERTIFICATES; index++) {
                entries.setCertificateEntry("certificate-" + index, root);
            }
        })), named("a key's chain", store("JKS", PASSPHRASE,
                entries -> entries.setKeyEntry(LEAF, chain.leafKey().getPrivate(), OTHER_PASSPHRASE, longChain))));
    }

    /** A reader of the keystore formats and the others, whose keys the normalizer given describes. */
    private static ContainerReader reader(KeyNormalizer normalizer) {
        return new ContainerReader(List.of(new JavaKeyStoreFormat(), new PemFormat(), new DerFormat()),
                new ContainerAssembler(normalizer));
    }

    /** The alias of a key or certificate entry. */
    private static String alias(ContainerEntry entry) {
        return entry instanceof KeyEntry key ? key.alias() : ((CertificateEntry) entry).alias();
    }

    /** The certificates as the JDK's key stores take them. */
    private static X509Certificate[] jca(X509CertificateHolder... certificates) throws CertificateException {
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        X509Certificate[] converted = new X509Certificate[certificates.length];
        for (int index = 0; index < certificates.length; index++) {
            converted[index] = converter.getCertificate(certificates[index]);
        }
        return converted;
    }

    private static KeyStore.TrustedCertificateEntry trusted(X509CertificateHolder certificate)
            throws CertificateException {
        return new KeyStore.TrustedCertificateEntry(jca(certificate)[0]);
    }

    /** A store of the type as the JDK writes it under the store password, holding the entries the setter sets. */
    private static byte[] store(String type, char[] storePassword, Entries setter)
            throws GeneralSecurityException, IOException {
        KeyStore store = KeyStore.getInstance(type);
        store.load(null, null);
        setter.set(store);
        ByteArrayOutputStream file = new ByteArrayOutputStream();
        store.store(file, storePassword);
        return file.toByteArray();
    }

    /** Sets the entries of a store. */
    @FunctionalInterface
    private interface Entries {

        void set(KeyStore store) throws GeneralSecurityException;
    }

    /** The content of a store's only entry after its tag, alias and date, up to the digest that ends the store. */
    private static byte[] onlyEntryContent(byte[] store) throws IOException {
        return Arrays.copyOfRange(store, onlyEntryContentAt(store), store.length - DIGEST_LENGTH);
    }

    /** Where the content of a store's only entry starts: after its tag, alias and date. */
    private static int onlyEntryContentAt(byte[] store) throws IOException {
        DataInputStream entry = new DataInputStream(new ByteArrayInputStream(store));
        entry.skipNBytes(ALIAS_AT);
        entry.readUTF();
        entry.readLong();
        return store.length - entry.available();
    }

    /** Where the length of the chain of the store's first entry, a key named {@value #LEAF}, stands. */
    private static int chainLengthAt(byte[] store) {
        return KEY_LENGTH_AT + Integer.BYTES + ByteBuffer.wrap(store).getInt(KEY_LENGTH_AT);
    }

    /** Where the length of the first certificate of that chain stands: after the chain's length and the type. */
    private static int certificateLengthAt(byte[] store) {
        return chainLengthAt(store) + Integer.BYTES + Short.BYTES + X509.length();
    }

    /**
     * The store as a version 1 store holds it: its private-key and trusted-certificate entries without the type of each
     * certificate, digested again.
     */
    private static byte[] versionOne(byte[] store) throws IOException, GeneralSecurityException {
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(store, 0, store.length - DIGEST_LENGTH));
        ByteArrayOutputStream content = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(content);
        out.writeInt(in.readInt());
        in.readInt();
        out.writeInt(1);
        int count = in.readInt();
        out.writeInt(count);
        for (int entry = 0; entry < count; entry++) {
            int tag = in.readInt();
            out.writeInt(tag);
            out.writeUTF(in.readUTF());
            out.writeLong(in.readLong());
            int certificates = 1;
            if (tag == PRIVATE_KEY_TAG) {
                copyLengthAndBytes(in, out);
                certificates = in.readInt();
                out.writeInt(certificates);
            }
            for (int certificate = 0; certificate < certificates; certificate++) {
                in.readUTF();
                copyLengthAndBytes(in, out);
            }
        }
        return digested(content.toByteArray());
    }

    private static void copyLengthAndBytes(DataInputStream in, DataOutputStream out) throws IOException {
        byte[] bytes = new byte[in.readInt()];
        in.readFully(bytes);
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    /** The store's content without the digest that ends it, digested again under the test passphrase. */
    private static byte[] redigested(byte[] store) throws GeneralSecurityException {
        return JavaKeyStoreFixtures.redigested(store, PASSPHRASE);
    }

    /** The content followed by the digest a JDK store ends with under the test passphrase. */
    private static byte[] digested(byte[] content) throws GeneralSecurityException {
        return JavaKeyStoreFixtures.digested(content, PASSPHRASE);
    }

    private static byte[] withInt(byte[] store, int position, int value) {
        byte[] changed = store.clone();
        ByteBuffer.wrap(changed).putInt(position, value);
        return changed;
    }

    private static byte[] withShort(byte[] store, int position, int value) {
        byte[] changed = store.clone();
        ByteBuffer.wrap(changed).putShort(position, (short) value);
        return changed;
    }

    private static byte[] withByte(byte[] store, int position, int value) {
        byte[] changed = store.clone();
        changed[position] = (byte) value;
        return changed;
    }
}

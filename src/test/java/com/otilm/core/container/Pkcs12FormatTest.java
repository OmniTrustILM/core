package com.otilm.core.container;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.client.inspection.InspectedEntryKind;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.container.ContainerFixtures.Chain;
import com.otilm.core.key.normalization.DerivationBudget;
import com.otilm.core.key.normalization.KeyFileRefusal;
import com.otilm.core.key.normalization.KeyNormalizer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertBag;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.EncryptedData;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.PBMAC1Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.SafeBag;
import org.bouncycastle.asn1.pkcs.SecretBag;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.PKCS12SecretBag;
import org.bouncycastle.pkcs.PKCS12SecretBagBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;

import static com.otilm.core.container.ContainerFixtures.PASSPHRASE;
import static com.otilm.core.container.ContainerFixtures.sha256;
import static com.otilm.core.container.Pkcs12Fixtures.OPENSSL_ALIAS;
import static com.otilm.core.container.Pkcs12Fixtures.PBES2_AES_256;
import static com.otilm.core.container.Pkcs12Fixtures.builder;
import static com.otilm.core.container.Pkcs12Fixtures.openSsl;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class Pkcs12FormatTest {

    private static final char[] OTHER_PASSPHRASE = "another passphrase".toCharArray();

    private static final char[] EMPTY_PASSWORD = new char[0];

    private static final ASN1ObjectIdentifier SHA256 = NISTObjectIdentifiers.id_sha256;

    private static final byte[] LEAF_ID = {1};

    private static final byte[] OTHER_ID = {2};

    private static final ASN1ObjectIdentifier JKS = new ASN1ObjectIdentifier("1.3.6.1.4.1.42.2.17.1.1");

    private static final ASN1ObjectIdentifier JCEKS = new ASN1ObjectIdentifier("1.3.6.1.4.1.42.2.19.1");

    private static ContainerReader reader;

    private static Chain chain;

    private static KeyPair ec;

    private static SecretKey aes;

    @BeforeAll
    static void fixtures() throws Exception {
        ContainerFixtures.registerProviders();
        reader = Pkcs12Fixtures.reader();
        chain = ContainerFixtures.rsaChain();
        ec = ContainerFixtures.ec();
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        aes = generator.generateKey();
    }

    @Test
    void read_readsAKeyWithItsChain() throws Exception {
        // given
        byte[] file = jdkStore(store -> store
                .setKeyEntry("leaf", chain.leafKey().getPrivate(), PASSPHRASE,
                        new Certificate[]{jca(chain.leaf()), jca(chain.intermediate()), jca(chain.root())}));
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        Container container = reader.read(file, passphrase);

        // then
        assertThat(container.digest()).isEqualTo(sha256(file));
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.KEY_PAIR_WITH_CHAIN);
            assertThat(entry.alias()).isEqualTo("leaf");
            assertThat(entry.reference()).isEqualTo(sha256(chain.leafKey().getPublic().getEncoded()));
            assertThat(entry.leaf()).isEqualTo(chain.leaf());
            assertThat(entry.issuers()).containsExactly(chain.intermediate(), chain.root());
        });
    }

    @Test
    void read_readsATruststore() throws Exception {
        // given
        List<X509CertificateHolder> certificates = new ArrayList<>();
        for (int index = 0; index < 150; index++) {
            certificates.add(ContainerFixtures.selfSigned(ec, "CN=Trusted " + index));
        }
        byte[] file = jdkStore(store -> {
            for (int index = 0; index < certificates.size(); index++) {
                store.setCertificateEntry("trusted " + index, jca(certificates.get(index)));
            }
        });
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        Container container = reader.read(file, passphrase);

        // then
        assertThat(container.entries()).hasSize(150).allSatisfy(entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.CERTIFICATE);
            assertThat(((CertificateEntry) entry).alias()).startsWith("trusted ");
        });
        assertThat(container.entries())
                .map(entry -> ((CertificateEntry) entry).certificate())
                .containsExactlyInAnyOrderElementsOf(certificates);
    }

    @Test
    void read_readsAKeyOnlyFile() throws Exception {
        // given
        byte[] file = builder()
                .shroudedKeyBag(chain.leafKey().getPrivate(), PASSPHRASE, "only", LEAF_ID)
                .mac(PASSPHRASE, SHA256)
                .build();
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        Container container = reader.read(file, passphrase);

        // then
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.PRIVATE_KEY);
            assertThat(entry.alias()).isEqualTo("only");
            assertThat(entry.reference()).isEqualTo(sha256(chain.leafKey().getPublic().getEncoded()));
            assertThat(entry.description().algorithm()).isEqualTo(KeyAlgorithm.RSA);
            assertThat(entry.leaf()).isNull();
        });
    }

    @Test
    void read_readsSeveralKeysAsSeparateEntries() throws Exception {
        // given
        X509CertificateHolder second = ContainerFixtures.selfSigned(ec, "CN=Second");
        byte[] file = builder()
                .shroudedKeyBag(chain.leafKey().getPrivate(), PASSPHRASE, "first", LEAF_ID)
                .shroudedKeyBag(ec.getPrivate(), PASSPHRASE, "second", OTHER_ID)
                .encryptedSafe(PASSPHRASE, PBES2_AES_256)
                .certBag(chain.leaf(), "first", LEAF_ID)
                .certBag(second, "second", OTHER_ID)
                .mac(PASSPHRASE, SHA256)
                .build();
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        Container container = reader.read(file, passphrase);

        // then
        assertThat(container.entries())
                .extracting(ContainerEntry::kind)
                .containsExactly(InspectedEntryKind.KEY_PAIR_WITH_CHAIN, InspectedEntryKind.KEY_PAIR_WITH_CHAIN);
        assertThat(container.entries())
                .map(KeyEntry.class::cast)
                .extracting(KeyEntry::alias, KeyEntry::leaf)
                .containsExactly(tuple("first", chain.leaf()), tuple("second", second));
    }

    @Test
    void read_describesEachKeyOnce() throws Exception {
        // given
        ContainerFixtures.RecordingNormalizer normalizer = new ContainerFixtures.RecordingNormalizer();
        ContainerReader recording = Pkcs12Fixtures.reader(normalizer);
        byte[] file = builder()
                .shroudedKeyBag(chain.leafKey().getPrivate(), PASSPHRASE, "first", LEAF_ID)
                .shroudedKeyBag(ec.getPrivate(), PASSPHRASE, "second", OTHER_ID)
                .mac(PASSPHRASE, SHA256)
                .build();
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        Container container = recording.read(file, passphrase);

        // then
        assertThat(container.entries()).hasSize(2);
        assertThat(normalizer.described()).hasSize(2);
    }

    @Test
    void read_listsAPrivateKeyInASecretBagAsAPrivateKey() throws Exception {
        // given
        byte[] file = builder().bag(leafKeyInASecretBag()).mac(PASSPHRASE, SHA256).build();
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        Container container = reader.read(file, passphrase);

        // then
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.PRIVATE_KEY);
            assertThat(entry.secret()).isFalse();
            assertThat(entry.description().type()).isEqualTo(KeyRequestType.KEY_PAIR);
            assertThat(entry.reference()).isEqualTo(sha256(chain.leafKey().getPublic().getEncoded()));
        });
    }

    @Test
    void read_bindsAPrivateKeyInASecretBagToItsCertificate() throws Exception {
        // given
        byte[] file = builder()
                .bag(leafKeyInASecretBag())
                .certBag(chain.leaf(), null, null)
                .mac(PASSPHRASE, SHA256)
                .build();
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        Container container = reader.read(file, passphrase);

        // then
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.KEY_PAIR_WITH_CHAIN);
            assertThat(entry.leaf()).isEqualTo(chain.leaf());
        });
    }

    @Test
    void read_readsAnAesSecretKey() throws Exception {
        // given
        byte[] file = jdkStore(store -> store
                .setEntry("secret", new KeyStore.SecretKeyEntry(aes), new KeyStore.PasswordProtection(PASSPHRASE)));
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        Container container = reader.read(file, passphrase);

        // then
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.SECRET_KEY);
            assertThat(entry.alias()).isEqualTo("secret");
            assertThat(entry.description().type()).isEqualTo(KeyRequestType.SECRET);
            assertThat(entry.description().algorithm()).isEqualTo(KeyAlgorithm.AES);
            assertThat(entry.description().length()).isEqualTo(256);
            assertThat(entry.reference()).isEqualTo(sha256(entry.keyFile()));
        });
    }

    @ParameterizedTest
    @MethodSource("pbmac1Files")
    void read_verifiesAPbmac1Integrity(byte[] file, char[] password) {
        // given
        Passphrase passphrase = new Passphrase(password);

        // when
        Container container = reader.read(file, passphrase);

        // then
        assertThat(container.entries())
                .extracting(ContainerEntry::kind)
                .containsExactly(InspectedEntryKind.KEY_PAIR_WITH_CHAIN);
    }

    @Test
    void read_readsOpenSslLegacyFiles() throws Exception {
        // given
        byte[] file = openSsl(Pkcs12Fixtures.OPENSSL_LEGACY);
        Passphrase passphrase = new Passphrase(Pkcs12Fixtures.openSslPassphrase());

        // when
        Container container = reader.read(file, passphrase);

        // then
        assertOpenSslKeyPair(container);
    }

    @ParameterizedTest
    @MethodSource("absentPassphrases")
    void read_opensAFileOpenSslProtectedWithAnEmptyPassword(Passphrase passphrase) throws Exception {
        // given
        byte[] file = openSsl(Pkcs12Fixtures.OPENSSL_EMPTY_PASSWORD);

        // when
        Container container = reader.read(file, passphrase);

        // then
        assertOpenSslKeyPair(container);
    }

    @Test
    void read_opensALegacyFileOpenSslProtectedWithAnEmptyPassword() throws Exception {
        // given
        byte[] file = openSsl(Pkcs12Fixtures.OPENSSL_LEGACY_EMPTY_PASSWORD);

        // when
        Container container = reader.read(file, null);

        // then
        assertOpenSslKeyPair(container);
    }

    @Test
    void read_opensAJdkStoreProtectedWithAnEmptyPassword() throws Exception {
        // given
        byte[] file = jdkStore(EMPTY_PASSWORD,
                store -> store
                        .setEntry("leaf",
                                new KeyStore.PrivateKeyEntry(chain.leafKey().getPrivate(),
                                        new Certificate[]{jca(chain.leaf())}),
                                new KeyStore.PasswordProtection(EMPTY_PASSWORD, "PBEWithSHA1AndDESede", null)));

        // when
        Container container = reader.read(file, null);

        // then
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.KEY_PAIR_WITH_CHAIN);
            assertThat(entry.alias()).isEqualTo("leaf");
            assertThat(entry.leaf()).isEqualTo(chain.leaf());
        });
    }

    @Test
    void read_opensAFileBouncyCastleProtectedWithAnEmptyPassword() throws Exception {
        // given
        byte[] file = builder()
                .keyBag(chain.leafKey().getPrivate(), "leaf", LEAF_ID)
                .encryptedSafe(EMPTY_PASSWORD, PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC)
                .certBag(chain.leaf(), "leaf", LEAF_ID)
                .mac(EMPTY_PASSWORD, SHA256)
                .build();

        // when
        Container container = reader.read(file, null);

        // then
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.KEY_PAIR_WITH_CHAIN);
            assertThat(entry.leaf()).isEqualTo(chain.leaf());
        });
    }

    @ParameterizedTest
    @MethodSource("wronglyOpenedFiles")
    void read_refusesAWrongPassphraseAsAnIntegrityFailure(byte[] file, Passphrase passphrase) {
        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, passphrase));

        // then
        assertThat(refusal.getMessage()).isEqualTo(ContainerRefusal.INTEGRITY_FAILED);
    }

    @ParameterizedTest
    @MethodSource("classicMacDigests")
    void read_verifiesAClassicMacOverSha1OrSha2(ASN1ObjectIdentifier digest) throws Exception {
        // given
        byte[] file = builder().keyBag(ec.getPrivate(), "key", null).mac(PASSPHRASE, digest).build();
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        Container container = reader.read(file, passphrase);

        // then
        assertThat(container.entries())
                .extracting(ContainerEntry::kind)
                .containsExactly(InspectedEntryKind.PRIVATE_KEY);
    }

    @Test
    void read_refusesAnUnsupportedMacNamingIt() throws Exception {
        // given
        byte[] file = builder().keyBag(ec.getPrivate(), "key", null).mac(PASSPHRASE, PKCSObjectIdentifiers.md5).build();
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, passphrase));

        // then
        assertThat(refusal.getMessage())
                .isEqualTo(ContainerRefusal.integrityUnsupported(PKCSObjectIdentifiers.md5.getId()).getMessage());
    }

    @ParameterizedTest
    @MethodSource("unsupportedPbmac1Parts")
    void read_refusesAPbmac1OfAnUnsupportedPartNamingIt(AlgorithmIdentifier mac, ASN1ObjectIdentifier part)
            throws Exception {
        // given
        byte[] file = Pkcs12Fixtures
                .withMacAlgorithm(builder().keyBag(ec.getPrivate(), "key", null).pbmac1(PASSPHRASE).build(), mac);
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, passphrase));

        // then
        assertThat(refusal.getMessage()).isEqualTo(ContainerRefusal.integrityUnsupported(part.getId()).getMessage());
    }

    @ParameterizedTest
    @MethodSource("damagedPbmac1Parameters")
    @Timeout(5)
    void read_refusesDamagedPbmac1ParametersAsAnIntegrityFailure(AlgorithmIdentifier mac) throws Exception {
        // given
        byte[] file = Pkcs12Fixtures
                .withMacAlgorithm(builder().keyBag(ec.getPrivate(), "key", null).pbmac1(PASSPHRASE).build(), mac);
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, passphrase));

        // then
        assertThat(refusal.getMessage()).isEqualTo(ContainerRefusal.INTEGRITY_FAILED);
    }

    @ParameterizedTest
    @MethodSource("filesUnderTwoPassphrases")
    void read_refusesKeysUnderAnotherPassphrase(byte[] file) {
        // given
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, passphrase));

        // then
        assertThat(refusal.getMessage()).isEqualTo(ContainerRefusal.TWO_PASSPHRASES);
    }

    @ParameterizedTest
    @MethodSource("filesUnderAnotherPassphraseWithoutAMac")
    void read_refusesWhatThePassphraseDoesNotOpenWithoutAMacAsUnreadable(byte[] file) {
        // given
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, passphrase));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    @ParameterizedTest
    @MethodSource("pbes1Schemes")
    void read_opensASafeUnderPbes1(ASN1ObjectIdentifier scheme) throws Exception {
        // given
        byte[] file = builder()
                .keyBag(chain.leafKey().getPrivate(), "leaf", LEAF_ID)
                .encryptedSafe(PASSPHRASE, scheme)
                .certBag(chain.leaf(), "leaf", LEAF_ID)
                .mac(PASSPHRASE, SHA256)
                .build();
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        Container container = reader.read(file, passphrase);

        // then
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.KEY_PAIR_WITH_CHAIN);
            assertThat(entry.leaf()).isEqualTo(chain.leaf());
        });
    }

    @Test
    void read_readsAFileOfIndefiniteLengthsAsNssEncodesIt() throws Exception {
        // given
        byte[] file = Pkcs12Fixtures
                .withIndefiniteLengths(builder()
                        .shroudedKeyBag(chain.leafKey().getPrivate(), PASSPHRASE, "leaf", LEAF_ID)
                        .encryptedSafe(PASSPHRASE, PBES2_AES_256)
                        .certBag(chain.leaf(), "leaf", LEAF_ID)
                        .mac(PASSPHRASE, SHA256)
                        .build());
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        Container container = reader.read(file, passphrase);

        // then
        assertThat(file[1]).as("the PFX's length octet").isEqualTo((byte) 0x80);
        assertThat(container.digest()).isEqualTo(sha256(file));
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.KEY_PAIR_WITH_CHAIN);
            assertThat(entry.alias()).isEqualTo("leaf");
            assertThat(entry.leaf()).isEqualTo(chain.leaf());
        });
    }

    @Test
    void read_readsAFileWithoutAMac() throws Exception {
        // given
        byte[] file = builder()
                .shroudedKeyBag(chain.leafKey().getPrivate(), PASSPHRASE, "leaf", LEAF_ID)
                .encryptedSafe(PASSPHRASE, PBES2_AES_256)
                .certBag(chain.leaf(), "leaf", LEAF_ID)
                .build();
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        Container container = reader.read(file, passphrase);

        // then
        assertThat(container.entries())
                .extracting(ContainerEntry::kind)
                .containsExactly(InspectedEntryKind.KEY_PAIR_WITH_CHAIN);
    }

    @Test
    void read_readsAKeyWithoutProtection() throws Exception {
        // given
        byte[] file = builder()
                .keyBag(chain.leafKey().getPrivate(), "leaf", LEAF_ID)
                .certBag(chain.leaf(), "leaf", LEAF_ID)
                .mac(PASSPHRASE, SHA256)
                .build();
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        Container container = reader.read(file, passphrase);

        // then
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.KEY_PAIR_WITH_CHAIN);
            assertThat(entry.keyFile()).isEqualTo(chain.leafKey().getPrivate().getEncoded());
        });
    }

    @Test
    void read_readsTheBagsOfNestedSafeContents() throws Exception {
        // given
        SafeBag key = new PKCS12SafeBagBuilder(PrivateKeyInfo.getInstance(chain.leafKey().getPrivate().getEncoded()))
                .build()
                .toASN1Structure();
        SafeBag certificate = new PKCS12SafeBagBuilder(chain.leaf()).build().toASN1Structure();
        SafeBag inner = new SafeBag(PKCSObjectIdentifiers.safeContentsBag, new DERSequence(certificate));
        SafeBag outer = new SafeBag(PKCSObjectIdentifiers.safeContentsBag,
                new DERSequence(new ASN1Encodable[]{key, inner}));
        byte[] file = builder().bag(new PKCS12SafeBag(outer)).mac(PASSPHRASE, SHA256).build();
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        Container container = reader.read(file, passphrase);

        // then
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.KEY_PAIR_WITH_CHAIN);
            assertThat(entry.leaf()).isEqualTo(chain.leaf());
        });
    }

    @ParameterizedTest
    @MethodSource("friendlyNamesOfNoText")
    void read_takesNoAliasFromAFriendlyNameThatIsNoText(ASN1Set values) throws Exception {
        // given
        SafeBag certificate = new SafeBag(PKCSObjectIdentifiers.certBag,
                new CertBag(PKCSObjectIdentifiers.x509Certificate, new DEROctetString(chain.root().getEncoded())),
                new DERSet(new ASN1Encodable[]{
                        new Attribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, values),
                        new Attribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, new DERSet(new ASN1Integer(8)))}));
        byte[] file = builder().bag(new PKCS12SafeBag(certificate)).mac(PASSPHRASE, SHA256).build();
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        Container container = reader.read(file, passphrase);

        // then
        assertThat(container.entries())
                .singleElement()
                .isInstanceOfSatisfying(CertificateEntry.class, entry -> assertThat(entry.alias()).isNull());
    }

    @ParameterizedTest
    @MethodSource("filesMissingAStructure")
    void read_refusesAFileMissingAStructureAsNotSupported(byte[] file) {
        // given
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, passphrase));

        // then
        assertThat(refusal.getMessage()).isEqualTo(ContainerRefusal.NOT_SUPPORTED_FORMAT);
    }

    @Test
    void read_refusesRecipientProtectedContent() throws Exception {
        // given
        byte[] file = Pkcs12Fixtures
                .withSafes(builder().certBag(chain.root(), null, null).build(),
                        new ContentInfo(PKCSObjectIdentifiers.envelopedData, new DERSequence()));
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, passphrase));

        // then
        assertThat(refusal.getMessage()).isEqualTo(ContainerRefusal.RECIPIENT_PROTECTED);
    }

    @Test
    void read_refusesAnUnprotectedSecretKey() throws Exception {
        // given
        byte[] file = builder().secretBag(aes, null, "secret").mac(PASSPHRASE, SHA256).build();
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, passphrase));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNPROTECTED_SECRET);
    }

    @Test
    void read_refusesACrlBagNamingItsType() throws Exception {
        // given
        PKCS12SafeBag crl = new PKCS12SafeBagBuilder(new X509v2CRLBuilder(new X500Name("CN=Issuer"), new Date())
                .build(new JcaContentSignerBuilder("SHA256withECDSA")
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(ec.getPrivate())))
                .build();
        byte[] file = builder().bag(crl).mac(PASSPHRASE, SHA256).build();
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, passphrase));

        // then
        assertThat(refusal.getMessage())
                .isEqualTo(ContainerRefusal.entryUnsupported(PKCSObjectIdentifiers.crlBag.getId()).getMessage());
    }

    @Test
    void read_refusesACertificateOfAnotherTypeNamingIt() throws Exception {
        // given
        PKCS12SafeBag certificate = new PKCS12SafeBag(new SafeBag(PKCSObjectIdentifiers.certBag,
                new CertBag(PKCSObjectIdentifiers.sdsiCertificate, new DERIA5String("sdsi"))));
        byte[] file = builder().bag(certificate).mac(PASSPHRASE, SHA256).build();
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, passphrase));

        // then
        assertThat(refusal.getMessage())
                .isEqualTo(
                        ContainerRefusal.entryUnsupported(PKCSObjectIdentifiers.sdsiCertificate.getId()).getMessage());
    }

    @ParameterizedTest
    @MethodSource("secretsOfAnotherShape")
    void read_refusesASecretOfAnotherShapeNamingItsType(ASN1Encodable value) throws Exception {
        // given
        ASN1ObjectIdentifier type = new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.1");
        PKCS12SafeBag secret = new PKCS12SafeBagBuilder(new PKCS12SecretBag(new SecretBag(type, value))).build();
        byte[] file = builder().bag(secret).mac(PASSPHRASE, SHA256).build();
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, passphrase));

        // then
        assertThat(refusal.getMessage()).isEqualTo(ContainerRefusal.entryUnsupported(type.getId()).getMessage());
    }

    @Test
    void read_refusesASafeOfAnotherTypeNamingIt() throws Exception {
        // given
        byte[] file = Pkcs12Fixtures
                .withSafes(builder().certBag(chain.root(), null, null).build(),
                        new ContentInfo(PKCSObjectIdentifiers.signedData, new DERSequence()));
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, passphrase));

        // then
        assertThat(refusal.getMessage())
                .isEqualTo(ContainerRefusal.entryUnsupported(PKCSObjectIdentifiers.signedData.getId()).getMessage());
    }

    @Test
    void read_refusesPublicKeyIntegrityNamingIt() throws Exception {
        // given
        byte[] file = new Pfx(new ContentInfo(PKCSObjectIdentifiers.signedData, new DERSequence()), null).getEncoded();
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, passphrase));

        // then
        assertThat(refusal.getMessage())
                .isEqualTo(
                        ContainerRefusal.integrityUnsupported(PKCSObjectIdentifiers.signedData.getId()).getMessage());
    }

    @ParameterizedTest
    @MethodSource("safeProtectionsNotAccepted")
    void read_refusesASafeUnderAProtectionItDoesNotAcceptNamingIt(ASN1ObjectIdentifier protection) throws Exception {
        // given
        EncryptedData safe = new EncryptedData(PKCSObjectIdentifiers.data,
                new AlgorithmIdentifier(protection, DERNull.INSTANCE), new DEROctetString(new byte[16]));
        byte[] file = Pkcs12Fixtures
                .withSafes(builder().certBag(chain.root(), null, null).build(),
                        new ContentInfo(PKCSObjectIdentifiers.encryptedData, safe));
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, passphrase));

        // then
        assertThat(refusal.getMessage())
                .isEqualTo(KeyFileRefusal.unsupportedProtection(protection.getId()).getMessage());
    }

    @Test
    void read_bindsBySpkiDespiteAMisleadingLocalKeyId() throws Exception {
        // given
        byte[] file = builder()
                .shroudedKeyBag(chain.leafKey().getPrivate(), PASSPHRASE, "leaf", LEAF_ID)
                .shroudedKeyBag(ec.getPrivate(), PASSPHRASE, "other", OTHER_ID)
                .certBag(chain.leaf(), "leaf", OTHER_ID)
                .mac(PASSPHRASE, SHA256)
                .build();
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        Container container = reader.read(file, passphrase);

        // then
        assertThat(container.entries())
                .map(KeyEntry.class::cast)
                .extracting(KeyEntry::alias, ContainerEntry::kind, KeyEntry::leaf)
                .containsExactly(tuple("leaf", InspectedEntryKind.KEY_PAIR_WITH_CHAIN, chain.leaf()),
                        tuple("other", InspectedEntryKind.PRIVATE_KEY, null));
    }

    @Test
    void read_chargesTheWholeFile() throws Exception {
        // given
        byte[] file = builder()
                .iterations(4_000_000)
                .shroudedKeyBag(chain.leafKey().getPrivate(), PASSPHRASE, "leaf", LEAF_ID)
                .encryptedSafe(PASSPHRASE, PBES2_AES_256)
                .certBag(chain.leaf(), "leaf", LEAF_ID)
                .mac(PASSPHRASE, SHA256)
                .build();
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, passphrase));

        // then
        assertThat(refusal.getMessage())
                .isEqualTo(KeyFileRefusal
                        .limitExceeded("key derivation iteration", DerivationBudget.FILE_ITERATIONS)
                        .getMessage());
    }

    @ParameterizedTest
    @MethodSource("derivationsOverTheBudget")
    void read_chargesEachDerivationBeforeItRuns(byte[] file, Passphrase passphrase) {
        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, passphrase));

        // then
        assertThat(refusal.getMessage())
                .isEqualTo(KeyFileRefusal
                        .limitExceeded("key derivation iteration", DerivationBudget.FILE_ITERATIONS)
                        .getMessage());
    }

    @ParameterizedTest
    @MethodSource("safesThatDoNotOpen")
    void read_refusesASafeWhoseContentIsNoSafeContentsAsUnreadable(byte[] content) throws Exception {
        // given
        byte[] file = Pkcs12Fixtures
                .withSafes(builder().certBag(chain.root(), null, null).build(),
                        Pkcs12Fixtures.encryptedSafe(content, PASSPHRASE));
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, passphrase));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    @Test
    void read_refusesMoreCertificatesThanTheLimit() throws Exception {
        // given
        Pkcs12Fixtures.Builder builder = builder();
        for (int index = 0; index <= ContainerLimits.MAXIMUM_CERTIFICATES; index++) {
            builder.certBag(chain.root(), null, null);
        }
        byte[] file = builder.mac(PASSPHRASE, SHA256).build();
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, passphrase));

        // then
        assertThat(refusal.getMessage())
                .isEqualTo(KeyFileRefusal
                        .limitExceeded("certificate count", ContainerLimits.MAXIMUM_CERTIFICATES)
                        .getMessage());
    }

    @Test
    void read_refusesMoreKeysThanTheLimitBeforeOpeningThem() throws Exception {
        // given
        Pkcs12Fixtures.Builder builder = builder();
        for (int index = 0; index <= ContainerLimits.MAXIMUM_OTHER_ENTRIES; index++) {
            builder.shroudedKeyBag(ec.getPrivate(), OTHER_PASSPHRASE, null, null);
        }
        byte[] file = builder.mac(PASSPHRASE, SHA256).build();
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, passphrase));

        // then
        assertThat(refusal.getMessage())
                .isEqualTo(KeyFileRefusal
                        .limitExceeded("entry count", ContainerLimits.MAXIMUM_OTHER_ENTRIES)
                        .getMessage());
    }

    @ParameterizedTest
    @MethodSource("deeplyNestedFiles")
    void read_refusesNestingBeyondTheLimitInsideTheFile(byte[] file) {
        // given
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, passphrase));

        // then
        assertThat(refusal.getMessage())
                .isEqualTo(KeyFileRefusal
                        .limitExceeded("nesting depth", KeyNormalizer.MAXIMUM_NESTING_DEPTH)
                        .getMessage());
    }

    @Test
    void read_asksThePkcs12FormatAmongTheOthers() throws Exception {
        // given
        byte[] file = builder()
                .keyBag(chain.leafKey().getPrivate(), "leaf", LEAF_ID)
                .certBag(chain.leaf(), "leaf", LEAF_ID)
                .build();

        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(DerFormat.class,
                PemFormat.class, Pkcs12Format.class, KeyNormalizer.class, ContainerAssembler.class,
                ContainerReader.class)) {
            // when
            Container container = context.getBean(ContainerReader.class).read(file, null);

            // then
            assertThat(container.entries())
                    .extracting(ContainerEntry::kind)
                    .containsExactly(InspectedEntryKind.KEY_PAIR_WITH_CHAIN);
        }
    }

    static Stream<Arguments> pbmac1Files() throws Exception {
        return Stream
                .of(arguments(named("OpenSSL's", openSsl(Pkcs12Fixtures.OPENSSL_PBMAC1)),
                        Pkcs12Fixtures.openSslPassphrase()),
                        arguments(named("over SHA-256", keyPairFile().pbmac1(PASSPHRASE).build()), PASSPHRASE),
                        arguments(named("over SHA-512",
                                keyPairFile().pbmac1(PASSPHRASE, PKCSObjectIdentifiers.id_hmacWithSHA512).build()),
                                PASSPHRASE),
                        arguments(named("over SHA-224, as the JDK computes it",
                                Pkcs12Fixtures
                                        .withJdkPbmac1(keyPairFile().build(), PASSPHRASE,
                                                PKCSObjectIdentifiers.id_hmacWithSHA224)),
                                PASSPHRASE),
                        arguments(named("over SHA-384, as the JDK computes it",
                                Pkcs12Fixtures
                                        .withJdkPbmac1(keyPairFile().build(), PASSPHRASE,
                                                PKCSObjectIdentifiers.id_hmacWithSHA384)),
                                PASSPHRASE));
    }

    static Stream<Named<ASN1ObjectIdentifier>> pbes1Schemes() {
        return Stream
                .of(named("MD5 and DES", PKCSObjectIdentifiers.pbeWithMD5AndDES_CBC),
                        named("SHA-1 and DES", PKCSObjectIdentifiers.pbeWithSHA1AndDES_CBC));
    }

    static Stream<Named<Passphrase>> absentPassphrases() {
        return Stream.of(named("none", null), named("an empty one", new Passphrase(EMPTY_PASSWORD)));
    }

    static Stream<Arguments> wronglyOpenedFiles() throws Exception {
        byte[] classic = builder().keyBag(ec.getPrivate(), "key", null).mac(PASSPHRASE, SHA256).build();
        byte[] pbmac1 = builder().keyBag(ec.getPrivate(), "key", null).pbmac1(PASSPHRASE).build();
        return Stream
                .of(arguments(named("a classic MAC and another passphrase", classic), new Passphrase(OTHER_PASSPHRASE)),
                        arguments(named("a classic MAC and none", classic), null),
                        arguments(named("PBMAC1 and another passphrase", pbmac1), new Passphrase(OTHER_PASSPHRASE)),
                        arguments(named("PBMAC1 and none", pbmac1), null),
                        arguments(named("OpenSSL's legacy file and none", openSsl(Pkcs12Fixtures.OPENSSL_LEGACY)),
                                null),
                        arguments(named("OpenSSL's file under an empty password and a passphrase",
                                openSsl(Pkcs12Fixtures.OPENSSL_EMPTY_PASSWORD)), new Passphrase(PASSPHRASE)),
                        arguments(named("PBMAC1 and a passphrase without a UTF-8 encoding", pbmac1),
                                new Passphrase(new char[]{'\uD800'})));
    }

    static Stream<Named<ASN1Set>> friendlyNamesOfNoText() {
        return Stream
                .of(named("a value that is no string", new DERSet(new ASN1Integer(7))),
                        named("an empty string", new DERSet(new DERBMPString(""))), named("no value", new DERSet()));
    }

    static Stream<Named<ASN1ObjectIdentifier>> classicMacDigests() {
        return Stream
                .of(named("SHA-1", OIWObjectIdentifiers.idSHA1), named("SHA-224", NISTObjectIdentifiers.id_sha224),
                        named("SHA-256", SHA256), named("SHA-384", NISTObjectIdentifiers.id_sha384),
                        named("SHA-512", NISTObjectIdentifiers.id_sha512),
                        named("SHA-512/224", NISTObjectIdentifiers.id_sha512_224),
                        named("SHA-512/256", NISTObjectIdentifiers.id_sha512_256));
    }

    static Stream<Arguments> unsupportedPbmac1Parts() {
        AlgorithmIdentifier sha256 = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, DERNull.INSTANCE);
        return Stream
                .of(arguments(named("a derivation other than PBKDF2",
                        new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBMAC1, new PBMAC1Params(
                                new AlgorithmIdentifier(MiscObjectIdentifiers.id_scrypt, DERNull.INSTANCE), sha256))),
                        MiscObjectIdentifiers.id_scrypt),
                        arguments(
                                named("a PRF over SHA-1",
                                        Pkcs12Fixtures
                                                .pbmac1(PKCSObjectIdentifiers.id_hmacWithSHA1,
                                                        PKCSObjectIdentifiers.id_hmacWithSHA256, 32)),
                                PKCSObjectIdentifiers.id_hmacWithSHA1),
                        arguments(
                                named("an HMAC over SHA-1",
                                        Pkcs12Fixtures
                                                .pbmac1(PKCSObjectIdentifiers.id_hmacWithSHA256,
                                                        PKCSObjectIdentifiers.id_hmacWithSHA1, 32)),
                                PKCSObjectIdentifiers.id_hmacWithSHA1));
    }

    static Stream<Named<AlgorithmIdentifier>> damagedPbmac1Parameters() {
        ASN1ObjectIdentifier sha256 = PKCSObjectIdentifiers.id_hmacWithSHA256;
        return Stream
                .of(named("no parameters", new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBMAC1)),
                        named("parameters that are none",
                                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBMAC1, DERNull.INSTANCE)),
                        named("no key length", Pkcs12Fixtures.pbmac1(sha256, sha256, null)),
                        named("a key length of zero", Pkcs12Fixtures.pbmac1(sha256, sha256, 0)),
                        named("a key longer than an HMAC takes", Pkcs12Fixtures.pbmac1(sha256, sha256, 65)),
                        named("a key whose derivation would take PBKDF2 far longer than its iterations",
                                Pkcs12Fixtures.pbmac1(sha256, sha256, 1 << 20)));
    }

    static Stream<Named<byte[]>> filesUnderTwoPassphrases() throws Exception {
        return Stream
                .of(named("a key",
                        builder()
                                .shroudedKeyBag(ec.getPrivate(), OTHER_PASSPHRASE, "key", null)
                                .mac(PASSPHRASE, SHA256)
                                .build()),
                        named("a secret key",
                                builder().secretBag(aes, OTHER_PASSPHRASE, "secret").mac(PASSPHRASE, SHA256).build()),
                        named("a safe under PBES2",
                                builder()
                                        .encryptedSafe(OTHER_PASSPHRASE, PBES2_AES_256)
                                        .certBag(chain.root(), null, null)
                                        .mac(PASSPHRASE, SHA256)
                                        .build()),
                        named("a safe under a PKCS#12 scheme", builder()
                                .encryptedSafe(OTHER_PASSPHRASE, PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC)
                                .certBag(chain.root(), null, null)
                                .pbmac1(PASSPHRASE)
                                .build()));
    }

    static Stream<Named<byte[]>> filesUnderAnotherPassphraseWithoutAMac() throws Exception {
        return Stream
                .of(named("a key", builder().shroudedKeyBag(ec.getPrivate(), OTHER_PASSPHRASE, "key", null).build()),
                        named("a safe",
                                builder()
                                        .encryptedSafe(OTHER_PASSPHRASE, PBES2_AES_256)
                                        .certBag(chain.root(), null, null)
                                        .build()));
    }

    static Stream<Named<ASN1Encodable>> secretsOfAnotherShape() {
        return Stream
                .of(named("an octet string of no key", new DEROctetString(new byte[]{0x04, 0x01, 0x07})),
                        named("a value that is no octet string", new ASN1Integer(7)));
    }

    static Stream<Named<ASN1ObjectIdentifier>> safeProtectionsNotAccepted() {
        return Stream
                .of(named("JKS", JKS), named("JCEKS", JCEKS),
                        named("PBES1 with MD2 and DES", PKCSObjectIdentifiers.pbeWithMD2AndDES_CBC),
                        named("PBES1 with MD5 and RC2", PKCSObjectIdentifiers.pbeWithMD5AndRC2_CBC),
                        named("PBES1 with SHA-1 and RC2", PKCSObjectIdentifiers.pbeWithSHA1AndRC2_CBC),
                        named("an unknown scheme", new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.2")));
    }

    /** Files with one key derivation over the budget, each to be refused before the derivation runs. */
    static Stream<Arguments> derivationsOverTheBudget() throws Exception {
        int overTheBudget = DerivationBudget.FILE_ITERATIONS + 1;
        ASN1ObjectIdentifier sha256 = PKCSObjectIdentifiers.id_hmacWithSHA256;
        byte[] certificate = builder().certBag(chain.root(), null, null).build();
        SafeBag key = new SafeBag(PKCSObjectIdentifiers.pkcs8ShroudedKeyBag,
                new EncryptedPrivateKeyInfo(Pkcs12Fixtures.pbes2(overTheBudget), new byte[32]));
        return Stream
                .of(arguments(named("a classic MAC", Pkcs12Fixtures
                        .withMacIterations(builder().certBag(chain.root(), null, null).mac(PASSPHRASE, SHA256).build(),
                                overTheBudget)),
                        ContainerFixtures.passphrase()),
                        arguments(
                                named("a PBMAC1", Pkcs12Fixtures
                                        .withMacAlgorithm(
                                                builder().certBag(chain.root(), null, null).pbmac1(PASSPHRASE).build(),
                                                Pkcs12Fixtures.pbmac1(sha256, sha256, 32, overTheBudget))),
                                ContainerFixtures.passphrase()),
                        arguments(
                                named("a safe",
                                        Pkcs12Fixtures
                                                .withSafes(certificate,
                                                        new ContentInfo(PKCSObjectIdentifiers.encryptedData,
                                                                new EncryptedData(PKCSObjectIdentifiers.data,
                                                                        Pkcs12Fixtures.pbes2(overTheBudget),
                                                                        new DEROctetString(new byte[32]))))),
                                ContainerFixtures.passphrase()),
                        arguments(
                                named("a protected key once the MAC verified",
                                        builder().bag(new PKCS12SafeBag(key)).mac(PASSPHRASE, SHA256).build()),
                                ContainerFixtures.passphrase()),
                        arguments(named("the second encoding of an empty password", Pkcs12Fixtures
                                .withMacIterations(
                                        builder().certBag(chain.root(), null, null).mac(PASSPHRASE, SHA256).build(),
                                        6_000_000)),
                                null));
    }

    static Stream<Named<byte[]>> safesThatDoNotOpen() throws Exception {
        return Stream
                .of(named("content nested beyond the limit",
                        ContainerFixtures.nested(KeyNormalizer.MAXIMUM_NESTING_DEPTH + 1)),
                        named("content that is no safe contents", new ASN1Integer(7).getEncoded()),
                        named("no content", new byte[0]));
    }

    static Stream<Named<byte[]>> filesMissingAStructure() throws Exception {
        byte[] certificate = builder().certBag(chain.root(), null, null).build();
        return Stream
                .of(named("an authenticated safe without content",
                        new Pfx(new ContentInfo(PKCSObjectIdentifiers.data, null), null).getEncoded()),
                        named("a safe without content",
                                Pkcs12Fixtures
                                        .withSafes(certificate, new ContentInfo(PKCSObjectIdentifiers.data, null))),
                        named("an encrypted safe without its encrypted content", Pkcs12Fixtures
                                .withSafes(certificate,
                                        new ContentInfo(PKCSObjectIdentifiers.encryptedData,
                                                new DERSequence(new ASN1Encodable[]{
                                                        new ASN1Integer(0),
                                                        new DERSequence(new ASN1Encodable[]{
                                                                PKCSObjectIdentifiers.data,
                                                                Pkcs12Fixtures.pbes2(Pkcs12Fixtures.ITERATIONS)})})))));
    }

    static Stream<Named<byte[]>> deeplyNestedFiles() throws Exception {
        byte[] nested = ContainerFixtures.nested(KeyNormalizer.MAXIMUM_NESTING_DEPTH + 1);
        return Stream
                .of(named("the authenticated safe",
                        new Pfx(new ContentInfo(PKCSObjectIdentifiers.data, new DEROctetString(nested)), null)
                                .getEncoded()),
                        named("a safe",
                                Pkcs12Fixtures
                                        .withSafes(builder().certBag(chain.root(), null, null).build(),
                                                new ContentInfo(PKCSObjectIdentifiers.data,
                                                        new DEROctetString(nested)))),
                        named("a secret",
                                builder()
                                        .bag(new PKCS12SafeBagBuilder(new PKCS12SecretBag(new SecretBag(
                                                PKCSObjectIdentifiers.pkcs8ShroudedKeyBag, new DEROctetString(nested))))
                                                .build())
                                        .build()));
    }

    /** The leaf's private key in a secret bag, protected with the passphrase as the JDK protects a secret key. */
    private static PKCS12SafeBag leafKeyInASecretBag() throws Exception {
        return new PKCS12SafeBagBuilder(new PKCS12SecretBagBuilder(PKCSObjectIdentifiers.pkcs8ShroudedKeyBag,
                new DEROctetString(ContainerFixtures.encryptedPkcs8(chain.leafKey()))).build()).build();
    }

    /** A builder of a file holding the leaf's key and certificate, without protection. */
    private static Pkcs12Fixtures.Builder keyPairFile() throws Exception {
        return builder().keyBag(chain.leafKey().getPrivate(), "leaf", LEAF_ID).certBag(chain.leaf(), "leaf", LEAF_ID);
    }

    /** OpenSSL's key and self-signed certificate, bound as one entry under OpenSSL's alias. */
    private static void assertOpenSslKeyPair(Container container) {
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.KEY_PAIR_WITH_CHAIN);
            assertThat(entry.alias()).isEqualTo(OPENSSL_ALIAS);
            assertThat(entry.description().algorithm()).isEqualTo(KeyAlgorithm.RSA);
            assertThat(entry.description().length()).isEqualTo(2048);
            assertThat(entry.leaf().getSubject()).isEqualTo(new X500Name("CN=pkcs12-test"));
            assertThat(SubjectPublicKeyInfo.getInstance(entry.description().subjectPublicKeyInfo()))
                    .isEqualTo(entry.leaf().getSubjectPublicKeyInfo());
            assertThat(entry.reference()).isEqualTo(sha256(entry.description().subjectPublicKeyInfo()));
            assertThat(entry.issuers()).isEmpty();
        });
    }

    /** A PKCS#12 store as the JDK writes it under {@link ContainerFixtures#PASSPHRASE}. */
    private static byte[] jdkStore(StoreEntries entries) throws GeneralSecurityException, IOException {
        return jdkStore(PASSPHRASE, entries);
    }

    /** A PKCS#12 store as the JDK writes it under the password given. */
    private static byte[] jdkStore(char[] password, StoreEntries entries) throws GeneralSecurityException, IOException {
        KeyStore store = KeyStore.getInstance("PKCS12", "SUN");
        store.load(null, null);
        entries.set(store);
        ByteArrayOutputStream file = new ByteArrayOutputStream();
        store.store(file, password);
        return file.toByteArray();
    }

    private static X509Certificate jca(X509CertificateHolder certificate) throws GeneralSecurityException {
        return new JcaX509CertificateConverter().getCertificate(certificate);
    }

    /** Sets the entries of a store. */
    @FunctionalInterface
    private interface StoreEntries {

        void set(KeyStore store) throws GeneralSecurityException;
    }
}

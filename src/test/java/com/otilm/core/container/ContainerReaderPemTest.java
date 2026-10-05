package com.otilm.core.container;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.inspection.InspectedEntryKind;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.container.ContainerFixtures.Chain;
import com.otilm.core.key.normalization.KeyFileRefusal;
import com.otilm.core.key.normalization.KeyNormalizer;
import com.otilm.core.util.CertificateUtil;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.stream.Stream;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.pem.PemObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;

import static com.otilm.core.container.ContainerFixtures.CRLF;
import static com.otilm.core.container.ContainerFixtures.LF;
import static com.otilm.core.container.ContainerFixtures.sha256;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Named.named;

class ContainerReaderPemTest {

    private static ContainerReader reader;

    private static Chain chain;

    @BeforeAll
    static void fixtures() throws Exception {
        ContainerFixtures.registerProviders();
        reader = ContainerFixtures.reader();
        chain = ContainerFixtures.rsaChain();
    }

    @Test
    void read_readsASingleCertificate() throws Exception {
        // given
        byte[] file = ContainerFixtures.pem(LF, chain.leaf());
        String fingerprint = CertificateUtil
                .getThumbprint(new JcaX509CertificateConverter().getCertificate(chain.leaf()));

        // when
        Container container = reader.read(file, null);

        // then
        assertThat(container.digest()).isEqualTo(sha256(file));
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(CertificateEntry.class, entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.CERTIFICATE);
            assertThat(entry.reference()).isEqualTo(fingerprint);
            assertThat(entry.certificate()).isEqualTo(chain.leaf());
            assertThat(entry.alias()).isNull();
        });
    }

    @Test
    void read_readsAChainAndItsKeyAsOneKeyPairEntry() throws Exception {
        // given
        byte[] file = ContainerFixtures
                .pem(LF, chain.root(), chain.intermediate(), chain.leaf(),
                        ContainerFixtures.privateKeyBlock(chain.leafKey()));

        // when
        Container container = reader.read(file, null);

        // then
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.KEY_PAIR_WITH_CHAIN);
            assertThat(entry.reference()).isEqualTo(sha256(chain.leafKey().getPublic().getEncoded()));
            assertThat(entry.leaf()).isEqualTo(chain.leaf());
            assertThat(entry.issuers()).containsExactly(chain.intermediate(), chain.root());
            assertThat(entry.description().algorithm()).isEqualTo(KeyAlgorithm.RSA);
            assertThat(entry.secret()).isFalse();
        });
    }

    @Test
    void read_readsAPemBundleAsOpenSslWritesIt() throws Exception {
        // given
        byte[] file = ContainerFixtures
                .withByteOrderMark(ContainerFixtures
                        .pem(CRLF, "Bag Attributes", "    localKeyID: 01 02 03 04", "    friendlyName: leaf",
                                "subject=CN = Leaf", "issuer=CN = Intermediate", chain.leaf(),
                                "Bag Attributes: <No Attributes>", "subject=CN = Intermediate", "issuer=CN = Root",
                                chain.intermediate(), "Bag Attributes: <No Attributes>", "subject=CN = Root",
                                "issuer=CN = Root", chain.root(), "Bag Attributes", "    localKeyID: 01 02 03 04",
                                "    friendlyName: leaf", "Key Attributes: <No Attributes>",
                                ContainerFixtures.privateKeyBlock(chain.leafKey())));

        // when
        Container container = reader.read(file, null);

        // then
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.KEY_PAIR_WITH_CHAIN);
            assertThat(entry.leaf()).isEqualTo(chain.leaf());
            assertThat(entry.issuers()).containsExactly(chain.intermediate(), chain.root());
        });
    }

    @ParameterizedTest
    @MethodSource("encryptedKeys")
    void read_readsAnEncryptedKeyWithThePassphrase(Object keyBlock) throws Exception {
        // given
        byte[] file = ContainerFixtures.pem(LF, chain.leaf(), keyBlock);
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
    @MethodSource("encryptedKeys")
    void read_refusesAnEncryptedKeyWithoutItsPassphrase(Object keyBlock) throws Exception {
        // given
        byte[] file = ContainerFixtures.pem(LF, chain.leaf(), keyBlock);

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, null));

        // then
        assertThat(refusal.getMessage()).isEqualTo(KeyFileRefusal.UNREADABLE);
    }

    @Test
    void read_refusesTwoPrivateKeys() throws Exception {
        // given
        byte[] file = ContainerFixtures
                .pem(LF, ContainerFixtures.privateKeyBlock(chain.leafKey()),
                        ContainerFixtures.privateKeyBlock(chain.intermediateKey()));

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, null));

        // then
        assertThat(refusal.getMessage()).isEqualTo(ContainerRefusal.PEM_TOO_MANY_KEYS);
    }

    @Test
    void read_refusesAnUnknownBlockNamingIt() throws Exception {
        // given
        byte[] file = ContainerFixtures
                .pem(LF, chain.leaf(), ContainerFixtures.privateKeyBlock(chain.leafKey()),
                        new PemObject("X509 CRL", new byte[]{0x30, 0x00}));

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, null));

        // then
        assertThat(refusal.getMessage())
                .isEqualTo("The file holds a PEM block of type X509 CRL, which is not supported.");
    }

    @Test
    void read_refusesAnUnknownBlockWithoutRepeatingAnUnusualType() throws Exception {
        // given
        byte[] file = ContainerFixtures.pem(LF, new PemObject("X".repeat(65), new byte[]{0x30, 0x00}));

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, null));

        // then
        assertThat(refusal.getMessage())
                .isEqualTo("The file holds a PEM block of type an unrecognized type, which is not supported.");
    }

    @ParameterizedTest
    @MethodSource("damagedFiles")
    void read_refusesDamagedPemAsNotSupported(byte[] file) {
        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, null));

        // then
        assertThat(refusal.getMessage()).isEqualTo(ContainerRefusal.NOT_SUPPORTED_FORMAT);
    }

    @Test
    void read_refusesABlockStartItCannotReadRatherThanTheBlocksAfterIt() throws Exception {
        // given
        byte[] file = ContainerFixtures
                .pem(LF, chain.leaf(), "-----BEGIN PRIVATE KEY", "MAA=", "-----END PRIVATE KEY-----",
                        ContainerFixtures.privateKeyBlock(chain.leafKey()));

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, null));

        // then
        assertThat(refusal.getMessage()).isEqualTo(ContainerRefusal.NOT_SUPPORTED_FORMAT);
    }

    @ParameterizedTest
    @ValueSource(strings = {"CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"})
    void read_listsASigningRequest(String type) throws Exception {
        // given
        PKCS10CertificationRequest request = ContainerFixtures.signingRequest(chain.leafKey());
        byte[] der = request.getEncoded();
        byte[] file = ContainerFixtures.pem(LF, new PemObject(type, der));

        // when
        Container container = reader.read(file, null);

        // then
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(SigningRequestEntry.class, entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.SIGNING_REQUEST);
            assertThat(entry.reference()).isEqualTo(sha256(der));
            assertThat(entry.request()).isEqualTo(request);
        });
    }

    @Test
    void read_readsATrustedCertificateWithoutItsTrustData() throws Exception {
        // given
        byte[] certificate = chain.root().getEncoded();
        byte[] trust = new DERSequence(new DERSequence(KeyPurposeId.id_kp_serverAuth)).getEncoded(ASN1Encoding.DER);
        byte[] file = ContainerFixtures
                .pem(LF, new PemObject("TRUSTED CERTIFICATE", Arrays.concatenate(certificate, trust)));

        // when
        Container container = reader.read(file, null);

        // then
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(CertificateEntry.class, entry -> {
            assertThat(entry.certificate()).isEqualTo(chain.root());
            assertThat(entry.reference()).isEqualTo(sha256(certificate));
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"PKCS7", "CMS"})
    void read_readsTheCertificatesOfAPkcs7Block(String type) throws Exception {
        // given
        byte[] file = ContainerFixtures
                .pem(LF, new PemObject(type, ContainerFixtures.pkcs7(chain.leaf(), chain.intermediate())));

        // when
        Container container = reader.read(file, null);

        // then
        assertThat(container.entries())
                .map(entry -> ((CertificateEntry) entry).certificate())
                .containsExactly(chain.leaf(), chain.intermediate());
    }

    @Test
    void read_listsAKeyAndACertificateThatEncodeTheKeyDifferentlyApart() throws Exception {
        // given
        KeyPair ec = ContainerFixtures.ec();
        X509CertificateHolder certificate = ContainerFixtures.selfSigned(ec, "CN=Named curve");
        byte[] file = ContainerFixtures
                .pem(LF, certificate, new PemObject("PRIVATE KEY", ContainerFixtures.explicitCurvePkcs8(ec)));

        // when
        Container container = reader.read(file, null);

        // then
        assertThat(container.entries())
                .extracting(ContainerEntry::kind)
                .containsExactly(InspectedEntryKind.CERTIFICATE, InspectedEntryKind.PRIVATE_KEY);
    }

    @Test
    void read_referencesAKeyOfAnUnsupportedAlgorithmByTheContentOfItsBlock() throws Exception {
        // given
        KeyPair ed25519 = ContainerFixtures.ed25519();
        byte[] file = ContainerFixtures.pem(LF, ContainerFixtures.privateKeyBlock(ed25519));

        // when
        Container container = reader.read(file, null);

        // then
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.PRIVATE_KEY);
            assertThat(entry.reference()).isEqualTo(sha256(ContainerFixtures.pkcs8(ed25519)));
            assertThat(entry.description().supported()).isFalse();
        });
    }

    @Test
    void read_skipsEcParameters() throws Exception {
        // given
        KeyPair ec = ContainerFixtures.ec();
        byte[] file = ContainerFixtures
                .pem(LF, ContainerFixtures.ecParametersBlock(), ContainerFixtures.traditional(ec, null));

        // when
        Container container = reader.read(file, null);

        // then
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.PRIVATE_KEY);
            assertThat(entry.description().algorithm()).isEqualTo(KeyAlgorithm.ECDSA);
            assertThat(entry.reference()).isEqualTo(sha256(ec.getPublic().getEncoded()));
        });
    }

    @Test
    void read_readsAnEmptyFileOfParametersAsNoEntries() throws Exception {
        // given
        byte[] file = ContainerFixtures.pem(LF, ContainerFixtures.ecParametersBlock());

        // when
        Container container = reader.read(file, null);

        // then
        assertThat(container.entries()).isEmpty();
        assertThat(container.digest()).isEqualTo(sha256(file));
    }

    @Test
    void read_asksThePemFormatBeforeTheDerOne() throws Exception {
        // given
        byte[] file = ContainerFixtures.pem(LF, chain.leaf());

        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(DerFormat.class,
                PemFormat.class, KeyNormalizer.class, ContainerAssembler.class, ContainerReader.class)) {
            // when
            Container container = context.getBean(ContainerReader.class).read(file, null);

            // then
            assertThat(container.entries())
                    .extracting(ContainerEntry::kind)
                    .containsExactly(InspectedEntryKind.CERTIFICATE);
        }
    }

    @Test
    void entry_findsAnEntryByItsReference() throws Exception {
        // given
        Container container = reader.read(ContainerFixtures.pem(LF, chain.leaf(), chain.root()), null);
        String reference = sha256(chain.root().getEncoded());

        // when, then
        assertThat(container.entry(reference))
                .hasValueSatisfying(entry -> assertThat(entry.reference()).isEqualTo(reference));
        assertThat(container.entry(sha256(new byte[0]))).isEmpty();
    }

    @Test
    void clear_overwritesEveryKeyTheEntriesKeep() throws Exception {
        // given
        Container container = reader
                .read(ContainerFixtures.pem(LF, chain.leaf(), ContainerFixtures.privateKeyBlock(chain.leafKey())),
                        null);
        byte[] keyFile = ((KeyEntry) container.entries().getFirst()).keyFile();
        assertThat(new String(keyFile, StandardCharsets.US_ASCII)).startsWith("-----BEGIN PRIVATE KEY-----");

        // when
        container.clear();

        // then
        assertThat(keyFile).containsOnly(0);
    }

    static Stream<Named<Object>> encryptedKeys() throws Exception {
        return Stream
                .of(named("PKCS#8", ContainerFixtures.encryptedPrivateKeyBlock(chain.leafKey())),
                        named("OpenSSL traditional", ContainerFixtures.traditional(chain.leafKey(), "AES-256-CBC")));
    }

    static Stream<Named<byte[]>> damagedFiles() {
        return Stream
                .of(named("a block without its end",
                        "-----BEGIN CERTIFICATE-----\nMIIB\n".getBytes(StandardCharsets.US_ASCII)),
                        named("a block that is not base64",
                                "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n"
                                        .getBytes(StandardCharsets.US_ASCII)),
                        named("a block that is not a certificate",
                                "-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n"
                                        .getBytes(StandardCharsets.US_ASCII)),
                        named("a block that is not a certificate request",
                                "-----BEGIN CERTIFICATE REQUEST-----\nMAA=\n-----END CERTIFICATE REQUEST-----\n"
                                        .getBytes(StandardCharsets.US_ASCII)),
                        named("a trusted certificate without content",
                                "-----BEGIN TRUSTED CERTIFICATE-----\n-----END TRUSTED CERTIFICATE-----\n"
                                        .getBytes(StandardCharsets.US_ASCII)),
                        named("a malformed first line", "-----BEGIN CERTIFICATE\nMAA=\n-----END CERTIFICATE-----\n"
                                .getBytes(StandardCharsets.US_ASCII)));
    }
}

package com.otilm.core.container;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.inspection.InspectedEntryKind;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.container.ContainerFixtures.Chain;
import com.otilm.core.key.normalization.KeyFileRefusal;
import com.otilm.core.key.normalization.KeyNormalizer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.stream.Stream;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static com.otilm.core.container.ContainerFixtures.sha256;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Named.named;

class ContainerReaderDerTest {

    private static ContainerReader reader;

    private static Chain chain;

    @BeforeAll
    static void fixtures() throws Exception {
        ContainerFixtures.registerProviders();
        reader = ContainerFixtures.reader();
        chain = ContainerFixtures.rsaChain();
    }

    @Test
    void read_readsADerCertificate() throws Exception {
        // given
        byte[] file = chain.leaf().getEncoded();

        // when
        Container container = reader.read(file, null);

        // then
        assertThat(container.digest()).isEqualTo(sha256(file));
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(CertificateEntry.class, entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.CERTIFICATE);
            assertThat(entry.reference()).isEqualTo(sha256(file));
            assertThat(entry.certificate()).isEqualTo(chain.leaf());
        });
    }

    @Test
    void read_readsTheCertificatesOfADerPkcs7() throws Exception {
        // given
        byte[] file = ContainerFixtures.pkcs7(chain.root(), chain.intermediate(), chain.leaf());

        // when
        Container container = reader.read(file, null);

        // then
        assertThat(container.entries())
                .extracting(ContainerEntry::kind)
                .containsExactly(InspectedEntryKind.CERTIFICATE, InspectedEntryKind.CERTIFICATE,
                        InspectedEntryKind.CERTIFICATE);
        assertThat(container.entries())
                .map(entry -> ((CertificateEntry) entry).certificate())
                .containsExactly(chain.root(), chain.intermediate(), chain.leaf());
    }

    @Test
    void read_readsOnlyTheCertificatesOfAPkcs7() throws Exception {
        // given
        byte[] file = ContainerFixtures
                .pkcs7WithOtherContent(chain.leaf(), chain.intermediate(), chain.intermediateKey().getPrivate());

        // when
        Container container = reader.read(file, null);

        // then
        assertThat(container.entries())
                .singleElement()
                .isInstanceOfSatisfying(CertificateEntry.class,
                        entry -> assertThat(entry.certificate()).isEqualTo(chain.leaf()));
    }

    @Test
    void read_readsAPkcs7WithoutCertificatesAsNoEntries() throws Exception {
        // given
        byte[] file = ContainerFixtures.pkcs7();

        // when
        Container container = reader.read(file, null);

        // then
        assertThat(container.entries()).isEmpty();
    }

    @Test
    void read_readsADerSigningRequest() throws Exception {
        // given
        PKCS10CertificationRequest request = ContainerFixtures.signingRequest(chain.leafKey());
        byte[] file = request.getEncoded();

        // when
        Container container = reader.read(file, null);

        // then
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(SigningRequestEntry.class, entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.SIGNING_REQUEST);
            assertThat(entry.reference()).isEqualTo(sha256(file));
            assertThat(entry.request()).isEqualTo(request);
        });
    }

    @Test
    void read_readsAPlainDerPkcs8Key() {
        // given
        byte[] file = ContainerFixtures.pkcs8(chain.leafKey());

        // when
        Container container = reader.read(file, null);

        // then
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.PRIVATE_KEY);
            assertThat(entry.reference()).isEqualTo(sha256(chain.leafKey().getPublic().getEncoded()));
            assertThat(entry.keyFile()).isEqualTo(file).isNotSameAs(file);
        });
    }

    @Test
    void read_readsAnEncryptedDerPkcs8KeyWithThePassphrase() throws Exception {
        // given
        byte[] file = ContainerFixtures.encryptedPkcs8(chain.leafKey());
        Passphrase passphrase = ContainerFixtures.passphrase();

        // when
        Container container = reader.read(file, passphrase);

        // then
        assertThat(container.entries()).singleElement().isInstanceOfSatisfying(KeyEntry.class, entry -> {
            assertThat(entry.kind()).isEqualTo(InspectedEntryKind.PRIVATE_KEY);
            assertThat(entry.reference()).isEqualTo(sha256(chain.leafKey().getPublic().getEncoded()));
            assertThat(entry.keyFile()).isEqualTo(file);
        });
    }

    @ParameterizedTest
    @MethodSource("unknownStructures")
    void read_refusesAnUnknownStructure(byte[] file) {
        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, null));

        // then
        assertThat(refusal.getMessage()).isEqualTo(ContainerRefusal.NOT_SUPPORTED_FORMAT);
    }

    @Test
    void read_refusesNestingBeyondTheLimit() throws Exception {
        // given
        byte[] file = ContainerFixtures.nested(KeyNormalizer.MAXIMUM_NESTING_DEPTH + 1);

        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, null));

        // then
        assertThat(refusal.getMessage())
                .isEqualTo(
                        KeyFileRefusal.LIMIT_EXCEEDED.formatted("nesting depth", KeyNormalizer.MAXIMUM_NESTING_DEPTH));
    }

    /**
     * A key stating a curve larger than any the platform holds by name, over a 571-bit field with a 400,000-bit order
     * and a cofactor of 2, would cost seconds once a key is built from it, so the file is refused as it is read.
     */
    @ParameterizedTest
    @MethodSource("itemsStatingACurveLargerThanAnyNamedOne")
    void read_refusesAnItemWhoseKeyStatesACurveLargerThanAnyNamedOne(byte[] file) {
        // when
        ValidationException refusal = assertTimeoutPreemptively(Duration.ofMillis(200),
                () -> assertThrows(ValidationException.class, () -> reader.read(file, null)));

        // then
        assertThat(refusal.getMessage()).isEqualTo(ContainerRefusal.NOT_SUPPORTED_FORMAT);
    }

    /** A 571-bit field and a 572-bit order are the most a curve the platform holds by name comes to. */
    @Test
    void read_readsACertificateWhoseKeyStatesACurveNoLargerThanTheNamedOnes() throws Exception {
        // given
        byte[] file = ContainerFixtures.certificateOf(ContainerFixtures.explicitCurvePublicKey(571, 572)).getEncoded();

        // when
        Container container = reader.read(file, null);

        // then
        assertThat(container.entries())
                .extracting(ContainerEntry::kind)
                .containsExactly(InspectedEntryKind.CERTIFICATE);
    }

    /** The DER format leaves a keystore to its own format, so a reader without that format refuses it. */
    @ParameterizedTest
    @MethodSource("keystores")
    void read_refusesAKeystoreWithoutAFormatForIt(byte[] file) {
        // when
        ValidationException refusal = assertThrows(ValidationException.class, () -> reader.read(file, null));

        // then
        assertThat(new DerFormat().recognizes(file)).isFalse();
        assertThat(refusal.getMessage()).isEqualTo(ContainerRefusal.NOT_SUPPORTED_FORMAT);
    }

    static Stream<Named<byte[]>> unknownStructures() throws Exception {
        return Stream
                .of(named("a structure of no supported type",
                        new DERSequence(new ASN1Integer(7)).getEncoded(ASN1Encoding.DER)),
                        named("a content type other than signed data",
                                new ContentInfo(CMSObjectIdentifiers.envelopedData, DERNull.INSTANCE)
                                        .getEncoded(ASN1Encoding.DER)),
                        named("signed data that is not a SignedData",
                                new ContentInfo(CMSObjectIdentifiers.signedData, new DERSequence(new ASN1Integer(1)))
                                        .getEncoded(ASN1Encoding.DER)),
                        named("bytes that are not DER", "not a file".getBytes(StandardCharsets.US_ASCII)),
                        named("an empty file", new byte[0]));
    }

    static Stream<Named<byte[]>> itemsStatingACurveLargerThanAnyNamedOne() throws Exception {
        SubjectPublicKeyInfo publicKey = ContainerFixtures.explicitCurvePublicKey(571, 400_000);
        return Stream
                .of(named("a certificate", ContainerFixtures.certificateOf(publicKey).getEncoded()),
                        named("a certificate request", ContainerFixtures.signingRequestOf(publicKey).getEncoded()));
    }

    static Stream<Named<byte[]>> keystores() throws Exception {
        return Stream
                .of(named("PKCS#12", ContainerFixtures.keyStore("PKCS12")),
                        named("JKS", ContainerFixtures.keyStore("JKS")),
                        named("JCEKS", ContainerFixtures.keyStore("JCEKS")));
    }
}

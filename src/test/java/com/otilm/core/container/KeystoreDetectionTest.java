package com.otilm.core.container;

import com.otilm.core.key.normalization.KeyNormalizer;
import java.util.Random;
import java.util.stream.Stream;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Named.named;

class KeystoreDetectionTest {

    @BeforeAll
    static void providers() {
        ContainerFixtures.registerProviders();
    }

    @ParameterizedTest
    @ValueSource(strings = {"JKS", "JCEKS"})
    void isJavaKeyStore_recognizesTheMagicOfTheStore(String type) throws Exception {
        // given
        byte[] file = ContainerFixtures.keyStore(type);

        // when, then
        assertThat(KeystoreDetection.isJavaKeyStore(file)).isTrue();
        assertThat(KeystoreDetection.isPkcs12(file)).isFalse();
        assertThat(KeystoreDetection.isKeystore(file)).isTrue();
    }

    @Test
    void isPkcs12_recognizesAPfx() throws Exception {
        // given
        byte[] file = ContainerFixtures.keyStore("PKCS12");

        // when, then
        assertThat(KeystoreDetection.isPkcs12(file)).isTrue();
        assertThat(KeystoreDetection.isJavaKeyStore(file)).isFalse();
        assertThat(KeystoreDetection.isKeystore(file)).isTrue();
    }

    @ParameterizedTest
    @MethodSource("otherFiles")
    void isKeystore_isFalseForAnyOtherFile(byte[] file) {
        // when, then
        assertThat(KeystoreDetection.isJavaKeyStore(file)).isFalse();
        assertThat(KeystoreDetection.isPkcs12(file)).isFalse();
        assertThat(KeystoreDetection.isKeystore(file)).isFalse();
    }

    static Stream<Named<byte[]>> otherFiles() throws Exception {
        byte[] random = new byte[1024];
        new Random(1L).nextBytes(random);
        return Stream
                .of(named("a certificate",
                        ContainerFixtures.selfSigned(ContainerFixtures.ec(), "CN=Other").getEncoded()),
                        named("random bytes", random),
                        named("a structure of version 3 that is no PFX",
                                new DERSequence(new ASN1Integer(3)).getEncoded(ASN1Encoding.DER)),
                        named("a PFX nesting beyond the limit",
                                pfx(ASN1Primitive
                                        .fromByteArray(ContainerFixtures.nested(KeyNormalizer.MAXIMUM_NESTING_DEPTH)))),
                        named("a file shorter than the magic", new byte[]{(byte) 0xFE, (byte) 0xED}),
                        named("an empty file", new byte[0]));
    }

    @Test
    void isPkcs12_recognizesAPfxOfTheContentWithinTheLimit() throws Exception {
        // given
        byte[] file = pfx(
                ASN1Primitive.fromByteArray(ContainerFixtures.nested(KeyNormalizer.MAXIMUM_NESTING_DEPTH - 3)));

        // when, then
        assertThat(KeystoreDetection.isPkcs12(file)).isTrue();
    }

    /** A PFX of version 3 whose authenticated safe is the content, without integrity protection. */
    private static byte[] pfx(ASN1Encodable content) throws Exception {
        return new DERSequence(
                new ASN1Encodable[]{new ASN1Integer(3), new ContentInfo(PKCSObjectIdentifiers.data, content)})
                .getEncoded(ASN1Encoding.DER);
    }
}

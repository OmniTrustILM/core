package com.otilm.core.util.crl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CRLReason;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import javax.security.auth.x500.X500Principal;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static com.otilm.core.util.builders.X509CrlBuilder.anX509Crl;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;

/**
 * Checks the parser against the JDK's own: for every CRL both accept, the header, the entries and the signature verdict
 * must be the same.
 */
class EncodedCrlTest {

    private static final X500Principal ISSUER = new X500Principal("CN=Encoded CRL Test CA, O=OmniTrust");
    private static final Instant REVOKED_AT = Instant.parse("2026-03-04T05:06:07Z");
    private static final int ENTRY_COUNT = 250;
    private static final ASN1ObjectIdentifier UNKNOWN_EXTENSION = new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.1");

    private static KeyPair rsaKeyPair;

    @BeforeAll
    static void registerBouncyCastleAndCreateKey() throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        rsaKeyPair = keyPair("RSA", null);
    }

    // ── MatchingTheJdkParser ─────────────────────────────────────────────────

    @Nested
    class MatchingTheJdkParser {

        @ParameterizedTest
        @MethodSource("com.otilm.core.util.crl.EncodedCrlTest#signatureAlgorithms")
        void readsHeaderLikeJdk_whenSignedWith(SignatureAlgorithm algorithm) throws Exception {
            // given
            byte[] crl = crlWithEntries(algorithm.keyPair(), algorithm.name());

            // when
            EncodedCrl parsed = EncodedCrl.parse(crl);

            // then
            X509CRL jdk = jdkParse(crl);
            assertThat(parsed.header().getIssuerX500Principal()).isEqualTo(jdk.getIssuerX500Principal());
            assertThat(parsed.header().getThisUpdate()).isEqualTo(jdk.getThisUpdate());
            assertThat(parsed.header().getNextUpdate()).isEqualTo(jdk.getNextUpdate());
            assertThat(parsed.header().getSigAlgName()).isEqualTo(jdk.getSigAlgName());
            assertThat(parsed.header().getExtensionValue(Extension.cRLNumber.getId()))
                    .isEqualTo(jdk.getExtensionValue(Extension.cRLNumber.getId()));
        }

        @ParameterizedTest
        @MethodSource("com.otilm.core.util.crl.EncodedCrlTest#signatureAlgorithms")
        void readsEntriesLikeJdk_whenSignedWith(SignatureAlgorithm algorithm) throws Exception {
            // given
            byte[] crl = crlWithEntries(algorithm.keyPair(), algorithm.name());

            // when
            EncodedCrl parsed = EncodedCrl.parse(crl);

            // then
            assertThat(listOf(parsed.entries())).containsExactlyInAnyOrderElementsOf(jdkEntries(crl));
        }

        @ParameterizedTest
        @MethodSource("com.otilm.core.util.crl.EncodedCrlTest#signatureAlgorithms")
        void verifiesSignature_whenSignedWith(SignatureAlgorithm algorithm) throws Exception {
            // given
            byte[] crl = crlWithEntries(algorithm.keyPair(), algorithm.name());

            // when
            boolean signed = EncodedCrl.parse(crl).isSignedBy(algorithm.keyPair().getPublic());

            // then
            assertThat(signed).isTrue();
        }

        @ParameterizedTest
        @MethodSource("com.otilm.core.util.crl.EncodedCrlTest#signatureAlgorithms")
        void refusesSignature_whenEntryWasAlteredAfterSigningWith(SignatureAlgorithm algorithm) throws Exception {
            // given
            byte[] crl = crlWithEntries(algorithm.keyPair(), algorithm.name());
            byte[] altered = alterLastSerialNumber(crl);

            // when
            boolean signed = EncodedCrl.parse(altered).isSignedBy(algorithm.keyPair().getPublic());

            // then
            assertThat(signed).isFalse();
        }

        @Test
        void refusesSignature_whenAnotherKeySigned() throws Exception {
            // given
            byte[] crl = crlWithEntries(rsaKeyPair, "SHA256WithRSAEncryption");
            KeyPair otherKeyPair = keyPair("RSA", null);

            // when
            boolean signed = EncodedCrl.parse(crl).isSignedBy(otherKeyPair.getPublic());

            // then
            assertThat(signed).isFalse();
        }

        // ── Helpers ──────────────────────────────────────────────────────────

        /** Changes the last byte of the last entry's serial number, which the signature covers. */
        private static byte[] alterLastSerialNumber(byte[] der) throws Exception {
            byte[] altered = der.clone();
            int serialNumberContentEnd = lastSerialNumberContentEnd(der);
            altered[serialNumberContentEnd - 1] ^= 0x01;
            return altered;
        }

        private static int lastSerialNumberContentEnd(byte[] der) throws Exception {
            int tagOffset = lastSerialNumberTagOffset(der);
            int length = der[tagOffset + 1] & 0xff;
            return tagOffset + 2 + length;
        }
    }

    // ── Entries ──────────────────────────────────────────────────────────────

    @Nested
    class Entries {

        @ParameterizedTest
        @MethodSource("com.otilm.core.util.crl.EncodedCrlTest#reasonCodes")
        void readsReasonLikeJdk_whenEntryCarriesReasonCode(int reasonCode) throws Exception {
            // given
            byte[] crl = anX509Crl(ISSUER, rsaKeyPair.getPrivate())
                    .withRevocation(BigInteger.TEN, REVOKED_AT, reasonCodeExtension(reasonCode))
                    .build()
                    .getEncoded();

            // when
            List<RevokedCertificate> entries = listOf(EncodedCrl.parse(crl).entries());

            // then
            assertThat(entries).containsExactlyElementsOf(jdkEntries(crl));
        }

        @Test
        void readsNoReason_whenEntryCarriesNoExtension() throws Exception {
            // given
            byte[] crl = anX509Crl(ISSUER, rsaKeyPair.getPrivate())
                    .withRevocation(BigInteger.TEN, REVOKED_AT, null)
                    .build()
                    .getEncoded();

            // when
            List<RevokedCertificate> entries = listOf(EncodedCrl.parse(crl).entries());

            // then
            assertThat(entries)
                    .containsExactly(new RevokedCertificate(BigInteger.TEN, Date.from(REVOKED_AT), null))
                    .containsExactlyElementsOf(jdkEntries(crl));
        }

        @Test
        void readsEntryLikeJdk_whenRevocationDateIsGeneralizedTime() throws Exception {
            // given
            var revokedAfter2049 = Instant.parse("2051-06-07T08:09:10Z");
            byte[] crl = anX509Crl(ISSUER, rsaKeyPair.getPrivate())
                    .withRevocation(BigInteger.TWO, CRLReason.KEY_COMPROMISE.ordinal(), revokedAfter2049)
                    .build()
                    .getEncoded();

            // when
            List<RevokedCertificate> entries = listOf(EncodedCrl.parse(crl).entries());

            // then
            assertThat(entries).containsExactlyElementsOf(jdkEntries(crl));
            assertThat(entries.getFirst().revocationDate()).isEqualTo(Date.from(revokedAfter2049));
        }

        @Test
        void readsEntryLikeJdk_whenSerialNumberIsNegative() throws Exception {
            // given
            var negativeSerialNumber = BigInteger.valueOf(-4242);
            byte[] crl = anX509Crl(ISSUER, rsaKeyPair.getPrivate())
                    .withRevocation(negativeSerialNumber, CRLReason.SUPERSEDED.ordinal(), REVOKED_AT)
                    .build()
                    .getEncoded();

            // when
            List<RevokedCertificate> entries = listOf(EncodedCrl.parse(crl).entries());

            // then
            assertThat(entries).containsExactlyElementsOf(jdkEntries(crl));
        }

        @Test
        void readsEntryLikeJdk_whenEntryCarriesFurtherExtensions() throws Exception {
            // given
            ExtensionsGenerator extensions = new ExtensionsGenerator();
            extensions.addExtension(Extension.reasonCode, false, new ASN1Enumerated(CRLReason.CA_COMPROMISE.ordinal()));
            extensions
                    .addExtension(Extension.invalidityDate, false,
                            new ASN1GeneralizedTime(Date.from(REVOKED_AT.minusSeconds(3_600))));
            byte[] crl = anX509Crl(ISSUER, rsaKeyPair.getPrivate())
                    .withRevocation(BigInteger.ONE, REVOKED_AT, extensions.generate())
                    .build()
                    .getEncoded();

            // when
            List<RevokedCertificate> entries = listOf(EncodedCrl.parse(crl).entries());

            // then
            assertThat(entries).containsExactlyElementsOf(jdkEntries(crl));
        }

        @Test
        void keepsEntriesOutOfHeader_whenCrlIsDerEncoded() throws Exception {
            // given
            byte[] crl = crlWithEntries(rsaKeyPair, "SHA256WithRSAEncryption");

            // when
            EncodedCrl parsed = EncodedCrl.parse(crl);

            // then
            assertThat(parsed.header().getRevokedCertificates()).isNull();
        }

        @Test
        void readsSameEntries_whenIteratedAgain() throws Exception {
            // given
            EncodedCrl parsed = EncodedCrl.parse(crlWithEntries(rsaKeyPair, "SHA256WithRSAEncryption"));
            List<RevokedCertificate> firstPass = listOf(parsed.entries());

            // when
            List<RevokedCertificate> secondPass = listOf(parsed.entries());

            // then
            assertThat(secondPass).isEqualTo(firstPass).hasSize(ENTRY_COUNT);
        }

        @Test
        void returnsLatestRevocationDate_whenCrlListsSeveral() throws Exception {
            // given
            var latest = REVOKED_AT.plusSeconds(86_400);
            byte[] crl = anX509Crl(ISSUER, rsaKeyPair.getPrivate())
                    .withRevocation(BigInteger.ONE, CRLReason.KEY_COMPROMISE.ordinal(), REVOKED_AT)
                    .withRevocation(BigInteger.TWO, CRLReason.KEY_COMPROMISE.ordinal(), latest)
                    .withRevocation(BigInteger.TEN, CRLReason.KEY_COMPROMISE.ordinal(), REVOKED_AT)
                    .build()
                    .getEncoded();

            // when
            Date lastRevocationDate = EncodedCrl.parse(crl).lastRevocationDate();

            // then
            assertThat(lastRevocationDate).isEqualTo(Date.from(latest));
        }

        @Test
        void readsNoEntries_whenCrlListsNone() throws Exception {
            // given
            byte[] crl = anX509Crl(ISSUER, rsaKeyPair.getPrivate()).build().getEncoded();

            // when
            EncodedCrl parsed = EncodedCrl.parse(crl);

            // then
            assertThat(listOf(parsed.entries())).isEmpty();
            assertThat(parsed.lastRevocationDate()).isNull();
            assertThat(parsed.isSignedBy(rsaKeyPair.getPublic())).isTrue();
        }

        // ── Helpers ──────────────────────────────────────────────────────────

        private static Extensions reasonCodeExtension(int reasonCode) throws Exception {
            ExtensionsGenerator extensions = new ExtensionsGenerator();
            extensions.addExtension(Extension.reasonCode, false, new ASN1Enumerated(reasonCode));
            return extensions.generate();
        }
    }

    // ── Encodings ────────────────────────────────────────────────────────────

    @Nested
    class Encodings {

        @Test
        void readsCrlLikeJdk_whenItIsPemArmoured() throws Exception {
            // given
            byte[] der = crlWithEntries(rsaKeyPair, "SHA256WithRSAEncryption");
            byte[] pem = ("-----BEGIN X509 CRL-----\n" + Base64.getMimeEncoder().encodeToString(der)
                    + "\n-----END X509 CRL-----\n").getBytes(StandardCharsets.US_ASCII);

            // when
            EncodedCrl parsed = EncodedCrl.parse(pem);

            // then
            assertThat(listOf(parsed.entries())).containsExactlyInAnyOrderElementsOf(jdkEntries(pem));
            assertThat(parsed.isSignedBy(rsaKeyPair.getPublic())).isTrue();
        }

        @Test
        void ignoresTrailingBytesLikeJdk_whenTheyFollowTheCrl() throws Exception {
            // given
            byte[] der = crlWithEntries(rsaKeyPair, "SHA256WithRSAEncryption");
            byte[] withTrailingBytes = concat(der, new byte[]{0x0d, 0x0a, 0x00});

            // when
            EncodedCrl parsed = EncodedCrl.parse(withTrailingBytes);

            // then
            assertThat(listOf(parsed.entries())).containsExactlyInAnyOrderElementsOf(jdkEntries(withTrailingBytes));
            assertThat(parsed.isSignedBy(rsaKeyPair.getPublic())).isTrue();
        }

        @Test
        void readsCrlLikeJdk_whenOuterSequenceHasIndefiniteLength() throws Exception {
            // given
            byte[] der = crlWithEntries(rsaKeyPair, "SHA256WithRSAEncryption");
            byte[] indefiniteLength = withIndefiniteOuterLength(der);

            // when
            EncodedCrl parsed = EncodedCrl.parse(indefiniteLength);

            // then
            assertThat(listOf(parsed.entries())).containsExactlyInAnyOrderElementsOf(jdkEntries(indefiniteLength));
            assertThat(parsed.isSignedBy(rsaKeyPair.getPublic())).isTrue();
        }

        // ── Helpers ──────────────────────────────────────────────────────────

        private static byte[] concat(byte[] first, byte[] second) {
            byte[] joined = Arrays.copyOf(first, first.length + second.length);
            System.arraycopy(second, 0, joined, first.length, second.length);
            return joined;
        }
    }

    // ── Refusals ─────────────────────────────────────────────────────────────

    @Nested
    class Refusals {

        @Test
        void refusesCrl_whenItIsTruncated() throws Exception {
            // given
            byte[] der = crlWithEntries(rsaKeyPair, "SHA256WithRSAEncryption");
            byte[] truncated = Arrays.copyOf(der, der.length / 2);

            // when
            ThrowingCallable parse = () -> EncodedCrl.parse(truncated);

            // then
            assertThatThrownBy(parse).isInstanceOf(CRLException.class);
        }

        @Test
        void refusesCrl_whenItIsNoCrl() {
            // given
            byte[] notACrl = "certainly not a CRL".getBytes(StandardCharsets.US_ASCII);

            // when
            ThrowingCallable parse = () -> EncodedCrl.parse(notACrl);

            // then
            assertThatThrownBy(parse).isInstanceOf(CRLException.class);
        }

        @Test
        void refusesCrlLikeJdk_whenOuterSignatureAlgorithmDiffersFromSignedOne() throws Exception {
            // given
            byte[] der = crlWithEntries(rsaKeyPair, "SHA256WithRSAEncryption");
            byte[] mismatched = withOuterSignatureAlgorithm(der,
                    new AlgorithmIdentifier(PKCSObjectIdentifiers.sha384WithRSAEncryption));
            assertThatThrownBy(() -> jdkParse(mismatched)).as("JDK refuses it").isInstanceOf(CRLException.class);

            // when
            ThrowingCallable parse = () -> EncodedCrl.parse(mismatched);

            // then
            assertThatThrownBy(parse).isInstanceOf(CRLException.class);
        }

        @Test
        void refusesCrlLikeJdk_whenOuterSequenceCarriesAnExtraElement() throws Exception {
            // given
            byte[] der = crlWithEntries(rsaKeyPair, "SHA256WithRSAEncryption");
            byte[] withExtraElement = withExtraOuterElement(der);
            assertThatThrownBy(() -> jdkParse(withExtraElement)).as("JDK refuses it").isInstanceOf(CRLException.class);

            // when
            ThrowingCallable parse = () -> EncodedCrl.parse(withExtraElement);

            // then
            assertThatThrownBy(parse).isInstanceOf(CRLException.class);
        }

        @Test
        void refusesCrl_whenAnEntryIsMalformed() throws Exception {
            // given
            byte[] der = crlWithEntries(rsaKeyPair, "SHA256WithRSAEncryption");
            byte[] malformedEntry = withLastSerialNumberTag(der, (byte) 0x04);

            // when
            ThrowingCallable parse = () -> EncodedCrl.parse(malformedEntry);

            // then
            assertThatThrownBy(parse).isInstanceOf(CRLException.class);
        }

        @Test
        void refusesCrl_whenSignedListHasMoreFieldsThanACrlHas() throws Exception {
            // given
            byte[] der = crlWithEntries(rsaKeyPair, "SHA256WithRSAEncryption");
            byte[] extraSignedField = withExtraSignedListField(der);

            // when
            ThrowingCallable parse = () -> EncodedCrl.parse(extraSignedField);

            // then
            assertThatThrownBy(parse).isInstanceOf(CRLException.class).hasMessageContaining("more fields than a CRL");
        }

        @Test
        void refusesCrlWithReason_whenAnEntryIsLargerThanTheEntryLimit() throws Exception {
            // given
            ExtensionsGenerator oversizedEntryExtensions = new ExtensionsGenerator();
            oversizedEntryExtensions.addExtension(UNKNOWN_EXTENSION, false, new DEROctetString(new byte[70 * 1024]));
            byte[] crl = anX509Crl(ISSUER, rsaKeyPair.getPrivate())
                    .withRevocation(BigInteger.ONE, REVOKED_AT, oversizedEntryExtensions.generate())
                    .build()
                    .getEncoded();

            // when
            ThrowingCallable parse = () -> EncodedCrl.parse(crl);

            // then
            assertThatThrownBy(parse)
                    .isInstanceOfSatisfying(CrlRefusedException.class,
                            e -> assertThat(e.reason()).isEqualTo("one of its entries is larger than 64 KB"));
        }

        @Test
        void refusesCrlWithReason_whenItsPartBesidesTheEntriesIsLargerThanTheHeaderLimit() throws Exception {
            // given
            var oversizedExtensionValue = new DEROctetString(new byte[EncodedCrl.MAX_WHOLE_PARSE_SIZE]);
            byte[] crl = anX509Crl(ISSUER, rsaKeyPair.getPrivate())
                    .withExtension(UNKNOWN_EXTENSION, oversizedExtensionValue)
                    .build()
                    .getEncoded();

            // when
            ThrowingCallable parse = () -> EncodedCrl.parse(crl);

            // then
            assertThatThrownBy(parse)
                    .isInstanceOfSatisfying(CrlRefusedException.class,
                            e -> assertThat(e.reason()).isEqualTo("everything but its entries is larger than 1 MB"));
        }

        @Test
        void refusesCrlWithReason_whenItIsNotDerEncodedAndLargerThanTheWholeParseLimit() throws Exception {
            // given
            byte[] largeIndefiniteLength = withIndefiniteOuterLength(crlWithSerialNumbers(60_000));

            // when
            ThrowingCallable parse = () -> EncodedCrl.parse(largeIndefiniteLength);

            // then
            assertThat(largeIndefiniteLength.length).isGreaterThan(EncodedCrl.MAX_WHOLE_PARSE_SIZE);
            assertThatThrownBy(parse)
                    .isInstanceOfSatisfying(CrlRefusedException.class, e -> assertThat(e.reason())
                            .isEqualTo("it is not DER-encoded and larger than 1 MB, the most read whole"));
        }

        // ── Helpers ──────────────────────────────────────────────────────────

        private static byte[] withLastSerialNumberTag(byte[] der, byte tag) throws Exception {
            byte[] altered = der.clone();
            altered[lastSerialNumberTagOffset(der)] = tag;
            return altered;
        }

        private static byte[] withOuterSignatureAlgorithm(byte[] der, AlgorithmIdentifier signatureAlgorithm)
                throws Exception {
            ASN1Sequence crl = ASN1Sequence.getInstance(der);
            return new DERSequence(new ASN1Encodable[]{crl.getObjectAt(0), signatureAlgorithm, crl.getObjectAt(2)})
                    .getEncoded();
        }

        private static byte[] withExtraOuterElement(byte[] der) throws Exception {
            ASN1Sequence crl = ASN1Sequence.getInstance(der);
            return new DERSequence(new ASN1Encodable[]{
                    crl.getObjectAt(0),
                    crl.getObjectAt(1),
                    crl.getObjectAt(2),
                    new ASN1Enumerated(1)}).getEncoded();
        }

        private static byte[] withExtraSignedListField(byte[] der) throws Exception {
            ASN1Sequence crl = ASN1Sequence.getInstance(der);
            ASN1Sequence signedList = ASN1Sequence.getInstance(crl.getObjectAt(0));
            ASN1Encodable[] fields = Arrays.copyOf(signedList.toArray(), signedList.size() + 1);
            fields[signedList.size()] = DERNull.INSTANCE;
            return new DERSequence(new ASN1Encodable[]{new DERSequence(fields), crl.getObjectAt(1), crl.getObjectAt(2)})
                    .getEncoded();
        }

        private static byte[] crlWithSerialNumbers(int count) {
            var builder = anX509Crl(ISSUER, rsaKeyPair.getPrivate());
            for (int i = 0; i < count; i++) {
                builder.withRevocation(BigInteger.valueOf(1_000_000L + i), REVOKED_AT, null);
            }
            try {
                return builder.build().getEncoded();
            } catch (CRLException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    static Stream<Named<SignatureAlgorithm>> signatureAlgorithms() throws Exception {
        return Stream
                .of(named("RSA PKCS#1", new SignatureAlgorithm("SHA256WithRSAEncryption", keyPair("RSA", null))),
                        named("RSASSA-PSS", new SignatureAlgorithm("SHA256withRSAandMGF1", keyPair("RSA", null))),
                        named("ECDSA P-256",
                                new SignatureAlgorithm("SHA256withECDSA",
                                        keyPair("EC", new ECGenParameterSpec("secp256r1")))),
                        named("Ed25519", new SignatureAlgorithm("Ed25519", keyPair("Ed25519", null))),
                        named("ML-DSA-65", new SignatureAlgorithm("ML-DSA-65", keyPair("ML-DSA-65", null))));
    }

    static Stream<Integer> reasonCodes() {
        return Stream.of(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11);
    }

    private static byte[] crlWithEntries(KeyPair keyPair, String signatureAlgorithm) throws Exception {
        var builder = anX509Crl(ISSUER, keyPair.getPrivate()).withSignatureAlgorithm(signatureAlgorithm);
        for (int i = 0; i < ENTRY_COUNT; i++) {
            // an odd number shifted by whole bytes: unique, and from 1 to 17 bytes long
            BigInteger serialNumber = BigInteger.valueOf(2L * i + 1).shiftLeft(8 * (i % 16));
            if (i % 3 == 0) {
                builder.withRevocation(serialNumber, REVOKED_AT.plusSeconds(i), null);
            } else {
                builder.withRevocation(serialNumber, i % 11, REVOKED_AT.plusSeconds(i));
            }
        }
        return builder.build().getEncoded();
    }

    private static KeyPair keyPair(String algorithm, ECGenParameterSpec curve) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        if (curve != null) {
            generator.initialize(curve);
        } else if ("RSA".equals(algorithm)) {
            generator.initialize(2048);
        }
        return generator.generateKeyPair();
    }

    private static X509CRL jdkParse(byte[] crl) throws Exception {
        return (X509CRL) CertificateFactory.getInstance("X509").generateCRL(new ByteArrayInputStream(crl));
    }

    private static List<RevokedCertificate> jdkEntries(byte[] crl) throws Exception {
        Set<? extends X509CRLEntry> entries = jdkParse(crl).getRevokedCertificates();
        if (entries == null) {
            return List.of();
        }
        return entries
                .stream()
                .map(entry -> new RevokedCertificate(entry.getSerialNumber(), entry.getRevocationDate(),
                        entry.getRevocationReason()))
                .toList();
    }

    private static <T> List<T> listOf(Iterable<T> items) {
        List<T> list = new ArrayList<>();
        items.forEach(list::add);
        return list;
    }

    private static int lastSerialNumberTagOffset(byte[] der) throws Exception {
        ASN1Sequence crl = ASN1Sequence.getInstance(der);
        ASN1Sequence tbs = ASN1Sequence.getInstance(crl.getObjectAt(0));
        ASN1Sequence revoked = ASN1Sequence.getInstance(tbs.getObjectAt(5));
        byte[] lastEntry = revoked.getObjectAt(revoked.size() - 1).toASN1Primitive().getEncoded();
        int entryOffset = lastIndexOf(der, lastEntry);
        return entryOffset + 2;
    }

    private static int lastIndexOf(byte[] haystack, byte[] needle) {
        for (int i = haystack.length - needle.length; i >= 0; i--) {
            if (Arrays.equals(haystack, i, i + needle.length, needle, 0, needle.length)) {
                return i;
            }
        }
        throw new IllegalStateException("Entry not found in the CRL encoding");
    }

    private static byte[] withIndefiniteOuterLength(byte[] der) throws Exception {
        ASN1Sequence crl = ASN1Sequence.getInstance(der);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(new byte[]{0x30, (byte) 0x80});
        for (int i = 0; i < crl.size(); i++) {
            out.write(crl.getObjectAt(i).toASN1Primitive().getEncoded());
        }
        out.write(new byte[]{0x00, 0x00});
        return out.toByteArray();
    }

    record SignatureAlgorithm(String name, KeyPair keyPair) {
    }
}

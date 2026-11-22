package com.otilm.core.service.est.message;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.util.CertificateTestUtil;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.CryptographyUtil;
import com.otilm.core.util.EstCsrFixtures;
import com.otilm.core.util.PqcKeyFixtures;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;
import org.slf4j.LoggerFactory;

import static com.otilm.core.util.SignatureVerificationBoundsFixtures.compositeSignatureAlgorithm;
import static com.otilm.core.util.SignatureVerificationBoundsFixtures.pssSignatureAlgorithm;
import static com.otilm.core.util.SignatureVerificationBoundsFixtures.rsaPublicKeyInfo;
import static java.security.spec.RSAKeyGenParameterSpec.F4;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mockStatic;

class EstRequestDecoderTest {

    private static final String SUBJECT = "CN=device-1";
    private static final String ECDSA_SIGNATURE = "SHA256withECDSA";
    private static final String RSA_SIGNATURE = "SHA256withRSA";
    private static final String ML_DSA_SIGNATURE = "ML-DSA";
    private static final String SLH_DSA_SIGNATURE = "SLH-DSA";
    private static final String FALCON_SIGNATURE = "Falcon-512";
    private static final String HASH_ML_DSA_SIGNATURE = "HASH-ML-DSA";
    private static final String HASH_SLH_DSA_SIGNATURE = "HASH-SLH-DSA";
    private static final byte[] UNUSABLE_BYTES = {1, 2, 3};
    private static final String UNKNOWN_ALGORITHM_OID = "1.2.3.4";
    private static final ASN1ObjectIdentifier USER_PRINCIPAL_NAME = new ASN1ObjectIdentifier("1.3.6.1.4.1.311.20.2.3");

    private final Logger sanReader = (Logger) LoggerFactory.getLogger(CertificateUtil.class);
    private final ListAppender<ILoggingEvent> sanReaderLog = new ListAppender<>();
    private Level previousLevel;
    private boolean previousAdditive;

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** The logger is a process-wide singleton, so what is set on it here is taken off again after each test. */
    @BeforeEach
    void captureTheSanReaderLog() {
        previousLevel = sanReader.getLevel();
        previousAdditive = sanReader.isAdditive();
        sanReader.setLevel(Level.DEBUG);
        sanReader.setAdditive(false);
        sanReaderLog.start();
        sanReader.addAppender(sanReaderLog);
    }

    @AfterEach
    void releaseTheSanReaderLog() {
        sanReader.detachAppender(sanReaderLog);
        sanReaderLog.stop();
        sanReader.setLevel(previousLevel);
        sanReader.setAdditive(previousAdditive);
    }

    @Test
    void decodes_whenBodyIsBase64OfDerCsr() throws Exception {
        // given
        byte[] der = derCsr(SUBJECT);
        byte[] body = base64(der);

        // when
        Pkcs10CertificateRequest request = EstRequestDecoder.decode(body);

        // then
        assertThat(request.getEncoded()).isEqualTo(der);
        assertThat(request.getSubject()).isEqualTo(new X500Name(SUBJECT));
    }

    @Test
    void decodes_whenBase64IsWrappedInCrLfLinesWithTrailingNewline() throws Exception {
        // given
        byte[] der = derCsr(SUBJECT);
        byte[] body = base64Lines(der, "\r\n").getBytes(StandardCharsets.US_ASCII);

        // when
        Pkcs10CertificateRequest request = EstRequestDecoder.decode(body);

        // then
        assertThat(request.getEncoded()).isEqualTo(der);
    }

    @Test
    void decodes_whenBase64HoldsSpacesAndTabs() throws Exception {
        // given — a space and a tab after every ten characters, and a space and a tab at both ends
        byte[] der = derCsr(SUBJECT);
        String text = Base64.getEncoder().encodeToString(der);
        byte[] body = (" \t" + text.replaceAll("(.{10})", "$1 \t") + " \t").getBytes(StandardCharsets.US_ASCII);

        // when
        Pkcs10CertificateRequest request = EstRequestDecoder.decode(body);

        // then
        assertThat(request.getEncoded()).isEqualTo(der);
    }

    @Test
    void decodes_whenCsrCarriesChallengePassword() throws Exception {
        // given
        KeyPair keyPair = ecKeyPair();
        PKCS10CertificationRequestBuilder builder = requestFor(keyPair, SUBJECT)
                .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, new DERPrintableString("s3cr3t"));
        byte[] der = builder.build(signerOf(keyPair, ECDSA_SIGNATURE)).getEncoded();

        // when
        Pkcs10CertificateRequest request = EstRequestDecoder.decode(base64(der));

        // then
        assertThat(request.getEncoded()).isEqualTo(der);
        assertThat(request.getJcaObject().getAttributes(PKCSObjectIdentifiers.pkcs_9_at_challengePassword)).hasSize(1);
    }

    @Test
    void decodes_whenCsrWasAlteredAfterSigning() throws Exception {
        // given
        byte[] alteredAfterSigning = replaced(derCsr("CN=device-1"), "device-1", "device-2");

        // when
        Pkcs10CertificateRequest request = EstRequestDecoder.decode(base64(alteredAfterSigning));

        // then
        assertThat(request.getEncoded()).isEqualTo(alteredAfterSigning);
    }

    @Test
    void decodes_whenEverySubjectAlternativeNameCanBeRendered() throws Exception {
        // given
        GeneralName[] namesOfEveryReadableKind = namesOfEveryReadableKind();
        byte[] body = EstCsrFixtures.signedRequestBodyWithNames(SUBJECT, namesOfEveryReadableKind);

        // when
        Pkcs10CertificateRequest request = EstRequestDecoder.decode(body);

        // then
        assertThat(renderedNamesOf(request)).hasSize(namesOfEveryReadableKind.length);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource({
            "bodiesThatAreNotOneDerCsr",
            "requestsWhoseExtensionRequestCannotBeRead",
            "requestsWithANameThatCannotBeRendered"})
    void throwsBadRequest_whenBodyIsNotAnAcceptableRequest(byte[] body) {
        // given — a body that is not the base64 text of one DER request whose content the decoder accepts

        // when
        ThrowingCallable decode = () -> EstRequestDecoder.decode(body);

        // then
        assertThatThrownBy(decode)
                .isInstanceOfSatisfying(EstException.class,
                        thrown -> assertThat(thrown.error()).isEqualTo(EstError.BAD_REQUEST));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("requestsBeyondTheBounds")
    void throwsBadRequestWithoutBuildingAKey_whenKeyOrSignatureIsBeyondTheBounds(byte[] body) {
        // given — a request whose key or signature BouncyCastle could only build or verify at an unbounded cost

        try (MockedStatic<CryptographyUtil> cryptography = mockStatic(CryptographyUtil.class, CALLS_REAL_METHODS)) {
            // when
            ThrowingCallable decode = () -> EstRequestDecoder.decode(body);

            // then
            assertThatThrownBy(decode)
                    .isInstanceOfSatisfying(EstException.class,
                            thrown -> assertThat(thrown.error()).isEqualTo(EstError.BAD_REQUEST));
            cryptography.verifyNoInteractions();
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("requestsWithASupportedKeyAndSignature")
    void verifiesProofOfPossession_whenKeyAndSignatureAreSupported(byte[] body) {
        // given
        Pkcs10CertificateRequest request = EstRequestDecoder.decode(body);

        // when
        ThrowingCallable verify = () -> EstRequestDecoder.verifyProofOfPossession(request);

        // then
        assertThatCode(verify).doesNotThrowAnyException();
    }

    @Test
    void logsTheUnrenderedNameOnlyAtDebug_whenASubjectAlternativeNameCannotBeRendered() throws Exception {
        // given
        byte[] body = EstCsrFixtures.signedRequestBodyWithNames(SUBJECT, EstCsrFixtures.otherNameWithoutAValue());

        // when
        ThrowingCallable decode = () -> EstRequestDecoder.decode(body);

        // then
        assertThatThrownBy(decode).isInstanceOf(EstException.class);
        assertThat(sanReaderLog.list)
                .isNotEmpty()
                .allSatisfy(event -> assertThat(event.getLevel()).isEqualTo(Level.DEBUG));
    }

    @Test
    void throwsInvalidSignature_whenCsrWasAlteredAfterSigning() throws Exception {
        // given
        byte[] alteredAfterSigning = replaced(derCsr("CN=device-1"), "device-1", "device-2");
        Pkcs10CertificateRequest request = EstRequestDecoder.decode(base64(alteredAfterSigning));

        // when
        ThrowingCallable verify = () -> EstRequestDecoder.verifyProofOfPossession(request);

        // then
        assertThatThrownBy(verify)
                .isInstanceOfSatisfying(EstException.class,
                        thrown -> assertThat(thrown.error()).isEqualTo(EstError.INVALID_SIGNATURE));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("requestsWhoseSignatureCannotBeChecked")
    void throwsInvalidSignature_whenSignatureCannotBeChecked(byte[] body) {
        // given — a well-formed request whose signature cannot be checked with the key it carries
        Pkcs10CertificateRequest request = EstRequestDecoder.decode(body);

        // when
        ThrowingCallable verify = () -> EstRequestDecoder.verifyProofOfPossession(request);

        // then
        assertThatThrownBy(verify)
                .isInstanceOfSatisfying(EstException.class,
                        thrown -> assertThat(thrown.error()).isEqualTo(EstError.INVALID_SIGNATURE));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    static Stream<Named<byte[]>> bodiesThatAreNotOneDerCsr() throws Exception {
        byte[] der = derCsr(SUBJECT);
        // six question marks encode to a slash in base64, which the URL-safe alphabet writes as an underscore
        byte[] derWithSlashInBase64 = derCsr("CN=??????");
        // six greater-than signs encode to a plus in base64, which the URL-safe alphabet writes as a hyphen
        String base64WithPlus = Base64.getEncoder().encodeToString(derCsr("CN=>>>>>>"));
        byte[] certificate = CertificateTestUtil.createCACertificate().getEncoded();
        String pemArmour = "-----BEGIN CERTIFICATE REQUEST-----\n" + base64Lines(der, "\n")
                + "-----END CERTIFICATE REQUEST-----\n";
        return Stream
                .of(named("empty body", new byte[0]),
                        named("only blanks", " \r\n\t".getBytes(StandardCharsets.US_ASCII)),
                        named("raw DER instead of base64", der),
                        named("URL-safe alphabet", Base64.getUrlEncoder().encode(derWithSlashInBase64)),
                        named("a URL-safe hyphen for a plus",
                                base64WithPlus.replace('+', '-').getBytes(StandardCharsets.US_ASCII)),
                        named("PEM armour", pemArmour.getBytes(StandardCharsets.US_ASCII)),
                        named("a byte after the request", base64(concatenated(der, new byte[]{0}))),
                        named("a second request after the first", base64(concatenated(der, der))),
                        named("request cut short", base64(Arrays.copyOf(der, der.length / 2))),
                        named("BER with indefinite length", base64(withIndefiniteLength(der))),
                        named("a certificate", base64(certificate)));
    }

    static Stream<Named<byte[]>> requestsWhoseExtensionRequestCannotBeRead() throws Exception {
        KeyPair keyPair = ecKeyPair();
        ContentSigner signer = signerOf(keyPair, ECDSA_SIGNATURE);
        byte[] notASequenceOfExtensions = requestFor(keyPair, SUBJECT)
                .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new ASN1Integer(1))
                .build(signer)
                .getEncoded();
        byte[] withoutAValue = requestFor(keyPair, SUBJECT)
                .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new ASN1Encodable[0])
                .build(signer)
                .getEncoded();
        return Stream
                .of(named("extension request that is not a sequence of extensions", base64(notASequenceOfExtensions)),
                        named("extension request without a value", base64(withoutAValue)));
    }

    static Stream<Named<byte[]>> requestsWithANameThatCannotBeRendered() throws Exception {
        GeneralName otherNameWithoutAValue = EstCsrFixtures.otherNameWithoutAValue();
        GeneralName otherNameWithAnUntaggedValue = new GeneralName(GeneralName.otherName,
                new DERSequence(new ASN1Encodable[]{USER_PRINCIPAL_NAME, new DERUTF8String("device-1@example.com")}));
        GeneralName dnsName = new GeneralName(GeneralName.dNSName, "device-1.example");
        return Stream
                .of(named("an otherName that holds only its type",
                        EstCsrFixtures.signedRequestBodyWithNames(SUBJECT, otherNameWithoutAValue)),
                        named("an otherName whose value is not tagged",
                                EstCsrFixtures.signedRequestBodyWithNames(SUBJECT, otherNameWithAnUntaggedValue)),
                        named("a DNS name beside an otherName that holds only its type",
                                EstCsrFixtures.signedRequestBodyWithNames(SUBJECT, dnsName, otherNameWithoutAValue)));
    }

    static Stream<Named<byte[]>> requestsBeyondTheBounds() throws Exception {
        SubjectPublicKeyInfo rsaKeyOf16384Bits = rsaPublicKeyInfo(PKCSObjectIdentifiers.rsaEncryption, 16384, F4);
        AlgorithmIdentifier curveWithoutParameters = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,
                DERNull.INSTANCE);
        AlgorithmIdentifier unknownAlgorithm = new AlgorithmIdentifier(new ASN1ObjectIdentifier(UNKNOWN_ALGORITHM_OID));
        AlgorithmIdentifier ecdsaWithParameters = new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256,
                new DERSequence(new ASN1Integer(1)));
        CertificationRequest signedWithEc = signedWithEcKey();
        return Stream
                .of(named("a key of an algorithm that nobody knows",
                        EstCsrFixtures
                                .requestBodyWithPublicKey(new SubjectPublicKeyInfo(unknownAlgorithm, UNUSABLE_BYTES))),
                        named("an RSA modulus of 16384 bits",
                                EstCsrFixtures.requestBodyWithPublicKey(rsaKeyOf16384Bits)),
                        named("an EC key whose curve is not named",
                                EstCsrFixtures
                                        .requestBodyWithPublicKey(
                                                new SubjectPublicKeyInfo(curveWithoutParameters, UNUSABLE_BYTES))),
                        named("an RSASSA-PSS signature with a salt of 1025 bytes, one over the bound",
                                withSignatureAlgorithm(signedWithRsaKey(),
                                        pssSignatureAlgorithm(BigInteger.valueOf(1025)))),
                        named("a generic composite signature that lists the ECDSA algorithm 1000 times",
                                withSignatureAlgorithm(signedWithEc,
                                        compositeSignatureAlgorithm(
                                                new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256), 1000))),
                        named("an alternative public key beyond the bounds",
                                requestCarryingAlternativeKey(rsaKeyOf16384Bits)),
                        named("an ECDSA signature with parameters other than NULL",
                                withSignatureAlgorithm(signedWithEc, ecdsaWithParameters)));
    }

    static Stream<Named<byte[]>> requestsWithASupportedKeyAndSignature() throws Exception {
        KeyPair preHashMlDsa = CertificateGeneratorHelper
                .generateKeyPair(KeyAlgorithm.MLDSA, MLDSAParameterSpec.ml_dsa_44_with_sha512);
        KeyPair preHashSlhDsa = CertificateGeneratorHelper
                .generateKeyPair(KeyAlgorithm.SLHDSA, SLHDSAParameterSpec.slh_dsa_sha2_128f_with_sha256);
        return Stream
                .of(named("an RSA key of 2048 bits", base64(derCsr(rsaKeyPair(2048), RSA_SIGNATURE))),
                        named("an RSASSA-PSS signature with a salt of 32 bytes", pssSignedRequest(32)),
                        named("an RSASSA-PSS signature with the longest salt that a 2048-bit key allows, 222 bytes",
                                pssSignedRequest(222)),
                        named("an EC key on a named curve", base64(derCsr(SUBJECT))),
                        named("an Ed25519 key", base64(derCsr(edKeyPair("Ed25519"), "Ed25519"))),
                        named("an Ed448 key", base64(derCsr(edKeyPair("Ed448"), "Ed448"))),
                        named("an ML-DSA key", base64(derCsr(PqcKeyFixtures.keyPair(), ML_DSA_SIGNATURE))),
                        named("an ML-DSA-44 key that signs a SHA-512 digest",
                                base64(derCsr(preHashMlDsa, HASH_ML_DSA_SIGNATURE))),
                        named("an SLH-DSA key", base64(derCsr(slhDsaKeyPair(), SLH_DSA_SIGNATURE))),
                        named("an SLH-DSA-SHA2-128f key that signs a SHA-256 digest",
                                base64(derCsr(preHashSlhDsa, HASH_SLH_DSA_SIGNATURE))),
                        named("a Falcon key", base64(derCsr(falconKeyPair(), FALCON_SIGNATURE))));
    }

    /** One name of each kind that a client may ask for, each in a form that Core renders. */
    private static GeneralName[] namesOfEveryReadableKind() {
        DERTaggedObject principalName = new DERTaggedObject(true, 0, new DERUTF8String("device-1@example.com"));
        DERTaggedObject partyName = new DERTaggedObject(true, 1, new DERUTF8String("device-1"));
        return new GeneralName[]{
                new GeneralName(GeneralName.dNSName, "device-1.example"),
                new GeneralName(GeneralName.iPAddress, "192.168.1.1"),
                new GeneralName(GeneralName.iPAddress, "2001:db8::1"),
                new GeneralName(GeneralName.rfc822Name, "device-1@example.com"),
                new GeneralName(GeneralName.uniformResourceIdentifier, "https://device-1.example"),
                new GeneralName(new X500Name("CN=device-1,O=Acme")),
                new GeneralName(GeneralName.registeredID, "1.2.3.4.5"),
                new GeneralName(GeneralName.otherName,
                        new DERSequence(new ASN1Encodable[]{USER_PRINCIPAL_NAME, principalName})),
                new GeneralName(GeneralName.ediPartyName, new DERSequence(partyName))};
    }

    private static List<String> renderedNamesOf(Pkcs10CertificateRequest request) {
        return CertificateUtil.getSAN(request).values().stream().flatMap(List::stream).toList();
    }

    static Stream<Named<byte[]>> requestsWhoseSignatureCannotBeChecked() throws Exception {
        KeyPair keyPair = ecKeyPair();
        ContentSigner signer = signerOf(keyPair, ECDSA_SIGNATURE);
        CertificationRequest signed = requestFor(keyPair, SUBJECT).build(signer).toASN1Structure();
        AlgorithmIdentifier unknownAlgorithm = new AlgorithmIdentifier(new ASN1ObjectIdentifier(UNKNOWN_ALGORITHM_OID));
        AlgorithmIdentifier ecPublicKeyAlgorithm = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,
                SECObjectIdentifiers.secp256r1);
        AlgorithmIdentifier rsaPublicKeyAlgorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption,
                DERNull.INSTANCE);

        CertificationRequest malformedSignature = new CertificationRequest(signed.getCertificationRequestInfo(),
                signed.getSignatureAlgorithm(), new DERBitString(UNUSABLE_BYTES));
        CertificationRequest unknownSignatureAlgorithm = new CertificationRequest(signed.getCertificationRequestInfo(),
                unknownAlgorithm, signed.getSignature());
        CertificationRequest malformedKey = signedWithPublicKey(
                new SubjectPublicKeyInfo(ecPublicKeyAlgorithm, UNUSABLE_BYTES), signer);
        CertificationRequest rsaKeyThatIsNoEncoding = signedWithPublicKey(
                new SubjectPublicKeyInfo(rsaPublicKeyAlgorithm, UNUSABLE_BYTES), signer);
        CertificationRequest rsaKeyOfNoNumbers = signedWithPublicKey(
                new SubjectPublicKeyInfo(rsaPublicKeyAlgorithm, new ASN1Integer(1)), signer);
        CertificationRequest rsaKeyOfPartialBytes = signedWithPublicKey(
                new SubjectPublicKeyInfo(rsaPublicKeyAlgorithm, new DERBitString(new byte[]{1, 2, 4}, 2)), signer);
        return Stream
                .of(named("malformed signature value", base64(derOf(malformedSignature))),
                        named("unknown signature algorithm", base64(derOf(unknownSignatureAlgorithm))),
                        named("malformed public key", base64(derOf(malformedKey))),
                        named("RSA public key that is no ASN.1 encoding", base64(derOf(rsaKeyThatIsNoEncoding))),
                        named("RSA public key that is no sequence of two numbers", base64(derOf(rsaKeyOfNoNumbers))),
                        named("RSA public key whose bit string is not a whole number of bytes",
                                base64(derOf(rsaKeyOfPartialBytes))));
    }

    private static KeyPair ecKeyPair() throws Exception {
        return CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.ECDSA, new ECGenParameterSpec("secp256r1"));
    }

    private static CertificationRequest signedWithRsaKey() throws Exception {
        KeyPair keyPair = rsaKeyPair(2048);
        return requestFor(keyPair, SUBJECT).build(signerOf(keyPair, RSA_SIGNATURE)).toASN1Structure();
    }

    private static CertificationRequest signedWithEcKey() throws Exception {
        KeyPair keyPair = ecKeyPair();
        return requestFor(keyPair, SUBJECT).build(signerOf(keyPair, ECDSA_SIGNATURE)).toASN1Structure();
    }

    /** The request with another signature algorithm, which keeps the signature value that it had. */
    private static byte[] withSignatureAlgorithm(CertificationRequest signed, AlgorithmIdentifier signatureAlgorithm)
            throws IOException {
        return base64(derOf(new CertificationRequest(signed.getCertificationRequestInfo(), signatureAlgorithm,
                signed.getSignature())));
    }

    /** A request for an RSA key of 2048 bits, signed with RSASSA-PSS over SHA-256 and the salt length as given. */
    private static byte[] pssSignedRequest(int saltLength) throws Exception {
        KeyPair keyPair = rsaKeyPair(2048);
        PSSParameterSpec parameters = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, saltLength,
                PSSParameterSpec.TRAILER_FIELD_BC);
        ContentSigner signer = new JcaContentSignerBuilder("RSASSA-PSS", parameters)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());
        return base64(requestFor(keyPair, SUBJECT).build(signer).getEncoded());
    }

    private static KeyPair edKeyPair(String algorithm) throws Exception {
        return KeyPairGenerator.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME).generateKeyPair();
    }

    private static KeyPair falconKeyPair() throws Exception {
        return CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.FALCON, FalconParameterSpec.falcon_512);
    }

    private static KeyPair slhDsaKeyPair() throws Exception {
        return CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.SLHDSA, SLHDSAParameterSpec.slh_dsa_sha2_128f);
    }

    /**
     * A request whose own key is supported and that carries the alternative public key with the alternative signature
     * attributes that go with it, signed with unrelated keys.
     */
    private static byte[] requestCarryingAlternativeKey(SubjectPublicKeyInfo alternativePublicKey) throws Exception {
        KeyPair keyPair = ecKeyPair();
        ContentSigner signer = signerOf(keyPair, ECDSA_SIGNATURE);
        return base64(requestFor(keyPair, SUBJECT).build(signer, alternativePublicKey, signer).getEncoded());
    }

    private static KeyPair rsaKeyPair(int bits) throws Exception {
        return CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, new RSAKeyGenParameterSpec(bits, F4));
    }

    private static ContentSigner signerOf(KeyPair keyPair, String signatureAlgorithm) throws Exception {
        return new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());
    }

    private static JcaPKCS10CertificationRequestBuilder requestFor(KeyPair keyPair, String subject) {
        return new JcaPKCS10CertificationRequestBuilder(new X500Name(subject), keyPair.getPublic());
    }

    private static byte[] derCsr(String subject) throws Exception {
        KeyPair keyPair = ecKeyPair();
        return requestFor(keyPair, subject).build(signerOf(keyPair, ECDSA_SIGNATURE)).getEncoded();
    }

    private static byte[] derCsr(KeyPair keyPair, String signatureAlgorithm) throws Exception {
        return requestFor(keyPair, SUBJECT).build(signerOf(keyPair, signatureAlgorithm)).getEncoded();
    }

    private static CertificationRequest signedWithPublicKey(SubjectPublicKeyInfo publicKey, ContentSigner signer) {
        return new PKCS10CertificationRequestBuilder(new X500Name(SUBJECT), publicKey).build(signer).toASN1Structure();
    }

    private static byte[] derOf(CertificationRequest request) throws IOException {
        return request.getEncoded(ASN1Encoding.DER);
    }

    private static byte[] base64(byte[] der) {
        return Base64.getEncoder().encode(der);
    }

    /** Base64 in lines of 64 characters, each followed by the line end, the last one included. */
    private static String base64Lines(byte[] der, String lineEnd) {
        byte[] separator = lineEnd.getBytes(StandardCharsets.US_ASCII);
        return Base64.getMimeEncoder(64, separator).encodeToString(der) + lineEnd;
    }

    /** The same elements under an outer SEQUENCE of indefinite length, which BER allows and DER does not. */
    private static byte[] withIndefiniteLength(byte[] der) throws IOException {
        return new BERSequence(ASN1Sequence.getInstance(der).toArray()).getEncoded();
    }

    private static byte[] concatenated(byte[] first, byte[] second) {
        byte[] both = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, both, first.length, second.length);
        return both;
    }

    /** Replaces text of the same length, so the DER stays well-formed. */
    private static byte[] replaced(byte[] der, String original, String replacement) {
        byte[] altered = der.clone();
        int offset = new String(der, StandardCharsets.ISO_8859_1).indexOf(original);
        System.arraycopy(replacement.getBytes(StandardCharsets.ISO_8859_1), 0, altered, offset, replacement.length());
        return altered;
    }
}

package com.otilm.core.certificate.type;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.certificate.CertificateFormat;
import com.otilm.api.model.core.certificate.CertificateFormatEncoding;
import com.otilm.api.model.core.certificate.CertificateOperation;
import com.otilm.api.model.core.certificate.CertificateTypeDetailsDto;
import com.otilm.api.model.core.certificate.X509CertificateTypeDetailsDto;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.core.certificate.type.stub.StubCertificateTypeHandler;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.helpers.CertificateGeneratorHelper.CertificateChainInfo;
import com.otilm.core.util.CertificateUtil;
import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessageBuilder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static com.otilm.core.certificate.type.stub.StubCertificateFixtures.certificate;
import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;

class X509CertificateTypeHandlerTest {

    private static final String ISSUER_DN = "CN=Handler Test CA";
    private static final String SUBJECT_DN = "CN=handler-test-holder";

    private static CertificateChainInfo chain;
    private static KeyPair otherCaKeys;

    private final X509CertificateTypeHandler handler = new X509CertificateTypeHandler();

    @BeforeAll
    static void generateChain() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        chain = CertificateGeneratorHelper.generateCertificateWithIssuer(KeyAlgorithm.RSA, ISSUER_DN, SUBJECT_DN, null);
        otherCaKeys = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
    }

    @Test
    void declaresTypeCodeAndTheFullOperationSet() {
        // given — the X.509 handler as registered

        // when
        String typeCode = handler.typeCode();

        // then
        assertThat(typeCode).isEqualTo("X.509");
        assertThat(handler.supportedOperations()).containsExactlyInAnyOrder(CertificateOperation.values());
    }

    @Test
    void readsTheCommonProperties_whenParsingADerCertificate() throws Exception {
        // given
        X509Certificate leaf = chain.getEndEntityCertificate();

        // when
        ParsedCertificate parsed = handler.parseCertificate(leaf.getEncoded()).orElseThrow();

        // then
        CertificateProperties properties = parsed.properties();
        assertThat(parsed.typeCode()).isEqualTo("X.509");
        assertThat(properties.identifier()).isEqualTo(leaf.getSerialNumber().toString(16));
        assertThat(properties.holder()).isEqualTo(leaf.getSubjectX500Principal().getName());
        assertThat(properties.issuerReference()).isEqualTo(leaf.getIssuerX500Principal().getName());
        assertThat(properties.publicKey()).isEqualTo(leaf.getPublicKey());
        assertThat(properties.fingerprint()).isEqualTo(CertificateUtil.getThumbprint(leaf.getEncoded()));
    }

    @Test
    void reportsValidityDownToTheSecond_whenParsingACertificate() throws Exception {
        // given
        X509Certificate leaf = chain.getEndEntityCertificate();

        // when
        ParsedCertificate parsed = handler.parseCertificate(leaf.getEncoded()).orElseThrow();

        // then
        Validity validity = parsed.properties().validity();
        assertThat(validity.precision()).isEqualTo(ValidityPrecision.DATE_TIME);
        assertThat(validity.notBefore()).isEqualTo(leaf.getNotBefore().toInstant());
        assertThat(validity.notAfter()).isEqualTo(leaf.getNotAfter().toInstant());
    }

    @Test
    void reportsValid_whenTheCertificateIsWithinItsValidityPeriod() throws Exception {
        // given
        X509Certificate leaf = chain.getEndEntityCertificate();
        ParsedCertificate parsed = handler.parseCertificate(leaf.getEncoded()).orElseThrow();
        Instant duringValidity = leaf.getNotBefore().toInstant().plusSeconds(60);

        // when
        ValidityStatus status = parsed.properties().statusAt(duringValidity);

        // then
        assertThat(status).isEqualTo(ValidityStatus.VALID);
    }

    @Test
    void reportsExpired_whenTheMomentIsAfterTheEndOfTheCertificate() throws Exception {
        // given
        X509Certificate leaf = chain.getEndEntityCertificate();
        ParsedCertificate parsed = handler.parseCertificate(leaf.getEncoded()).orElseThrow();
        Instant afterExpiry = leaf.getNotAfter().toInstant().plusSeconds(60);

        // when
        ValidityStatus status = parsed.properties().statusAt(afterExpiry);

        // then
        assertThat(status).isEqualTo(ValidityStatus.EXPIRED);
    }

    @Test
    void readsTheSameCertificate_whenTheContentIsPemEncoded() throws Exception {
        // given
        X509Certificate leaf = chain.getEndEntityCertificate();
        byte[] pem = toPem(leaf);

        // when
        ParsedCertificate parsed = handler.parseCertificate(pem).orElseThrow();

        // then
        assertThat(parsed.encoded()).isEqualTo(leaf.getEncoded());
    }

    @Test
    void returnsEmpty_whenTheContentIsNotACertificate() {
        // given
        byte[] notACertificate = "not a certificate".getBytes(StandardCharsets.UTF_8);

        // when
        Optional<ParsedCertificate> parsed = handler.parseCertificate(notACertificate);

        // then
        assertThat(parsed).isEmpty();
    }

    @Test
    void returnsEmpty_whenTheContentIsACertificateOfAnotherType() {
        // given
        byte[] stubCertificate = certificate("42", "holder-one");

        // when
        Optional<ParsedCertificate> parsed = handler.parseCertificate(stubCertificate);

        // then
        assertThat(parsed).isEmpty();
    }

    @Test
    void readsHolderAndKey_whenParsingAPkcs10Request() throws Exception {
        // given
        KeyPair holderKeys = chain.getEndEntityCertificateKeyPair();
        byte[] csr = pkcs10(holderKeys, SUBJECT_DN);

        // when
        ParsedRequest parsed = handler.parseRequest(csr).orElseThrow();

        // then
        assertThat(parsed.format()).isEqualTo(CertificateRequestFormat.PKCS10);
        assertThat(parsed.holder()).isEqualTo(SUBJECT_DN);
        assertThat(parsed.publicKey()).isEqualTo(holderKeys.getPublic());
    }

    @Test
    void readsTheRequest_whenItIsPemEncoded() throws Exception {
        // given
        byte[] csr = pkcs10(chain.getEndEntityCertificateKeyPair(), SUBJECT_DN);
        String pem = "-----BEGIN CERTIFICATE REQUEST-----\n" + Base64.getMimeEncoder().encodeToString(csr)
                + "\n-----END CERTIFICATE REQUEST-----\n";

        // when
        ParsedRequest parsed = handler.parseRequest(pem.getBytes(StandardCharsets.UTF_8)).orElseThrow();

        // then
        assertThat(parsed.encoded()).isEqualTo(csr);
    }

    @Test
    void readsHolderAndKey_whenParsingACrmfRequest() throws Exception {
        // given
        KeyPair holderKeys = chain.getEndEntityCertificateKeyPair();
        byte[] crmf = crmf(holderKeys, SUBJECT_DN, true);

        // when
        ParsedRequest parsed = handler.parseRequest(crmf).orElseThrow();

        // then
        assertThat(parsed.format()).isEqualTo(CertificateRequestFormat.CRMF);
        assertThat(parsed.publicKey()).isEqualTo(holderKeys.getPublic());
    }

    @Test
    void returnsEmpty_whenTheContentIsNotARequest() throws Exception {
        // given
        byte[] certificateDer = chain.getEndEntityCertificate().getEncoded();

        // when
        Optional<ParsedRequest> parsed = handler.parseRequest(certificateDer);

        // then
        assertThat(parsed).isEmpty();
    }

    @Test
    void acceptsTheSignature_whenTheIssuerSignedTheCertificate() throws Exception {
        // given
        ParsedCertificate leaf = parsedCertificate(chain.getEndEntityCertificate());
        ParsedCertificate issuer = parsedCertificate(chain.getCaCertificate());

        // when
        boolean valid = handler.verifySignature(leaf, issuer);

        // then
        assertThat(valid).isTrue();
    }

    @Test
    void rejectsTheSignature_whenAnotherCertificateIsGivenAsTheIssuer() throws Exception {
        // given
        ParsedCertificate leaf = parsedCertificate(chain.getEndEntityCertificate());
        X509Certificate otherCa = CertificateGeneratorHelper.generateCACertificate(otherCaKeys, "CN=Other CA");

        // when
        boolean valid = handler.verifySignature(leaf, parsedCertificate(otherCa));

        // then
        assertThat(valid).isFalse();
    }

    @Test
    void checksTheOwnKey_whenNoIssuerIsGiven() throws Exception {
        // given
        ParsedCertificate selfSigned = parsedCertificate(chain.getCaCertificate());

        // when
        boolean valid = handler.verifySignature(selfSigned, null);

        // then
        assertThat(valid).isTrue();
    }

    @Test
    void recognisesTheIssuer_whenTheCertificateWasIssuedByIt() throws Exception {
        // given
        ParsedCertificate leaf = parsedCertificate(chain.getEndEntityCertificate());
        ParsedCertificate issuer = parsedCertificate(chain.getCaCertificate());

        // when
        boolean issuedBy = handler.isIssuedBy(leaf, issuer);

        // then
        assertThat(issuedBy).isTrue();
    }

    @Test
    void doesNotRecogniseTheIssuer_whenTheCertificateWasIssuedByAnother() throws Exception {
        // given
        ParsedCertificate leaf = parsedCertificate(chain.getEndEntityCertificate());
        X509Certificate otherCa = CertificateGeneratorHelper.generateCACertificate(otherCaKeys, "CN=Other CA");

        // when
        boolean issuedBy = handler.isIssuedBy(leaf, parsedCertificate(otherCa));

        // then
        assertThat(issuedBy).isFalse();
    }

    @Test
    void acceptsTheRequest_whenThePkcs10SignatureIsValid() throws Exception {
        // given
        ParsedRequest request = handler
                .parseRequest(pkcs10(chain.getEndEntityCertificateKeyPair(), SUBJECT_DN))
                .orElseThrow();

        // when
        boolean valid = handler.verifySignature(request, null);

        // then
        assertThat(valid).isTrue();
    }

    @Test
    void rejectsTheRequest_whenThePkcs10IsSignedWithAnotherKey() throws Exception {
        // given
        byte[] csr = pkcs10Signed(chain.getEndEntityCertificateKeyPair().getPublic(), otherCaKeys, SUBJECT_DN);
        ParsedRequest request = handler.parseRequest(csr).orElseThrow();

        // when
        boolean valid = handler.verifySignature(request, null);

        // then
        assertThat(valid).isFalse();
    }

    @Test
    void acceptsTheRequest_whenTheCrmfProofOfPossessionIsValid() throws Exception {
        // given
        ParsedRequest request = handler
                .parseRequest(crmf(chain.getEndEntityCertificateKeyPair(), SUBJECT_DN, true))
                .orElseThrow();

        // when
        boolean valid = handler.verifySignature(request, null);

        // then
        assertThat(valid).isTrue();
    }

    @Test
    void rejectsTheRequest_whenTheCrmfHasNoProofOfPossession() throws Exception {
        // given
        ParsedRequest request = handler
                .parseRequest(crmf(chain.getEndEntityCertificateKeyPair(), SUBJECT_DN, false))
                .orElseThrow();

        // when
        boolean valid = handler.verifySignature(request, null);

        // then
        assertThat(valid).isFalse();
    }

    @Test
    void returnsTheDerContent_whenEncodingRawDer() throws Exception {
        // given
        ParsedCertificate leaf = parsedCertificate(chain.getEndEntityCertificate());

        // when
        byte[] encoded = handler.encode(leaf, CertificateFormat.RAW, CertificateFormatEncoding.DER);

        // then
        assertThat(encoded).isEqualTo(chain.getEndEntityCertificate().getEncoded());
    }

    @Test
    void returnsPemThatReadsBackAsTheSameCertificate_whenEncodingRawPem() throws Exception {
        // given
        ParsedCertificate leaf = parsedCertificate(chain.getEndEntityCertificate());

        // when
        byte[] encoded = handler.encode(leaf, CertificateFormat.RAW, CertificateFormatEncoding.PEM);

        // then
        assertThat(new String(encoded, StandardCharsets.UTF_8)).startsWith("-----BEGIN CERTIFICATE-----");
        assertThat(handler.parseCertificate(encoded).orElseThrow().encoded())
                .isEqualTo(chain.getEndEntityCertificate().getEncoded());
    }

    @Test
    void returnsSignedDataCarryingTheCertificate_whenEncodingPkcs7() throws Exception {
        // given
        ParsedCertificate leaf = parsedCertificate(chain.getEndEntityCertificate());

        // when
        byte[] encoded = handler.encode(leaf, CertificateFormat.PKCS7, CertificateFormatEncoding.DER);

        // then
        assertThat(new CMSSignedData(encoded).getCertificates().getMatches(null)).hasSize(1);
    }

    @Test
    void describesTheX509Details_whenTheCertificateIsX509() {
        // given
        X509CertificateEntity certificate = aCertificate()
                .withCommonName("details.example.com")
                .withSubjectDn("CN=details.example.com")
                .build();

        // when
        Optional<CertificateTypeDetailsDto> details = handler.describeDetails(certificate);

        // then
        assertThat(details.orElseThrow()).isInstanceOfSatisfying(X509CertificateTypeDetailsDto.class, x509Details -> {
            assertThat(x509Details.getCommonName()).isEqualTo("details.example.com");
            assertThat(x509Details.getSubjectDn()).isEqualTo("CN=details.example.com");
        });
    }

    @Test
    void picksTheX509Handler_whenDetectingAmongSeveralTypes() throws Exception {
        // given
        var registry = new CertificateTypeHandlerRegistry(List.of(new StubCertificateTypeHandler(), handler));

        // when
        var detected = registry.detectCertificate(chain.getEndEntityCertificate().getEncoded());

        // then
        assertThat(detected).isPresent();
        assertThat(detected.get().handler()).isSameAs(handler);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private ParsedCertificate parsedCertificate(X509Certificate certificate) throws Exception {
        return handler.parseCertificate(certificate.getEncoded()).orElseThrow();
    }

    private static byte[] toPem(X509Certificate certificate) throws Exception {
        var out = new ByteArrayOutputStream();
        try (var writer = new JcaPEMWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8))) {
            writer.writeObject(certificate);
        }
        return out.toByteArray();
    }

    private static byte[] pkcs10(KeyPair keys, String subjectDn) throws Exception {
        return pkcs10Signed(keys.getPublic(), keys, subjectDn);
    }

    private static byte[] pkcs10Signed(PublicKey certifiedKey, KeyPair signingKeys, String subjectDn) throws Exception {
        return new JcaPKCS10CertificationRequestBuilder(new X500Name(subjectDn), certifiedKey)
                .build(new JcaContentSignerBuilder("SHA256WithRSA").build(signingKeys.getPrivate()))
                .getEncoded();
    }

    private static byte[] crmf(KeyPair keys, String subjectDn, boolean withProofOfPossession) throws Exception {
        CertificateRequestMessageBuilder builder = new JcaCertificateRequestMessageBuilder(BigInteger.ONE)
                .setPublicKey(keys.getPublic())
                .setSubject(new X500Name(subjectDn));
        if (withProofOfPossession) {
            builder
                    .setProofOfPossessionSigningKeySigner(
                            new JcaContentSignerBuilder("SHA256WithRSA").build(keys.getPrivate()));
        }
        return new CertReqMessages(builder.build().toASN1Structure()).getEncoded();
    }
}

package com.otilm.core.certificate.type;

import com.otilm.api.exception.CertificateRequestException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.attribute.ResponseAttributeV3;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.certificate.CertificateFormat;
import com.otilm.api.model.core.certificate.CertificateFormatEncoding;
import com.otilm.api.model.core.certificate.CertificateOperation;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.X509CertificateDetail;
import com.otilm.api.model.core.certificate.X509CertificateRequestDetail;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.certificate.type.stub.StubCertificateTypeHandler;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.helpers.CertificateGeneratorHelper.CertificateChainInfo;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import com.otilm.core.service.CryptographicOperationInternalService;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.X509ObjectToString;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessageBuilder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.StubCertificateFixtures.certificate;
import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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

    // the name style that stamping an issued certificate uses reads the OID caches when its class loads
    @BeforeAll
    static void cacheOidCategories() {
        for (OidCategory category : OidCategory.values()) {
            if (OidHandler.getOidCache(category) == null) {
                OidHandler.cacheOidCategory(category, new HashMap<>());
            }
        }
    }

    @Test
    void declaresTheX509TypeCode() {
        // given — the X.509 handler as registered

        // when
        String typeCode = handler.typeCode();

        // then
        assertThat(typeCode).isEqualTo("X.509");
    }

    @Test
    void declaresTheFullOperationSet() {
        // given — the X.509 handler as registered

        // when
        Set<CertificateOperation> operations = handler.supportedOperations();

        // then
        assertThat(operations).containsExactlyInAnyOrder(CertificateOperation.values());
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
    void returnsEmpty_whenTheFirstPemObjectAfterLeadingTextIsAPrivateKey() throws Exception {
        // given — a bundle as `openssl pkcs12 -nodes` writes it: attributes, then the key, then the certificate
        String bundle = """
                Bag Attributes
                    friendlyName: holder
                -----BEGIN PRIVATE KEY-----
                AAAA
                -----END PRIVATE KEY-----
                """ + new String(toPem(chain.getEndEntityCertificate()), StandardCharsets.UTF_8);

        // when
        Optional<ParsedCertificate> parsed = handler.parseCertificate(bundle.getBytes(StandardCharsets.UTF_8));

        // then
        assertThat(parsed).isEmpty();
    }

    @Test
    void readsTheDerCertificate_whenItsSubjectHoldsAPemHeaderText() throws Exception {
        // given
        KeyPair holderKeys = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate leaf = CertificateGeneratorHelper
                .generateEndEntityCertificate(chain.getCaCertificateKeyPair(), chain.getCaCertificate(), holderKeys,
                        "CN=-----BEGIN CERTIFICATE-----", null);

        // when
        Optional<ParsedCertificate> parsed = handler.parseCertificate(leaf.getEncoded());

        // then
        assertThat(parsed).isPresent();
    }

    @Test
    void readsTheDerCertificate_whenItsSubjectHoldsAPemHeaderOnALineOfItsOwn() throws Exception {
        // given — \0A is a line break in the subject, so the header text starts a line inside the DER
        KeyPair holderKeys = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate leaf = CertificateGeneratorHelper
                .generateEndEntityCertificate(chain.getCaCertificateKeyPair(), chain.getCaCertificate(), holderKeys,
                        "CN=holder\\0A-----BEGIN CERTIFICATE-----", null);

        // when
        Optional<ParsedCertificate> parsed = handler.parseCertificate(leaf.getEncoded());

        // then
        assertThat(parsed).isPresent();
    }

    @Test
    void readsTheDerRequest_whenItsSubjectHoldsAPemHeaderOnALineOfItsOwn() throws Exception {
        // given
        byte[] csr = pkcs10(chain.getEndEntityCertificateKeyPair(), "CN=holder\\0A-----BEGIN CERTIFICATE REQUEST-----");

        // when
        Optional<ParsedRequest> parsed = handler.parseRequest(csr);

        // then
        assertThat(parsed).isPresent();
    }

    @Test
    void readsTheDerRequest_whenItsSubjectHoldsAPemHeaderText() throws Exception {
        // given
        byte[] csr = pkcs10(chain.getEndEntityCertificateKeyPair(), "CN=-----BEGIN CERTIFICATE REQUEST-----");

        // when
        Optional<ParsedRequest> parsed = handler.parseRequest(csr);

        // then
        assertThat(parsed).isPresent();
    }

    @Test
    void readsTheCertificate_whenTextPrecedesItInPem() throws Exception {
        // given
        String withAttributes = "Bag Attributes\n    friendlyName: holder\n"
                + new String(toPem(chain.getEndEntityCertificate()), StandardCharsets.UTF_8);

        // when
        ParsedCertificate parsed = handler
                .parseCertificate(withAttributes.getBytes(StandardCharsets.UTF_8))
                .orElseThrow();

        // then
        assertThat(parsed.encoded()).isEqualTo(chain.getEndEntityCertificate().getEncoded());
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
    void returnsEmpty_whenTheContentIsACertificateInPem() throws Exception {
        // given
        byte[] certificatePem = toPem(chain.getEndEntityCertificate());

        // when
        Optional<ParsedRequest> parsed = handler.parseRequest(certificatePem);

        // then
        assertThat(parsed).isEmpty();
    }

    @Test
    void readsTheRequest_whenTheHeaderBodyAndFooterShareALine() throws Exception {
        // given
        byte[] csr = pkcs10(chain.getEndEntityCertificateKeyPair(), SUBJECT_DN);
        String singleLinePem = """
                -----BEGIN CERTIFICATE REQUEST-----%s-----END CERTIFICATE REQUEST-----"""
                .formatted(Base64.getEncoder().encodeToString(csr));

        // when
        ParsedRequest parsed = handler.parseRequest(singleLinePem.getBytes(StandardCharsets.UTF_8)).orElseThrow();

        // then
        assertThat(parsed.encoded()).isEqualTo(csr);
    }

    @Test
    void throwsHandlerException_whenAPemRequestHoldsNoRequestStructure() {
        // given — valid Base64 that decodes to an empty ASN.1 sequence
        byte[] emptySequencePem = "-----BEGIN CERTIFICATE REQUEST-----\nMAA=\n-----END CERTIFICATE REQUEST-----\n"
                .getBytes(StandardCharsets.UTF_8);

        // when
        ThrowingCallable parse = () -> handler.parseRequest(emptySequencePem);

        // then
        assertThatThrownBy(parse).isInstanceOf(CertificateTypeHandlerException.class);
    }

    @Test
    void throwsHandlerException_whenAPemRequestHasATruncatedBody() {
        // given
        byte[] truncatedPem = "-----BEGIN CERTIFICATE REQUEST-----\nAAA\n-----END CERTIFICATE REQUEST-----\n"
                .getBytes(StandardCharsets.UTF_8);

        // when
        ThrowingCallable parse = () -> handler.parseRequest(truncatedPem);

        // then
        assertThatThrownBy(parse).isInstanceOf(CertificateTypeHandlerException.class);
    }

    @Test
    void throwsHandlerException_whenAPemRequestIsMalformed() {
        // given
        byte[] malformedPem = """
                -----BEGIN CERTIFICATE REQUEST-----
                %%%not base64%%%
                -----END CERTIFICATE REQUEST-----
                """.getBytes(StandardCharsets.UTF_8);

        // when
        ThrowingCallable parse = () -> handler.parseRequest(malformedPem);

        // then
        assertThatThrownBy(parse).isInstanceOf(CertificateTypeHandlerException.class);
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
        byte[] encoded = handler.encode(List.of(leaf), CertificateFormat.RAW, CertificateFormatEncoding.DER);

        // then
        assertThat(encoded).isEqualTo(chain.getEndEntityCertificate().getEncoded());
    }

    @Test
    void returnsPemThatReadsBackAsTheSameCertificate_whenEncodingRawPem() throws Exception {
        // given
        ParsedCertificate leaf = parsedCertificate(chain.getEndEntityCertificate());

        // when
        byte[] encoded = handler.encode(List.of(leaf), CertificateFormat.RAW, CertificateFormatEncoding.PEM);

        // then
        assertThat(new String(encoded, StandardCharsets.UTF_8)).startsWith("-----BEGIN CERTIFICATE-----");
        assertThat(handler.parseCertificate(encoded).orElseThrow().encoded())
                .isEqualTo(chain.getEndEntityCertificate().getEncoded());
    }

    @Test
    void readsTheRequest_whenItIsGivenInBase64InTheNamedFormat() throws Exception {
        // given
        KeyPair holderKeys = chain.getEndEntityCertificateKeyPair();
        byte[] csr = pkcs10(holderKeys, SUBJECT_DN);

        // when
        ParsedRequest parsed = handler
                .readRequest(Base64.getEncoder().encodeToString(csr), CertificateRequestFormat.PKCS10);

        // then
        assertThat(parsed.format()).isEqualTo(CertificateRequestFormat.PKCS10);
        assertThat(parsed.encoded()).isEqualTo(csr);
        assertThat(parsed.holder()).isEqualTo(SUBJECT_DN);
        assertThat(parsed.publicKey()).isEqualTo(holderKeys.getPublic());
    }

    @Test
    void throwsRequestException_whenTheContentIsNotARequest() {
        // given
        var notARequest = Base64.getEncoder().encodeToString("not a request".getBytes(StandardCharsets.UTF_8));

        // when
        ThrowingCallable read = () -> handler.readRequest(notARequest, CertificateRequestFormat.PKCS10);

        // then
        assertThatThrownBy(read).isInstanceOf(CertificateRequestException.class);
    }

    @Test
    void acceptsTheRequest_whenItIsForTheKeyOfTheCertificate() throws Exception {
        // given
        ParsedCertificate leaf = parsedCertificate(chain.getEndEntityCertificate());
        ParsedRequest sameKey = handler
                .parseRequest(pkcs10(chain.getEndEntityCertificateKeyPair(), SUBJECT_DN))
                .orElseThrow();

        // when
        ThrowingCallable check = () -> handler.requireSameKey(sameKey, leaf);

        // then
        assertThatCode(check).doesNotThrowAnyException();
    }

    @Test
    void refusesTheRequest_whenItIsForAnotherKeyThanTheCertificate() throws Exception {
        // given
        ParsedCertificate leaf = parsedCertificate(chain.getEndEntityCertificate());
        ParsedRequest anotherKey = handler.parseRequest(pkcs10(otherCaKeys, SUBJECT_DN)).orElseThrow();

        // when
        ThrowingCallable check = () -> handler.requireSameKey(anotherKey, leaf);

        // then
        assertThatThrownBy(check)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("Public key of certificate and CSR does not match");
    }

    @Test
    void acceptsTheRekeyRequest_whenItHasANewKeyAndTheSameHolder() throws Exception {
        // given
        ParsedCertificate leaf = parsedCertificate(chain.getEndEntityCertificate());
        ParsedRequest newKey = handler.parseRequest(pkcs10(otherCaKeys, SUBJECT_DN)).orElseThrow();

        // when
        ThrowingCallable check = () -> handler.checkRekeyRequest(newKey, leaf);

        // then
        assertThatCode(check).doesNotThrowAnyException();
    }

    @Test
    void refusesTheRekeyRequest_whenItKeepsTheKeyOfTheCertificate() throws Exception {
        // given
        ParsedCertificate leaf = parsedCertificate(chain.getEndEntityCertificate());
        ParsedRequest sameKey = handler
                .parseRequest(pkcs10(chain.getEndEntityCertificateKeyPair(), SUBJECT_DN))
                .orElseThrow();

        // when
        ThrowingCallable check = () -> handler.checkRekeyRequest(sameKey, leaf);

        // then
        assertThatThrownBy(check)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("Public key of certificate and CSR are same");
    }

    @Test
    void refusesTheRekeyRequest_whenItNamesAnotherHolder() throws Exception {
        // given
        ParsedCertificate leaf = parsedCertificate(chain.getEndEntityCertificate());
        var anotherHolder = "CN=another-holder";
        ParsedRequest renamed = handler.parseRequest(pkcs10(otherCaKeys, anotherHolder)).orElseThrow();

        // when
        ThrowingCallable check = () -> handler.checkRekeyRequest(renamed, leaf);

        // then
        assertThatThrownBy(check)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("Subject DN of certificate and CSR does not match");
    }

    @Test
    void signsARequestForTheHolderOfTheCertificate_whenGeneratingARekeyRequest() throws Exception {
        // given
        var cryptographicOperationService = mock(CryptographicOperationInternalService.class);
        handler.setCryptographicOperationService(cryptographicOperationService);
        X509Certificate current = chain.getEndEntityCertificate();
        var signing = new RequestSigning(UUID.randomUUID(), UUID.randomUUID(), List.of(), null, null, null);
        var signedRequest = "signed-rekey-request";
        when(cryptographicOperationService
                .generateCsr(signing.keyUuid(), signing.tokenProfileUuid(), current.getSubjectX500Principal(), null,
                        signing.signatureAttributes(), null, null, null))
                .thenReturn(signedRequest);

        // when
        String generated = handler.generateRekeyRequest(parsedCertificate(current), signing);

        // then
        assertThat(generated).isEqualTo(signedRequest);
    }

    @Test
    void signsTheRequestWithTheGivenKeys_whenGeneratingARequestFromAttributes() throws Exception {
        // given
        var cryptographicOperationService = mock(CryptographicOperationInternalService.class);
        handler.setCryptographicOperationService(cryptographicOperationService);
        var signing = new RequestSigning(UUID.randomUUID(), UUID.randomUUID(), List.of(), UUID.randomUUID(),
                UUID.randomUUID(), List.of());
        var signedRequest = "signed-request";
        when(cryptographicOperationService
                .generateCsr(eq(signing.keyUuid()), eq(signing.tokenProfileUuid()), any(), any(),
                        eq(signing.signatureAttributes()), eq(signing.altKeyUuid()), eq(signing.altTokenProfileUuid()),
                        eq(signing.altSignatureAttributes())))
                .thenReturn(signedRequest);

        // when
        String generated = handler.generateRequest(List.of(), List.of(), CertificateRequestFormat.PKCS10, signing);

        // then
        assertThat(generated).isEqualTo(signedRequest);
    }

    @Test
    void refusesToGenerate_whenTheFormatIsCrmf() {
        // given
        var signing = new RequestSigning(UUID.randomUUID(), UUID.randomUUID(), List.of(), null, null, null);
        var unsupportedFormat = CertificateRequestFormat.CRMF;

        // when
        ThrowingCallable generate = () -> handler.generateRequest(List.of(), List.of(), unsupportedFormat, signing);

        // then
        assertThatThrownBy(generate)
                .isInstanceOf(CertificateException.class)
                .hasMessageContaining("CRMF format is not supported");
    }

    @Test
    void throwsValidation_whenTheKeyServiceFailsToSignTheRequest() throws Exception {
        // given
        var cryptographicOperationService = mock(CryptographicOperationInternalService.class);
        handler.setCryptographicOperationService(cryptographicOperationService);
        var signing = new RequestSigning(UUID.randomUUID(), UUID.randomUUID(), List.of(), null, null, null);
        var signingFailure = "the key cannot sign";
        when(cryptographicOperationService.generateCsr(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenThrow(new IOException(signingFailure));

        // when
        ThrowingCallable generate = () -> handler
                .generateRekeyRequest(parsedCertificate(chain.getEndEntityCertificate()), signing);

        // then
        assertThatThrownBy(generate)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("Failed to generate the CSR")
                .hasMessageContaining(signingFailure);
    }

    @Test
    void fillsTheX509Fields_whenStampingAnIssuedCertificate() throws Exception {
        // given
        X509Certificate issuedCertificate = chain.getEndEntityCertificate();
        var requested = aCertificate().withState(CertificateState.PENDING_ISSUE).build();

        // when
        Certificate stamped = handler.stampIssued(requested, parsedCertificate(issuedCertificate));

        // then
        assertThat(stamped).isSameAs(requested);
        assertThat(requested.getSerialNumber()).isEqualTo(issuedCertificate.getSerialNumber().toString(16));
        assertThat(requested.getSubjectDn()).contains("handler-test-holder");
        assertThat(requested.getNotAfter()).isEqualTo(issuedCertificate.getNotAfter());
        assertThat(requested.getState()).isEqualTo(CertificateState.PENDING_ISSUE);
    }

    @Test
    void returnsThePemOfTheCertificate_whenAskedForTheContentToStore() throws Exception {
        // given
        X509Certificate issuedCertificate = chain.getEndEntityCertificate();

        // when
        String content = handler.contentToStore(parsedCertificate(issuedCertificate));

        // then
        assertThat(content).isEqualTo(X509ObjectToString.toPem(issuedCertificate));
    }

    @Test
    void returnsSignedDataCarryingTheCertificate_whenEncodingPkcs7() throws Exception {
        // given
        ParsedCertificate leaf = parsedCertificate(chain.getEndEntityCertificate());

        // when
        byte[] encoded = handler.encode(List.of(leaf), CertificateFormat.PKCS7, CertificateFormatEncoding.DER);

        // then
        assertThat(new CMSSignedData(encoded).getCertificates().getMatches(null)).hasSize(1);
    }

    @Test
    void returnsEveryCertificateInOrder_whenEncodingAChainAsRawPem() throws Exception {
        // given
        ParsedCertificate leaf = parsedCertificate(chain.getEndEntityCertificate());
        ParsedCertificate ca = parsedCertificate(chain.getCaCertificate());

        // when
        byte[] encoded = handler.encode(List.of(leaf, ca), CertificateFormat.RAW, CertificateFormatEncoding.PEM);

        // then
        assertThat(readPemBlocks(encoded))
                .containsExactly(chain.getEndEntityCertificate().getEncoded(), chain.getCaCertificate().getEncoded());
    }

    @Test
    void returnsSignedDataCarryingEveryCertificate_whenEncodingAChainAsPkcs7() throws Exception {
        // given
        ParsedCertificate leaf = parsedCertificate(chain.getEndEntityCertificate());
        ParsedCertificate ca = parsedCertificate(chain.getCaCertificate());

        // when
        byte[] encoded = handler.encode(List.of(leaf, ca), CertificateFormat.PKCS7, CertificateFormatEncoding.DER);

        // then
        assertThat(new CMSSignedData(encoded).getCertificates().getMatches(null))
                .extracting(holder -> ((X509CertificateHolder) holder).getEncoded())
                .containsExactlyInAnyOrder(chain.getEndEntityCertificate().getEncoded(),
                        chain.getCaCertificate().getEncoded());
    }

    @Test
    void refusesAChain_whenEncodingRawDer() throws Exception {
        // given
        ParsedCertificate leaf = parsedCertificate(chain.getEndEntityCertificate());
        ParsedCertificate ca = parsedCertificate(chain.getCaCertificate());

        // when
        ThrowingCallable encoding = () -> handler
                .encode(List.of(leaf, ca), CertificateFormat.RAW, CertificateFormatEncoding.DER);

        // then
        assertThatThrownBy(encoding)
                .isInstanceOf(CertificateTypeHandlerException.class)
                .hasMessageContaining("one certificate only");
    }

    @Test
    void showsTheDisplayNameOfTheOid_whenPresentingTheExtendedKeyUsages() {
        // given
        // an OID of no registered arc, so the entry cannot replace one the shared cache already holds
        String namedOid = "2.999.1.1";
        String unnamedOid = "2.999.1.2";
        String displayName = "Handler Test Usage";
        OidHandler
                .cacheOid(OidCategory.EXTENDED_KEY_USAGE, namedOid,
                        new OidRecord(displayName, null, null, null, null, null, true));
        X509CertificateDetail detail = new X509CertificateDetail();
        detail.setExtendedKeyUsage(List.of(namedOid, unnamedOid));

        // when
        try {
            handler.presentDetail(detail);

            // then
            assertThat(detail.getExtendedKeyUsage()).containsExactly(displayName, unnamedOid);
        } finally {
            OidHandler.removeCachedOid(OidCategory.EXTENDED_KEY_USAGE, namedOid);
        }
    }

    @Test
    void givesTheX509RequestTheAlternativeSignatureAttributes_whenSettingThem() {
        // given
        ResponseAttribute altSignatureAttribute = new ResponseAttributeV3();
        X509CertificateRequestDetail request = new X509CertificateRequestDetail();

        // when
        handler.setAlternativeSignatureAttributes(request, List.of(altSignatureAttribute));

        // then
        assertThat(request.getAltSignatureAttributes()).containsExactly(altSignatureAttribute);
    }

    @Test
    void leavesTheDetailAsItIs_whenItHasNoExtendedKeyUsages() {
        // given
        X509CertificateDetail detail = new X509CertificateDetail();

        // when
        handler.presentDetail(detail);

        // then
        assertThat(detail.getExtendedKeyUsage()).isNull();
    }

    @Test
    void picksTheX509Handler_whenDetectingAmongSeveralTypes() throws Exception {
        // given
        var registry = new CertificateTypeHandlerRegistry(List.of(new StubCertificateTypeHandler(), handler));

        // when
        Optional<CertificateTypeHandlerRegistry.DetectedCertificate> detected = registry
                .detectCertificate(chain.getEndEntityCertificate().getEncoded());

        // then
        assertThat(detected).isPresent();
        assertThat(detected.get().handler()).isSameAs(handler);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static List<byte[]> readPemBlocks(byte[] pem) throws Exception {
        List<byte[]> blocks = new ArrayList<>();
        try (var reader = new PemReader(new InputStreamReader(new ByteArrayInputStream(pem), StandardCharsets.UTF_8))) {
            for (PemObject block = reader.readPemObject(); block != null; block = reader.readPemObject()) {
                blocks.add(block.getContent());
            }
        }
        return blocks;
    }

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

package com.otilm.core.service.est.message;

import com.otilm.api.model.core.est.EstMediaTypes;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.util.PkiFixtures;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletResponse;

import static java.util.Map.entry;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.Mockito.when;

/**
 * The expected status table below is the wire contract of the error responses, written out literally so that a change
 * to {@link EstError} fails here.
 */
@ExtendWith(MockitoExtension.class)
class EstResponsesTest {

    private static final String CONTENT_TRANSFER_ENCODING = "Content-Transfer-Encoding";
    private static final String PLAIN_TEXT_UTF8 = "text/plain; charset=UTF-8";
    private static final String CRLF = "\r\n";
    private static final String REALM = "devices";
    private static final String BASIC_CHALLENGE = "Basic realm=\"devices\"";

    private static final Map<EstError, Row> STATUS_TABLE = Map
            .ofEntries(
                    entry(EstError.BAD_REQUEST,
                            new Row(400, "The request is not a base64-encoded DER PKCS#10 certification request.",
                                    null)),
                    entry(EstError.INVALID_SIGNATURE,
                            new Row(400, "The certification request signature does not verify.", null)),
                    entry(EstError.UNAUTHORIZED, new Row(401, "Authentication is required.", BASIC_CHALLENGE)),
                    entry(EstError.REGISTRATION_REJECTED,
                            new Row(401, "The request does not match an active certificate registration.",
                                    BASIC_CHALLENGE)),
                    entry(EstError.CERTIFICATE_REJECTED, new Row(403, "The client certificate is not accepted.", null)),
                    entry(EstError.IDENTITY_MISMATCH,
                            new Row(403, "The request does not match the client certificate.", null)),
                    entry(EstError.NOT_FOUND, new Row(404, "Not found.", null)),
                    entry(EstError.METHOD_NOT_ALLOWED,
                            new Row(405, "The method is not allowed for this operation.", null)),
                    entry(EstError.PAYLOAD_TOO_LARGE, new Row(413, "The request is too large.", null)),
                    entry(EstError.UNSUPPORTED_MEDIA_TYPE,
                            new Row(415, "The content type must be application/pkcs10.", null)),
                    entry(EstError.INTERNAL_ERROR, new Row(500, "The request could not be processed.", null)),
                    entry(EstError.SERVICE_UNAVAILABLE,
                            new Row(503, "The service is temporarily unavailable. Try again later.", null)),
                    entry(EstError.REQUEST_REJECTED, new Row(403, "The certificate request was rejected.", null)),
                    entry(EstError.POLICY_VIOLATION,
                            new Row(400, "The certificate request does not meet the policy of the RA profile.", null)),
                    entry(EstError.ISSUANCE_FAILED,
                            new Row(503, "The certificate could not be issued. Try again later.", null)),
                    entry(EstError.RENEWAL_NOT_ALLOWED,
                            new Row(403, "Renewal with the same key is not allowed.", null)),
                    entry(EstError.REKEY_NOT_ALLOWED, new Row(403, "Renewal with a new key is not allowed.", null)),
                    entry(EstError.RENEWAL_NOT_DUE, new Row(403, "The certificate is not yet due for renewal.", null)),
                    entry(EstError.SUBJECT_CHANGE_UNSUPPORTED,
                            new Row(400, "Changing the subject name is not supported.", null)),
                    entry(EstError.RENEWAL_PENDING,
                            new Row(409, "The certificate already has a pending renewal.", null)),
                    entry(EstError.SERVER_KEYGEN_DISABLED,
                            new Row(403, "Server-side key generation is not enabled.", null)),
                    entry(EstError.SERVER_KEYGEN_UNAVAILABLE,
                            new Row(403, "Server-side key generation is not available for this route.", null)),
                    entry(EstError.ENCRYPTED_KEY_DELIVERY_UNSUPPORTED,
                            new Row(400, "Encrypted key delivery is not supported.", null)),
                    entry(EstError.ISSUANCE_TIMED_OUT,
                            new Row(503, "The certificate could not be issued in time.", null)));

    // ── CaCertificates ────────────────────────────────────────────────────────

    @Nested
    class CaCertificates {

        @Mock
        private X509Certificate unencodable;

        @Test
        void encodesCertsOnlyCms_withEveryChainCertificateAndNoSigner() throws Exception {
            // given
            List<X509Certificate> chain = List
                    .of(CertificateGeneratorHelper.generateCACertificate(null, "CN=Root CA"),
                            CertificateGeneratorHelper.generateCACertificate(null, "CN=Issuing CA"),
                            CertificateGeneratorHelper.generateCACertificate(null, "CN=Registration Authority"));

            // when
            ResponseEntity<byte[]> response = EstResponses.caCertificates(chain);

            // then
            byte[] der = Base64.getMimeDecoder().decode(response.getBody());
            CMSSignedData signedData = new CMSSignedData(der);
            assertThat(certificatesOf(signedData)).containsExactlyInAnyOrderElementsOf(chain);
            assertThat(signedData.getSignerInfos().size()).isZero();
            assertThat(signedData.getDigestAlgorithmIDs()).isEmpty();
            assertThat(signedData.getSignedContent()).isNull();
            assertThat(ASN1Primitive.fromByteArray(der).getEncoded(ASN1Encoding.DER)).isEqualTo(der);
        }

        @Test
        void answersOkWithPkcs7MimeAndBase64Encoding() throws Exception {
            // given
            List<X509Certificate> chain = List.of(CertificateGeneratorHelper.generateCACertificate(null, "CN=Root CA"));

            // when
            ResponseEntity<byte[]> response = EstResponses.caCertificates(chain);

            // then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE)).isEqualTo(EstMediaTypes.PKCS7_MIME);
            assertThat(response.getHeaders().getFirst(CONTENT_TRANSFER_ENCODING)).isEqualTo("base64");
        }

        @Test
        void throwsIllegalState_whenACertificateCannotBeEncoded() throws Exception {
            // given
            when(unencodable.getEncoded()).thenThrow(new CertificateEncodingException("not encodable"));

            // when
            ThrowingCallable encode = () -> EstResponses.caCertificates(List.of(unencodable));

            // then
            assertThatThrownBy(encode)
                    .isInstanceOf(IllegalStateException.class)
                    .hasCauseInstanceOf(CertificateEncodingException.class);
        }
    }

    // ── CsrAttributes ─────────────────────────────────────────────────────────

    @Nested
    class CsrAttributes {

        @Test
        void answersCsrAttrsAsBase64_whenTheSequenceIsNotEmpty() throws Exception {
            // given
            byte[] commonNameOnly = new DERSequence(new ASN1ObjectIdentifier("2.5.4.3")).getEncoded(ASN1Encoding.DER);

            // when
            ResponseEntity<byte[]> response = EstResponses.csrAttributes(commonNameOnly);

            // then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE)).isEqualTo(EstMediaTypes.CSR_ATTRS);
            assertThat(response.getHeaders().getFirst(CONTENT_TRANSFER_ENCODING)).isEqualTo("base64");
            assertThat(textOf(response)).isEqualTo(Base64.getEncoder().encodeToString(commonNameOnly) + CRLF);
        }

        @Test
        void answersNoContent_whenCsrAttrsAreAnEmptySequence() {
            // given
            byte[] emptySequence = {0x30, 0x00};

            // when
            ResponseEntity<byte[]> response = EstResponses.csrAttributes(emptySequence);

            // then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
            assertThat(response.getBody()).isNull();
        }
    }

    // ── Base64Layout ──────────────────────────────────────────────────────────

    @Nested
    class Base64Layout {

        @ParameterizedTest(name = "{0}")
        @MethodSource("derLengthsWithTheirLineLengths")
        void wrapsBase64InLinesOf64Characters(int derLength, List<Integer> expectedLineLengths) {
            // given — bytes standing in for the DER of a CsrAttrs, which the response does not look into
            byte[] der = bytesOfLength(derLength);

            // when
            ResponseEntity<byte[]> response = EstResponses.csrAttributes(der);

            // then
            String[] segments = textOf(response).split(CRLF, -1);
            List<String> lines = Arrays.asList(segments).subList(0, segments.length - 1);
            String afterTheLastLineEnd = segments[segments.length - 1];
            assertThat(afterTheLastLineEnd).isEmpty();
            assertThat(lines).extracting(String::length).containsExactlyElementsOf(expectedLineLengths);
            assertThat(Base64.getDecoder().decode(String.join("", lines))).isEqualTo(der);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static Stream<Arguments> derLengthsWithTheirLineLengths() {
            return Stream
                    .of(arguments(named("a single byte", 1), List.of(4)),
                            arguments(named("exactly one full line", 48), List.of(64)),
                            arguments(named("a full line and a short one", 49), List.of(64, 4)),
                            arguments(named("exactly two full lines", 96), List.of(64, 64)),
                            arguments(named("two full lines and a short one", 100), List.of(64, 64, 8)));
        }

        private static byte[] bytesOfLength(int length) {
            byte[] bytes = new byte[length];
            for (int index = 0; index < length; index++) {
                bytes[index] = (byte) (index + 1);
            }
            return bytes;
        }
    }

    // ── Enrolled ──────────────────────────────────────────────────────────────

    @Nested
    class Enrolled {

        @Test
        void answersIssuedCertificate_whenEnrolled() throws Exception {
            // given
            X509Certificate certificate = CertificateGeneratorHelper.generateCACertificate(null, "CN=Device");

            // when
            ResponseEntity<byte[]> response = EstResponses.enrolled(certificate);

            // then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE))
                    .isEqualTo(EstMediaTypes.PKCS7_CERTS_ONLY);
            assertThat(response.getHeaders().getFirst(CONTENT_TRANSFER_ENCODING)).isEqualTo("base64");
            CMSSignedData signedData = new CMSSignedData(Base64.getMimeDecoder().decode(response.getBody()));
            assertThat(certificatesOf(signedData)).containsExactly(certificate);
            assertThat(signedData.getSignerInfos().size()).isZero();
            assertThat(signedData.getSignedContent()).isNull();
        }
    }

    // ── ServerKeyGenerated ────────────────────────────────────────────────────

    @Nested
    class ServerKeyGenerated {

        private KeyPair keys;
        private X509Certificate certificate;
        private PrivateKeyInfo privateKey;

        @Mock
        private X509Certificate unencodable;

        @BeforeEach
        void createKeyAndCertificate() {
            keys = PkiFixtures.keyPair();
            certificate = PkiFixtures
                    .clientCertificateFor(PkiFixtures.rootCa("CN=Root"), keys, Instant.now().minusSeconds(60),
                            Instant.now().plusSeconds(3600), "CN=Device");
            privateKey = PrivateKeyInfo.getInstance(keys.getPrivate().getEncoded());
        }

        @Test
        void answersOkWithMultipartMixedAndNoStore() {
            // given — a generated key and its certificate

            // when
            ResponseEntity<byte[]> response = EstResponses.serverKeyGenerated(privateKey, certificate);

            // then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE))
                    .startsWith(EstMediaTypes.MULTIPART_MIXED + "; boundary=");
            assertThat(response.getHeaders().getFirst(HttpHeaders.CACHE_CONTROL)).isEqualTo("no-store");
        }

        @Test
        void framesTheBodyWithTheBoundaryOfTheContentType() {
            // given — a generated key and its certificate

            // when
            ResponseEntity<byte[]> response = EstResponses.serverKeyGenerated(privateKey, certificate);

            // then
            String boundary = boundaryOf(response);
            String body = textOf(response);
            assertThat(boundary).matches("[A-Za-z0-9-]{20,70}");
            assertThat(body).startsWith("--" + boundary + CRLF).endsWith(CRLF + "--" + boundary + "--" + CRLF);
            assertThat(body.split(Pattern.quote("--" + boundary), -1)).hasSize(4);
        }

        @Test
        void usesADifferentBoundaryEveryTime() {
            // given — two responses for the same key and certificate
            var first = EstResponses
                    .serverKeyGenerated(PrivateKeyInfo.getInstance(keys.getPrivate().getEncoded()), certificate);

            // when
            ResponseEntity<byte[]> second = EstResponses.serverKeyGenerated(privateKey, certificate);

            // then
            assertThat(boundaryOf(second)).isNotEqualTo(boundaryOf(first));
        }

        @Test
        void putsTheKeyPartFirstThenTheCertificatePart_eachWithItsHeaders() {
            // given — a generated key and its certificate

            // when
            ResponseEntity<byte[]> response = EstResponses.serverKeyGenerated(privateKey, certificate);

            // then
            String[] parts = partsOf(response);
            assertThat(parts[0])
                    .startsWith("Content-Type: application/pkcs8" + CRLF + "Content-Transfer-Encoding: base64" + CRLF
                            + CRLF);
            assertThat(parts[1])
                    .startsWith("Content-Type: application/pkcs7-mime; smime-type=certs-only" + CRLF
                            + "Content-Transfer-Encoding: base64" + CRLF + CRLF);
        }

        @Test
        void encodesTheKeyPartAsBase64OfPkcs8() {
            // given
            byte[] keyDer = keys.getPrivate().getEncoded();

            // when
            ResponseEntity<byte[]> response = EstResponses.serverKeyGenerated(privateKey, certificate);

            // then
            assertThat(Base64.getMimeDecoder().decode(bodyOf(partsOf(response)[0]))).isEqualTo(keyDer);
        }

        @Test
        void deliversTheKeyThatMatchesTheCertificate() throws Exception {
            // given
            byte[] message = {1, 2, 3};

            // when
            ResponseEntity<byte[]> response = EstResponses.serverKeyGenerated(privateKey, certificate);

            // then
            byte[] delivered = Base64.getMimeDecoder().decode(bodyOf(partsOf(response)[0]));
            PrivateKey key = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(delivered));
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(key);
            signer.update(message);
            byte[] signature = signer.sign();
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(certificate.getPublicKey());
            verifier.update(message);
            assertThat(verifier.verify(signature)).isTrue();
        }

        @Test
        void encodesTheCertificatePartAsBase64OfCertsOnlyCms() throws Exception {
            // given — a generated key and its certificate

            // when
            ResponseEntity<byte[]> response = EstResponses.serverKeyGenerated(privateKey, certificate);

            // then
            byte[] der = Base64.getMimeDecoder().decode(bodyOf(partsOf(response)[1]));
            CMSSignedData signedData = new CMSSignedData(der);
            assertThat(certificatesOf(signedData)).containsExactly(certificate);
            assertThat(signedData.getSignerInfos().size()).isZero();
            assertThat(ASN1Primitive.fromByteArray(der).getEncoded(ASN1Encoding.DER)).isEqualTo(der);
        }

        @Test
        void wrapsBothPartsInLinesOf64Characters() {
            // given — a generated key and its certificate

            // when
            ResponseEntity<byte[]> response = EstResponses.serverKeyGenerated(privateKey, certificate);

            // then
            for (String part : partsOf(response)) {
                String[] lines = bodyOf(part).split(CRLF);
                assertThat(Arrays.stream(lines).limit(lines.length - 1)).allMatch(line -> line.length() == 64);
                assertThat(lines[lines.length - 1]).hasSizeBetween(1, 64);
            }
        }

        @Test
        void overwritesTheKeyOctets_onceTheBodyIsBuilt() {
            // given
            byte[] octets = privateKey.getPrivateKey().getOctets();

            // when
            EstResponses.serverKeyGenerated(privateKey, certificate);

            // then
            assertThat(octets).containsOnly(0);
        }

        @Test
        void overwritesTheKeyOctets_whenTheCertificateCannotBeEncoded() throws Exception {
            // given
            byte[] octets = privateKey.getPrivateKey().getOctets();
            when(unencodable.getEncoded()).thenThrow(new CertificateEncodingException("not encodable"));

            // when
            ThrowingCallable respond = () -> EstResponses.serverKeyGenerated(privateKey, unencodable);

            // then
            assertThatThrownBy(respond).isInstanceOf(IllegalStateException.class);
            assertThat(octets).containsOnly(0);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static String boundaryOf(ResponseEntity<byte[]> response) {
            String contentType = response.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE);
            return contentType.substring(contentType.indexOf("boundary=") + "boundary=".length());
        }

        /** The two parts between the delimiters, each without the delimiter lines around it. */
        private static String[] partsOf(ResponseEntity<byte[]> response) {
            String[] sections = textOf(response).split(Pattern.quote("--" + boundaryOf(response)), -1);
            return new String[]{
                    sections[1].substring(CRLF.length(), sections[1].length() - CRLF.length()),
                    sections[2].substring(CRLF.length(), sections[2].length() - CRLF.length())};
        }

        private static String bodyOf(String part) {
            return part.substring(part.indexOf(CRLF + CRLF) + 2 * CRLF.length());
        }
    }

    // ── Pending ───────────────────────────────────────────────────────────────

    @Nested
    class Pending {

        @Test
        void answersAcceptedWithRetryAfter_whenPending() {
            // given
            Duration retryAfter = Duration.ofSeconds(30);

            // when
            ResponseEntity<byte[]> response = EstResponses.pending(retryAfter);

            // then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
            assertThat(response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("30");
            assertThat(response.getBody()).isNull();
            assertThat(response.getHeaders().getContentType()).isNull();
            assertThat(response.getHeaders().containsHeader(HttpHeaders.LOCATION)).isFalse();
        }
    }

    // ── ErrorResponse ─────────────────────────────────────────────────────────

    @Nested
    class ErrorResponse {

        @ParameterizedTest
        @EnumSource(EstError.class)
        void rendersErrorAsPlainText_withStatusAndText(EstError error) {
            // given
            Row expected = expectedRowOf(error);

            // when
            ResponseEntity<byte[]> response = EstResponses.error(error, REALM);

            // then
            assertThat(response.getStatusCode().value()).isEqualTo(expected.status());
            assertThat(response.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE)).isEqualTo(PLAIN_TEXT_UTF8);
            assertThat(textOf(response)).isEqualTo(expected.text());
            assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE)).isEqualTo(expected.challenge());
        }

        @ParameterizedTest
        @ValueSource(strings = {"devices", "est"})
        void addsBasicChallenge_whenErrorChallenges(String realm) {
            // given — an error that asks the client for credentials
            EstError challenging = EstError.UNAUTHORIZED;

            // when
            ResponseEntity<byte[]> response = EstResponses.error(challenging, realm);

            // then
            assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                    .isEqualTo("Basic realm=\"" + realm + "\"");
        }
    }

    // ── ErrorWithDetail ───────────────────────────────────────────────────────

    @Nested
    class ErrorWithDetail {

        @Test
        void appendsDetailAfterOneSpace_whenRefusalCarriesOne() {
            // given
            String detail = "The subject must contain a common name.";

            // when
            ResponseEntity<byte[]> response = EstResponses.error(EstError.POLICY_VIOLATION, REALM, detail);

            // then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(textOf(response)).isEqualTo(EstError.POLICY_VIOLATION.text() + " " + detail);
        }

        @Test
        void writesFixedSentenceOnly_whenRefusalCarriesNoDetail() {
            // given
            String noDetail = null;

            // when
            ResponseEntity<byte[]> response = EstResponses.error(EstError.POLICY_VIOLATION, REALM, noDetail);

            // then
            assertThat(textOf(response)).isEqualTo(EstError.POLICY_VIOLATION.text());
        }
    }

    // ── WriteError ────────────────────────────────────────────────────────────

    @Nested
    class WriteError {

        @Test
        void writesAllowHeader_whenMethodIsNotAllowed() throws Exception {
            // given
            MockHttpServletResponse response = new MockHttpServletResponse();

            // when
            EstResponses.write(response, EstError.METHOD_NOT_ALLOWED, "POST");

            // then
            assertThat(response.getStatus()).isEqualTo(405);
            assertThat(response.getHeader(HttpHeaders.ALLOW)).isEqualTo("POST");
        }

        @Test
        void omitsAllowHeader_whenErrorIsNotMethodNotAllowed() throws Exception {
            // given
            MockHttpServletResponse response = new MockHttpServletResponse();

            // when
            EstResponses.write(response, EstError.NOT_FOUND, "POST");

            // then
            assertThat(response.getHeader(HttpHeaders.ALLOW)).isNull();
        }

        @ParameterizedTest
        @EnumSource(EstError.class)
        void rendersTheSameAsTheEntity_whenWritingOnAServletResponse(EstError error) throws Exception {
            // given — the realm a response without a label carries
            ResponseEntity<byte[]> entity = EstResponses.error(error, "est");
            MockHttpServletResponse response = new MockHttpServletResponse();

            // when
            EstResponses.write(response, error, null);

            // then
            assertThat(response.getStatus()).isEqualTo(entity.getStatusCode().value());
            assertThat(response.getContentType()).isEqualTo(entity.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE));
            assertThat(response.getContentAsByteArray()).isEqualTo(entity.getBody());
            assertThat(response.getContentLength()).isEqualTo(Objects.requireNonNull(entity.getBody()).length);
            assertThat(response.getHeader(HttpHeaders.WWW_AUTHENTICATE))
                    .isEqualTo(entity.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE));
            assertThat(response.getHeader(HttpHeaders.ALLOW)).isNull();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private record Row(int status, String text, String challenge) {
    }

    private static Row expectedRowOf(EstError error) {
        return Objects.requireNonNull(STATUS_TABLE.get(error), () -> "no expected row for " + error);
    }

    private static String textOf(ResponseEntity<byte[]> response) {
        return new String(Objects.requireNonNull(response.getBody()), StandardCharsets.UTF_8);
    }

    private static List<X509Certificate> certificatesOf(CMSSignedData signedData) throws CertificateException {
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        List<X509Certificate> certificates = new ArrayList<>();
        for (X509CertificateHolder holder : signedData.getCertificates().getMatches(null)) {
            certificates.add(converter.getCertificate(holder));
        }
        return certificates;
    }
}

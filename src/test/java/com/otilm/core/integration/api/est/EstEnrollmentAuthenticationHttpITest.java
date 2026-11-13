package com.otilm.core.integration.api.est;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.Secret;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstRequestGuard;
import com.otilm.core.util.EstCsrFixtures;
import com.otilm.core.util.PkiFixtures.Ca;
import com.otilm.core.util.SecretLeakProbe;
import com.otilm.core.util.mocks.AuthorityV2ConnectorStubs;
import com.otilm.core.util.seeders.CertificateRegistrationSeeder;
import com.otilm.core.util.seeders.SecretSeeder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static com.otilm.core.util.EstClientCredentialsFixtures.basicAuthorization;
import static com.otilm.core.util.EstClientCredentialsFixtures.certificateHeader;
import static com.otilm.core.util.EstClientCredentialsFixtures.malformedBasicAuthorization;
import static com.otilm.core.util.EstClientCredentialsFixtures.malformedCertificateHeader;
import static com.otilm.core.util.PkiFixtures.CLIENT_SUBJECT;
import static com.otilm.core.util.PkiFixtures.clientCertificate;
import static com.otilm.core.util.PkiFixtures.intermediateCa;
import static com.otilm.core.util.PkiFixtures.raCertificate;
import static com.otilm.core.util.PkiFixtures.rootCa;
import static com.otilm.core.util.PkiFixtures.selfSignedClientCertificate;
import static java.security.spec.RSAKeyGenParameterSpec.F4;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * Who may enroll through {@code /simpleenroll}, over HTTP through the real filter chain: every authentication policy
 * against what a client can present, the refusals that come before authentication, and the proof of possession that
 * comes after it. A registration client that authentication accepts has its registration completed and is told to come
 * back, as nothing here goes on to issue its certificate; any other client that authentication accepts is answered
 * {@link #CONNECTOR_UNAVAILABLE}.
 * <p>
 * Every route that a test seeds holds the material of every policy: the Secret of an RA credential, the registration of
 * the subject, and the root of the PKI that issued the certificates. A policy that fell back on another one would then
 * accept what it must not, instead of being refused for want of configuration. Certificates name no revocation source.
 */
class EstEnrollmentAuthenticationHttpITest extends AbstractEstHttpITest {

    private static final String LABEL = "devices";
    private static final String USERNAME = "device-owner";
    private static final String PASSWORD = "p4ssw0rd";
    private static final String WRONG_PASSWORD = "wr0ng-p4ssw0rd";
    private static final String NO_USERNAME = "";
    private static final String BASIC_SCHEME = "Basic ";

    /**
     * What {@code /simpleenroll} answers any other client that authentication accepted here: the request goes on to be
     * issued, and the connector of the seeded RA Profile cannot be reached, so the service is unavailable.
     */
    private static final EstError CONNECTOR_UNAVAILABLE = EstError.SERVICE_UNAVAILABLE;

    @Autowired
    private SecretSeeder secrets;

    @Autowired
    private CertificateRegistrationSeeder registrations;

    @Value("${server.ssl.certificate-header-name}")
    private String certificateHeaderName;

    private Ca issuingCa;
    private RaProfile raProfile;
    private Secret credentialSecret;
    private Certificate trustedRoot;
    private Certificate registration;

    @BeforeEach
    void seedTheMaterialOfEveryPolicy() {
        Ca root = rootCa("EST Root CA");
        issuingCa = intermediateCa(root, "EST Issuing CA");
        trustedRoot = seeder.seedCertificate(root.certificate());
        raProfile = saveRaProfile("devices-ra");
        credentialSecret = secrets.seedBasicAuthSecret("ra-credential", USERNAME, PASSWORD);
        registration = registrations.seedRegistration(raProfile, CLIENT_SUBJECT);
    }

    // ── Authentication ────────────────────────────────────────────────────────

    @Nested
    class Authentication {

        @ParameterizedTest
        @MethodSource({"credentialsPerPolicy", "onlyTheCredentialsOfAnotherPolicy"})
        void answersPerPolicy_whenSimpleEnrollPresentsCredentials(EstAuthenticationPolicy policy, Presented presented,
                EstError answer) throws Exception {
            // given
            seedRoute(policy);
            byte[] csr = EstCsrFixtures.signedRequestBody(CLIENT_SUBJECT);

            // when
            MockHttpServletResponse response = enroll(csr, credentialsOf(presented));

            // then
            assertAnswered(response, answer);
        }

        @ParameterizedTest
        @MethodSource("credentialsOfBothKinds")
        void ignoresOtherPolicysCredentials_whenTheyAccompanyTheProfilesOwn(EstAuthenticationPolicy policy,
                Presented own, Presented other, EstError answer) throws Exception {
            // given
            seedRoute(policy);
            byte[] csr = EstCsrFixtures.signedRequestBody(CLIENT_SUBJECT);
            Credentials ofBothKinds = credentialsOf(own).and(credentialsOf(other));

            // when
            MockHttpServletResponse response = enroll(csr, ofBothKinds);

            // then
            assertAnswered(response, answer);
        }

        @Test
        void answersAccepted_whenRegistrationClientPresentsTheChallenge() throws Exception {
            // given — nothing here issues what the completion queues, so it is still on its way when the wait ends
            seedRoute(EstAuthenticationPolicy.CERTIFICATE_REGISTRATION);
            AuthorityV2ConnectorStubs.on(connectorServer).stubIssueAttributeValidation();
            byte[] csr = EstCsrFixtures.signedRequestBody(CLIENT_SUBJECT);
            Credentials challengeOfTheRegistration = credentialsOf(Presented.BASIC_OF_A_REGISTRATION);

            // when
            MockHttpServletResponse response = enroll(csr, challengeOfTheRegistration);

            // then
            assertThat(response.getStatus()).isEqualTo(HttpStatus.ACCEPTED.value());
            assertThat(response.getHeader(HttpHeaders.RETRY_AFTER)).isEqualTo("30");
        }

        @ParameterizedTest
        @EnumSource(value = Presented.class, names = {"TRUSTED_RA_CERTIFICATE", "MALFORMED_CERTIFICATE"})
        void answersAccepted_whenACertificateAccompaniesTheChallenge(Presented alongside) throws Exception {
            // given — the registration was completed with this request, which is then answered without waiting
            seedRoute(EstAuthenticationPolicy.CERTIFICATE_REGISTRATION);
            byte[] csr = EstCsrFixtures.signedRequestBody(CLIENT_SUBJECT);
            registrations
                    .seedCompletion(registration, Base64.getMimeDecoder().decode(csr), CertificateState.REGISTERED);
            Credentials challengeAndCertificate = credentialsOf(Presented.BASIC_OF_A_REGISTRATION)
                    .and(credentialsOf(alongside));

            // when
            MockHttpServletResponse response = enroll(csr, challengeAndCertificate);

            // then
            assertThat(response.getStatus()).isEqualTo(HttpStatus.ACCEPTED.value());
        }

        @Test
        void answersIdentityMismatch_whenVendorCsrSubjectDiffersFromCertificate() throws Exception {
            // given
            seedRoute(EstAuthenticationPolicy.VENDOR_MTLS);
            var subjectOfAnotherDevice = "CN=another device";
            byte[] csrOfAnotherDevice = EstCsrFixtures.signedRequestBody(subjectOfAnotherDevice);
            Credentials certificateOfTheDevice = credentialsOf(Presented.TRUSTED_CLIENT_CERTIFICATE);

            // when
            MockHttpServletResponse response = enroll(csrOfAnotherDevice, certificateOfTheDevice);

            // then
            assertAnswered(response, EstError.IDENTITY_MISMATCH);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        static Stream<Arguments> credentialsPerPolicy() {
            return Stream
                    .of(arguments(EstAuthenticationPolicy.RA_BASIC, Presented.NOTHING, EstError.UNAUTHORIZED),
                            arguments(EstAuthenticationPolicy.RA_BASIC, Presented.BASIC_WITH_WRONG_PASSWORD,
                                    EstError.UNAUTHORIZED),
                            arguments(EstAuthenticationPolicy.RA_BASIC, Presented.BASIC_OF_A_SECRET,
                                    CONNECTOR_UNAVAILABLE),
                            arguments(EstAuthenticationPolicy.CERTIFICATE_REGISTRATION, Presented.NOTHING,
                                    EstError.UNAUTHORIZED),
                            arguments(EstAuthenticationPolicy.CERTIFICATE_REGISTRATION,
                                    Presented.BASIC_OF_NO_REGISTRATION, EstError.REGISTRATION_REJECTED),
                            arguments(EstAuthenticationPolicy.VENDOR_MTLS, Presented.NOTHING,
                                    EstError.CERTIFICATE_REJECTED),
                            arguments(EstAuthenticationPolicy.VENDOR_MTLS, Presented.UNTRUSTED_CERTIFICATE,
                                    EstError.CERTIFICATE_REJECTED),
                            arguments(EstAuthenticationPolicy.VENDOR_MTLS, Presented.TRUSTED_CLIENT_CERTIFICATE,
                                    CONNECTOR_UNAVAILABLE),
                            arguments(EstAuthenticationPolicy.RA_MTLS, Presented.NOTHING,
                                    EstError.CERTIFICATE_REJECTED),
                            arguments(EstAuthenticationPolicy.RA_MTLS, Presented.TRUSTED_CLIENT_CERTIFICATE,
                                    EstError.CERTIFICATE_REJECTED),
                            arguments(EstAuthenticationPolicy.RA_MTLS, Presented.TRUSTED_RA_CERTIFICATE,
                                    CONNECTOR_UNAVAILABLE),
                            arguments(EstAuthenticationPolicy.RA_BASIC, Presented.MALFORMED_BASIC,
                                    EstError.UNAUTHORIZED),
                            arguments(EstAuthenticationPolicy.CERTIFICATE_REGISTRATION, Presented.MALFORMED_BASIC,
                                    EstError.UNAUTHORIZED),
                            arguments(EstAuthenticationPolicy.VENDOR_MTLS, Presented.MALFORMED_CERTIFICATE,
                                    EstError.CERTIFICATE_REJECTED),
                            arguments(EstAuthenticationPolicy.RA_MTLS, Presented.MALFORMED_CERTIFICATE,
                                    EstError.CERTIFICATE_REJECTED),
                            arguments(EstAuthenticationPolicy.RA_MTLS, Presented.UNTRUSTED_CERTIFICATE,
                                    EstError.CERTIFICATE_REJECTED));
        }

        /**
         * Each credential is accepted by the policies of its kind: the Basic credentials by {@code raBasic}, and by
         * {@code certificateRegistration}, which finds the registration by the subject of the request; the certificate
         * by the certificate policies. A header of the other kind that cannot be read is no credential either.
         */
        static Stream<Arguments> onlyTheCredentialsOfAnotherPolicy() {
            return Stream
                    .of(arguments(EstAuthenticationPolicy.RA_BASIC, Presented.TRUSTED_RA_CERTIFICATE,
                            EstError.UNAUTHORIZED),
                            arguments(EstAuthenticationPolicy.CERTIFICATE_REGISTRATION,
                                    Presented.TRUSTED_RA_CERTIFICATE, EstError.UNAUTHORIZED),
                            arguments(EstAuthenticationPolicy.VENDOR_MTLS, Presented.BASIC_OF_A_SECRET,
                                    EstError.CERTIFICATE_REJECTED),
                            arguments(EstAuthenticationPolicy.RA_MTLS, Presented.BASIC_OF_A_SECRET,
                                    EstError.CERTIFICATE_REJECTED),
                            arguments(EstAuthenticationPolicy.RA_BASIC, Presented.MALFORMED_CERTIFICATE,
                                    EstError.UNAUTHORIZED),
                            arguments(EstAuthenticationPolicy.CERTIFICATE_REGISTRATION, Presented.MALFORMED_CERTIFICATE,
                                    EstError.UNAUTHORIZED),
                            arguments(EstAuthenticationPolicy.VENDOR_MTLS, Presented.MALFORMED_BASIC,
                                    EstError.CERTIFICATE_REJECTED),
                            arguments(EstAuthenticationPolicy.RA_MTLS, Presented.MALFORMED_BASIC,
                                    EstError.CERTIFICATE_REJECTED));
        }

        /**
         * The answer is the one that the profile's own credentials get alone: the other kind neither rescues wrong
         * credentials nor spoils valid ones, whether it is valid or cannot be read.
         */
        static Stream<Arguments> credentialsOfBothKinds() {
            return Stream
                    .of(arguments(EstAuthenticationPolicy.RA_BASIC, Presented.BASIC_OF_A_SECRET,
                            Presented.TRUSTED_RA_CERTIFICATE, CONNECTOR_UNAVAILABLE),
                            arguments(EstAuthenticationPolicy.RA_BASIC, Presented.BASIC_OF_A_SECRET,
                                    Presented.MALFORMED_CERTIFICATE, CONNECTOR_UNAVAILABLE),
                            arguments(EstAuthenticationPolicy.RA_BASIC, Presented.BASIC_WITH_WRONG_PASSWORD,
                                    Presented.TRUSTED_RA_CERTIFICATE, EstError.UNAUTHORIZED),
                            arguments(EstAuthenticationPolicy.CERTIFICATE_REGISTRATION,
                                    Presented.BASIC_OF_NO_REGISTRATION, Presented.TRUSTED_RA_CERTIFICATE,
                                    EstError.REGISTRATION_REJECTED),
                            arguments(EstAuthenticationPolicy.VENDOR_MTLS, Presented.TRUSTED_CLIENT_CERTIFICATE,
                                    Presented.BASIC_OF_A_SECRET, CONNECTOR_UNAVAILABLE),
                            arguments(EstAuthenticationPolicy.VENDOR_MTLS, Presented.TRUSTED_CLIENT_CERTIFICATE,
                                    Presented.MALFORMED_BASIC, CONNECTOR_UNAVAILABLE),
                            arguments(EstAuthenticationPolicy.VENDOR_MTLS, Presented.UNTRUSTED_CERTIFICATE,
                                    Presented.BASIC_OF_A_SECRET, EstError.CERTIFICATE_REJECTED),
                            arguments(EstAuthenticationPolicy.RA_MTLS, Presented.TRUSTED_RA_CERTIFICATE,
                                    Presented.BASIC_OF_A_SECRET, CONNECTOR_UNAVAILABLE),
                            arguments(EstAuthenticationPolicy.RA_MTLS, Presented.TRUSTED_RA_CERTIFICATE,
                                    Presented.MALFORMED_BASIC, CONNECTOR_UNAVAILABLE),
                            arguments(EstAuthenticationPolicy.RA_MTLS, Presented.TRUSTED_CLIENT_CERTIFICATE,
                                    Presented.BASIC_OF_A_SECRET, EstError.CERTIFICATE_REJECTED));
        }
    }

    // ── RefusalsBeforeAuthentication ──────────────────────────────────────────

    @Nested
    class RefusalsBeforeAuthentication {

        @ParameterizedTest
        @EnumSource(value = Presented.class, names = {"BASIC_OF_A_SECRET", "NOTHING"})
        void answersBadRequest_whenSimpleEnrollBodyIsNotACsr(Presented presented) throws Exception {
            // given
            seedRoute(EstAuthenticationPolicy.RA_BASIC);
            byte[] notACsr = "this is not a certification request".getBytes(StandardCharsets.US_ASCII);

            // when
            MockHttpServletResponse response = enroll(notACsr, credentialsOf(presented));

            // then
            assertAnswered(response, EstError.BAD_REQUEST);
        }

        @Test
        void answersBadRequest_whenCsrAsksForANameThatCannotBeRendered() throws Exception {
            // given
            seedRoute(EstAuthenticationPolicy.RA_BASIC);
            byte[] csrWithAnUnrenderableName = EstCsrFixtures
                    .signedRequestBodyWithNames(CLIENT_SUBJECT, EstCsrFixtures.otherNameWithoutAValue());

            // when
            MockHttpServletResponse response = enroll(csrWithAnUnrenderableName, credentialsOf(Presented.NOTHING));

            // then
            assertAnswered(response, EstError.BAD_REQUEST);
        }

        @Test
        void answersBadRequest_whenCsrCarriesAnRsaKeyOf16384Bits() throws Exception {
            // given
            seedRoute(EstAuthenticationPolicy.RA_BASIC);
            byte[] csrWithAnRsaKeyOf16384Bits = EstCsrFixtures
                    .requestBodyWithRsaPublicKey(PKCSObjectIdentifiers.rsaEncryption, 16384, F4);

            // when
            MockHttpServletResponse response = enroll(csrWithAnRsaKeyOf16384Bits, credentialsOf(Presented.NOTHING));

            // then
            assertAnswered(response, EstError.BAD_REQUEST);
        }

        @Test
        void answersPayloadTooLarge_whenSimpleEnrollBodyExceedsTheLimit() throws Exception {
            // given
            seedRoute(EstAuthenticationPolicy.RA_BASIC);
            byte[] bodyOverTheLimit = new byte[EstRequestGuard.MAX_BODY_BYTES + 1];
            Arrays.fill(bodyOverTheLimit, (byte) 'A');
            Credentials validCredentials = credentialsOf(Presented.BASIC_OF_A_SECRET);

            // when
            MockHttpServletResponse response = enroll(bodyOverTheLimit, validCredentials);

            // then
            assertAnswered(response, EstError.PAYLOAD_TOO_LARGE);
        }

        @Test
        void answersUnsupportedMediaType_whenSimpleEnrollIsJson() throws Exception {
            // given
            seedRoute(EstAuthenticationPolicy.RA_BASIC);
            byte[] csr = EstCsrFixtures.signedRequestBody(CLIENT_SUBJECT);
            Credentials validCredentials = credentialsOf(Presented.BASIC_OF_A_SECRET);
            MockHttpServletRequestBuilder enrollmentAsJson = presenting(
                    estPost(LABEL + "/simpleenroll", csr).contentType(MediaType.APPLICATION_JSON), validCredentials);

            // when
            MockHttpServletResponse response = mockMvc.perform(enrollmentAsJson).andReturn().getResponse();

            // then
            assertAnswered(response, EstError.UNSUPPORTED_MEDIA_TYPE);
        }
    }

    // ── ProofOfPossession ─────────────────────────────────────────────────────

    @Nested
    class ProofOfPossession {

        @ParameterizedTest
        @MethodSource("credentialsThatAuthenticate")
        void answersInvalidSignature_whenAnAuthenticatedClientsCsrSignatureDoesNotVerify(EstAuthenticationPolicy policy,
                Presented presented) throws Exception {
            // given
            seedRoute(policy);
            byte[] csrWithForgedSignature = EstCsrFixtures.forgedRequestBody(CLIENT_SUBJECT);

            // when
            MockHttpServletResponse response = enroll(csrWithForgedSignature, credentialsOf(presented));

            // then
            assertAnswered(response, EstError.INVALID_SIGNATURE);
        }

        @Test
        void answersAsNonMatch_whenRegistrationClientsCsrSignatureDoesNotVerify() throws Exception {
            // given — the forged request names the registered subject, and the client presents its challenge
            seedRoute(EstAuthenticationPolicy.CERTIFICATE_REGISTRATION);
            byte[] csrWithForgedSignature = EstCsrFixtures.forgedRequestBody(CLIENT_SUBJECT);

            // when
            MockHttpServletResponse response = enroll(csrWithForgedSignature,
                    credentialsOf(Presented.BASIC_OF_A_REGISTRATION));

            // then
            assertAnswered(response, EstError.REGISTRATION_REJECTED);
        }

        @ParameterizedTest
        @MethodSource("refusalsOfAClientWithoutCredentials")
        void answersTheRefusalOfAuthentication_whenAnUnauthenticatedClientsCsrSignatureDoesNotVerify(
                EstAuthenticationPolicy policy, EstError refusal) throws Exception {
            // given
            seedRoute(policy);
            byte[] csrWithForgedSignature = EstCsrFixtures.forgedRequestBody(CLIENT_SUBJECT);

            // when
            MockHttpServletResponse response = enroll(csrWithForgedSignature, credentialsOf(Presented.NOTHING));

            // then
            assertAnswered(response, refusal);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        /** Under {@code certificateRegistration} a forged request is refused like one that matches no registration. */
        static Stream<Arguments> credentialsThatAuthenticate() {
            return Stream
                    .of(arguments(EstAuthenticationPolicy.RA_BASIC, Presented.BASIC_OF_A_SECRET),
                            arguments(EstAuthenticationPolicy.VENDOR_MTLS, Presented.TRUSTED_CLIENT_CERTIFICATE),
                            arguments(EstAuthenticationPolicy.RA_MTLS, Presented.TRUSTED_RA_CERTIFICATE));
        }

        static Stream<Arguments> refusalsOfAClientWithoutCredentials() {
            return Stream
                    .of(arguments(EstAuthenticationPolicy.RA_BASIC, EstError.UNAUTHORIZED),
                            arguments(EstAuthenticationPolicy.CERTIFICATE_REGISTRATION, EstError.UNAUTHORIZED),
                            arguments(EstAuthenticationPolicy.VENDOR_MTLS, EstError.CERTIFICATE_REJECTED),
                            arguments(EstAuthenticationPolicy.RA_MTLS, EstError.CERTIFICATE_REJECTED));
        }
    }

    // ── Discovery ─────────────────────────────────────────────────────────────

    @Nested
    class Discovery {

        @ParameterizedTest
        @ValueSource(strings = {"cacerts", "csrattrs"})
        void answersWithoutAuthentication_whenDiscoveryCarriesBadCredentials(String operation) throws Exception {
            // given
            stubCaCertificates(generateChain());
            seedRoute(EstAuthenticationPolicy.VENDOR_MTLS);
            Credentials badCredentials = new Credentials(basicAuthorization(USERNAME, WRONG_PASSWORD),
                    malformedCertificateHeader());

            // when
            MockHttpServletRequestBuilder discovery = presenting(estGet(LABEL + "/" + operation), badCredentials);
            MockHttpServletResponse response = mockMvc.perform(discovery).andReturn().getResponse();

            // then
            assertThat(response.getStatus()).isEqualTo(200);
        }
    }

    // ── Logging ───────────────────────────────────────────────────────────────

    @Nested
    class Logging {

        @ParameterizedTest
        @MethodSource("refusedRequests")
        void logsNoCredential_whenRequestsAreRefused(EstAuthenticationPolicy policy, Presented presented,
                String subjectOfTheRequest) throws Exception {
            // given
            seedRoute(policy);
            byte[] csr = EstCsrFixtures.signedRequestBody(subjectOfTheRequest);
            Credentials refusedCredentials = credentialsOf(presented);

            try (SecretLeakProbe probe = SecretLeakProbe.capture()) {
                // when
                MockHttpServletResponse response = enroll(csr, refusedCredentials);

                // then
                assertThat(response.getStatus()).isIn(401, 403);
                SecretLeakProbe.assertNoneReveals(probe.logged(), secretsPresentedWith(csr, refusedCredentials));
            }
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        static Stream<Arguments> refusedRequests() {
            var subjectOfAnotherDevice = "CN=another device";
            return Stream
                    .of(arguments(EstAuthenticationPolicy.RA_BASIC, Presented.BASIC_WITH_WRONG_PASSWORD,
                            CLIENT_SUBJECT),
                            arguments(EstAuthenticationPolicy.CERTIFICATE_REGISTRATION,
                                    Presented.BASIC_OF_NO_REGISTRATION, CLIENT_SUBJECT),
                            arguments(EstAuthenticationPolicy.VENDOR_MTLS, Presented.UNTRUSTED_CERTIFICATE,
                                    CLIENT_SUBJECT),
                            arguments(EstAuthenticationPolicy.VENDOR_MTLS, Presented.TRUSTED_CLIENT_CERTIFICATE,
                                    subjectOfAnotherDevice),
                            arguments(EstAuthenticationPolicy.RA_MTLS, Presented.TRUSTED_CLIENT_CERTIFICATE,
                                    CLIENT_SUBJECT));
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * What a client presents: Basic credentials that match what the route holds or do not, a certificate that a trusted
     * CA issued or that none did, or a header that cannot be read. A trusted client certificate lacks the RA usage,
     * which a trusted RA certificate carries.
     */
    private enum Presented {
        NOTHING,
        BASIC_OF_A_SECRET,
        BASIC_WITH_WRONG_PASSWORD,
        BASIC_OF_A_REGISTRATION,
        BASIC_OF_NO_REGISTRATION,
        UNTRUSTED_CERTIFICATE,
        TRUSTED_CLIENT_CERTIFICATE,
        TRUSTED_RA_CERTIFICATE,
        MALFORMED_BASIC,
        MALFORMED_CERTIFICATE
    }

    /** The two headers by which a client presents credentials; {@code null} for one that it does not send. */
    private record Credentials(String authorization, String certificate) {

        /** What a client presents that sends the headers of both: this one's, completed by the other's. */
        Credentials and(Credentials other) {
            return new Credentials(authorization != null ? authorization : other.authorization(),
                    certificate != null ? certificate : other.certificate());
        }
    }

    private void seedRoute(EstAuthenticationPolicy policy) {
        seeder.seedEstProfile(LABEL, policy, raProfile, List.of(credentialSecret), List.of(trustedRoot));
    }

    private Credentials credentialsOf(Presented presented) {
        return switch (presented) {
            case NOTHING -> new Credentials(null, null);
            case BASIC_OF_A_SECRET -> basic(USERNAME, PASSWORD);
            case BASIC_WITH_WRONG_PASSWORD -> basic(USERNAME, WRONG_PASSWORD);
            case BASIC_OF_A_REGISTRATION -> basic(NO_USERNAME, CertificateRegistrationSeeder.CHALLENGE);
            case BASIC_OF_NO_REGISTRATION ->
                basic(UUID.randomUUID().toString(), CertificateRegistrationSeeder.CHALLENGE);
            case UNTRUSTED_CERTIFICATE -> new Credentials(null, certificateHeader(selfSignedClientCertificate()));
            case TRUSTED_CLIENT_CERTIFICATE ->
                new Credentials(null, certificateHeader(clientCertificate(issuingCa), issuingCa.certificate()));
            case TRUSTED_RA_CERTIFICATE ->
                new Credentials(null, certificateHeader(raCertificate(issuingCa), issuingCa.certificate()));
            case MALFORMED_BASIC -> new Credentials(malformedBasicAuthorization(), null);
            case MALFORMED_CERTIFICATE -> new Credentials(null, malformedCertificateHeader());
        };
    }

    private static Credentials basic(String username, String password) {
        return new Credentials(basicAuthorization(username, password), null);
    }

    private MockHttpServletResponse enroll(byte[] csr, Credentials credentials) throws Exception {
        MockHttpServletRequestBuilder enrollment = presenting(estPost(LABEL + "/simpleenroll", csr), credentials);
        return mockMvc.perform(enrollment).andReturn().getResponse();
    }

    private MockHttpServletRequestBuilder presenting(MockHttpServletRequestBuilder request, Credentials credentials) {
        if (credentials.authorization() != null) {
            request.header(HttpHeaders.AUTHORIZATION, credentials.authorization());
        }
        if (credentials.certificate() != null) {
            request.header(certificateHeaderName, credentials.certificate());
        }
        return request;
    }

    /** The answer is the plain text of the error, with the Basic challenge of the realm when the error asks for one. */
    private static void assertAnswered(MockHttpServletResponse response, EstError error) throws Exception {
        assertPlainTextError(response, error);
        String expectedChallenge = error.challenges() ? "Basic realm=\"" + LABEL + "\"" : null;
        assertThat(response.getHeader(HttpHeaders.WWW_AUTHENTICATE)).isEqualTo(expectedChallenge);
    }

    /**
     * Everything that a log must not reveal of a request: the request itself, each password that the tests use, and the
     * credentials as the client sent them, whole and in parts that a line could quote.
     */
    private static String[] secretsPresentedWith(byte[] csr, Credentials credentials) {
        List<String> secrets = new ArrayList<>(List
                .of(new String(csr, StandardCharsets.US_ASCII), PASSWORD, WRONG_PASSWORD,
                        CertificateRegistrationSeeder.CHALLENGE));
        if (credentials.authorization() != null) {
            secrets.add(credentials.authorization());
            secrets.add(credentials.authorization().substring(BASIC_SCHEME.length()));
        }
        if (credentials.certificate() != null) {
            secrets.add(credentials.certificate());
            secrets.addAll(Arrays.asList(credentials.certificate().split(",")));
        }
        return secrets.toArray(String[]::new);
    }
}

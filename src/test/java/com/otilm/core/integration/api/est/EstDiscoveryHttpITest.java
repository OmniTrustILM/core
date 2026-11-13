package com.otilm.core.integration.api.est;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.matching.RequestPatternBuilder;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.GeneralNameType;
import com.otilm.api.model.core.est.EstMediaTypes;
import com.otilm.api.model.core.logging.enums.AuditLogOutput;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.logging.records.LogRecord;
import com.otilm.api.model.core.logging.records.ResourceObjectIdentity;
import com.otilm.api.model.core.raprofile.AttributeSetMergeMode;
import com.otilm.api.model.core.settings.logging.AuditLoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.ResourceLoggingSettingsDto;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.Secret;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.messaging.model.AuditLogMessage;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.service.est.EstCaCertificates;
import com.otilm.core.service.est.impl.EstServiceImpl;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstRequestGuard;
import com.otilm.core.service.writer.RaProfileCertificateRequestAttributeWriter;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.core.util.EstCsrFixtures;
import com.otilm.core.util.SecretLeakProbe;
import com.otilm.core.util.seeders.SecretSeeder;
import jakarta.servlet.ServletContext;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.awaitility.Awaitility;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.request.AbstractMockHttpServletRequestBuilder;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import static com.otilm.core.util.EstClientCredentialsFixtures.basicAuthorization;
import static com.otilm.core.util.builders.DataAttributeV3Builder.aDataAttribute;
import static com.otilm.core.util.builders.MappedDataAttributeV3Builder.aMappedDataAttribute;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * The discovery operations, {@code /cacerts} and {@code /csrattrs}, over HTTP; what {@code /simpleenroll} answers a
 * client of an {@code raBasic} profile; and the refusals that every EST operation shares.
 */
class EstDiscoveryHttpITest extends AbstractEstHttpITest {

    private static final String V3_CA_CERTIFICATES = "/v3/authorityProvider/authorities/caCertificates";
    private static final String V3_REQUEST_ATTRIBUTES = "/v3/authorityProvider/certificates/request/attributes";
    private static final String CERTIFICATE_HEADER = "X-APP-CERTIFICATE";
    private static final ASN1ObjectIdentifier COMMON_NAME = new ASN1ObjectIdentifier("2.5.4.3");
    private static final String CONNECTOR_TEXT = "connector-internal-detail";
    private static final int SLOW_CONNECTOR_MILLIS = 2000;
    private static final int SAMPLES = 5;
    private static final String OPEN_TRANSACTIONS = "SELECT count(*) FROM pg_stat_activity "
            + "WHERE datname = current_database() AND pid <> pg_backend_pid() AND state = 'idle in transaction'";

    @Autowired
    private SettingExternalService settingService;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private SecretSeeder secretSeeder;

    @Autowired
    private RaProfileCertificateRequestAttributeWriter requestAttributeWriter;

    // ── CaCertificates ────────────────────────────────────────────────────────

    @Nested
    class CaCertificates {

        @Test
        void returnsCertsOnlyCms_whenCaCertificatesAreRequestedUnlabelled() throws Exception {
            // given
            List<X509Certificate> chain = generateChain();
            stubCaCertificates(chain);
            seeder.seedSystemDefault(saveRaProfile("devices-ra"));

            // when
            MockHttpServletResponse response = getFromEst("cacerts");

            // then
            assertCaCertificates(response, chain);
        }

        @Test
        void returnsCertsOnlyCms_whenCaCertificatesAreRequestedByRaProfileLabel() throws Exception {
            // given
            List<X509Certificate> chain = generateChain();
            stubCaCertificates(chain);
            var label = "devices-ra";
            seeder.activateEst(saveRaProfile(label), seeder.seedEstProfile("est-devices", true, null));

            // when
            MockHttpServletResponse response = getFromEst(label + "/cacerts");

            // then
            assertCaCertificates(response, chain);
        }

        @Test
        void leavesTheInventoryUntouched_whenCaCertificatesAreServed() throws Exception {
            // given
            stubCaCertificates(generateChain());
            seeder.seedSystemDefault(saveRaProfile("devices-ra"));

            // when
            MockHttpServletResponse response = getFromEst("cacerts");

            // then
            assertThat(response.getStatus()).isEqualTo(200);
            assertThat(certificateRepository.count()).isZero();
        }

        @Test
        void holdsNoTransactionOpen_whenTheConnectorIsAsked() throws Exception {
            // given
            stubCaCertificates(generateChain(), SLOW_CONNECTOR_MILLIS);
            seeder.seedSystemDefault(saveRaProfile("devices-ra"));

            // when
            CompletableFuture<MockHttpServletResponse> served = getFromEstInTheBackground("cacerts");
            List<Long> openTransactions = sampleOpenTransactionsWhileTheConnectorIsAsked(
                    WireMock.postRequestedFor(WireMock.urlPathMatching(CA_CERTIFICATES)));

            // then
            assertThat(openTransactions).contains(0L);
            assertThat(served.get(30, TimeUnit.SECONDS).getStatus()).isEqualTo(200);
        }

        @Test
        void answersServiceUnavailable_whenConnectorFails() throws Exception {
            // given
            connectorServer
                    .stubFor(WireMock
                            .post(WireMock.urlPathMatching(CA_CERTIFICATES))
                            .willReturn(WireMock.serverError().withBody(CONNECTOR_TEXT)));
            seeder.seedSystemDefault(saveRaProfile("devices-ra"));

            // when
            MockHttpServletResponse response = getFromEst("cacerts");

            // then
            assertPlainTextError(response, EstError.SERVICE_UNAVAILABLE);
        }

        @Test
        void answersServiceUnavailable_whenConnectorRefusesTheRequest() throws Exception {
            // given
            connectorServer
                    .stubFor(WireMock
                            .post(WireMock.urlPathMatching(CA_CERTIFICATES))
                            .willReturn(WireMock
                                    .status(422)
                                    .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                                    .withBody("[\"" + CONNECTOR_TEXT + "\"]")));
            seeder.seedSystemDefault(saveRaProfile("devices-ra"));

            // when
            MockHttpServletResponse response = getFromEst("cacerts");

            // then
            assertPlainTextError(response, EstError.SERVICE_UNAVAILABLE);
        }

        @Test
        void answersServiceUnavailable_whenAuthorityReturnsNoCertificates() throws Exception {
            // given
            stubCaCertificates(List.of());
            seeder.seedSystemDefault(saveRaProfile("devices-ra"));

            // when
            MockHttpServletResponse response = getFromEst("cacerts");

            // then
            assertPlainTextError(response, EstError.SERVICE_UNAVAILABLE);
        }

        @ParameterizedTest
        @MethodSource("undecodableConnectorAnswers")
        void answersServiceUnavailable_whenConnectorAnswerCannotBeDecoded(ResponseDefinitionBuilder connectorAnswer)
                throws Exception {
            // given
            connectorServer
                    .stubFor(WireMock.post(WireMock.urlPathMatching(CA_CERTIFICATES)).willReturn(connectorAnswer));
            seeder.seedSystemDefault(saveRaProfile("devices-ra"));

            // when
            MockHttpServletResponse response = getFromEst("cacerts");

            // then
            assertPlainTextError(response, EstError.SERVICE_UNAVAILABLE);
        }

        @ParameterizedTest
        @MethodSource("undecodableConnectorAnswers")
        void logsOnlyTheClassName_whenConnectorAnswerCannotBeDecoded(ResponseDefinitionBuilder connectorAnswer)
                throws Exception {
            // given
            connectorServer
                    .stubFor(WireMock.post(WireMock.urlPathMatching(CA_CERTIFICATES)).willReturn(connectorAnswer));
            RaProfile raProfile = saveRaProfile("devices-ra");
            seeder.seedSystemDefault(raProfile);

            try (LoggedBy logged = LoggedBy.capture(EstCaCertificates.class)) {
                // when
                getFromEst("cacerts");

                // then
                assertFailureLoggedByClassNameOnly(logged, raProfile, WebClientResponseException.class);
            }
        }

        @Test
        void answersServiceUnavailable_whenConnectorAnswersWithoutABody() throws Exception {
            // given
            connectorServer.stubFor(WireMock.post(WireMock.urlPathMatching(CA_CERTIFICATES)).willReturn(WireMock.ok()));
            seeder.seedSystemDefault(saveRaProfile("devices-ra"));

            // when
            MockHttpServletResponse response = getFromEst("cacerts");

            // then
            assertPlainTextError(response, EstError.SERVICE_UNAVAILABLE);
        }

        @Test
        void answersServiceUnavailable_whenV3ConnectorAnswersWithoutABody() throws Exception {
            // given
            connectorServer
                    .stubFor(WireMock.post(WireMock.urlPathEqualTo(V3_CA_CERTIFICATES)).willReturn(WireMock.ok()));
            seeder.seedSystemDefault(saveRaProfileOnV3Authority("devices-ra"));

            // when
            MockHttpServletResponse response = getFromEst("cacerts");

            // then
            assertPlainTextError(response, EstError.SERVICE_UNAVAILABLE);
        }

        @Test
        void recordsTheEstProfileOfTheRoute_whenCaCertificatesAreServed() throws Exception {
            // given
            turnOnAuditLogs(false);
            stubCaCertificates(generateChain());
            EstProfile estProfile = seeder.seedSystemDefault(saveRaProfile("devices-ra"));

            // when
            getFromEst("cacerts");

            // then
            LogRecord audited = protocolRecord();
            assertThat(audited.operation()).isEqualTo(Operation.GET_CHAIN);
            assertThat(audited.operationResult()).isEqualTo(OperationResult.SUCCESS);
            assertThat(audited.resource().type()).isEqualTo(Resource.CERTIFICATE);
            assertThat(audited.affiliatedResource().type()).isEqualTo(Resource.EST_PROFILE);
            assertThat(audited.affiliatedResource().objects())
                    .containsExactly(new ResourceObjectIdentity(estProfile.getName(), estProfile.getUuid()));
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        static Stream<Arguments> undecodableConnectorAnswers() {
            return Stream
                    .of(arguments(named("a type that nothing reads", answerOfATypeNothingReads())),
                            arguments(named("text that is not JSON", WireMock.ok(CONNECTOR_TEXT))));
        }
    }

    // ── CsrAttributes ─────────────────────────────────────────────────────────

    @Nested
    class CsrAttributes {

        @Test
        void returnsCsrAttrs_whenRaProfileRequestsSubjectAndSanFields() throws Exception {
            // given
            RaProfile raProfile = seeder.seedRaProfile("devices-ra");
            saveRequestAttributes(raProfile, AttributeSetMergeMode.STATIC_ONLY, commonName(), dnsName());
            seeder.seedSystemDefault(raProfile);

            // when
            MockHttpServletResponse response = getFromEst("csrattrs");

            // then
            assertCsrAttrsServed(response);
            ASN1Sequence csrAttrs = csrAttrsIn(response);
            assertThat(csrAttrs.size()).isEqualTo(2);
            assertThat(csrAttrs.getObjectAt(0)).isEqualTo(COMMON_NAME);
            Attribute extensionRequest = Attribute.getInstance(csrAttrs.getObjectAt(1));
            assertThat(extensionRequest.getAttrType()).isEqualTo(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
            assertThat(extensionRequest.getAttributeValues()).containsExactly(Extension.subjectAlternativeName);
        }

        @Test
        void returnsCsrAttrsOfTheRaProfileOfTheRoute_whenAnEstProfileLabelIsRequested() throws Exception {
            // given
            RaProfile defaultRaProfile = seeder.seedRaProfile("default-ra");
            saveRequestAttributes(defaultRaProfile, AttributeSetMergeMode.STATIC_ONLY, dnsName());
            seeder.seedSystemDefault(defaultRaProfile);
            var label = "est-devices";
            RaProfile routedRaProfile = seeder.seedRaProfile("devices-ra");
            saveRequestAttributes(routedRaProfile, AttributeSetMergeMode.STATIC_ONLY, commonName());
            seeder.seedEstProfile(label, true, routedRaProfile);

            // when
            MockHttpServletResponse response = getFromEst(label + "/csrattrs");

            // then
            assertCsrAttrsServed(response);
            assertThat(csrAttrsIn(response).toArray()).containsExactly(COMMON_NAME);
        }

        @Test
        void answersNoContent_whenRaProfileRequestsNothing() throws Exception {
            // given
            RaProfile raProfile = seeder.seedRaProfile("devices-ra");
            DataAttributeV3 notPartOfTheCertificate = aDataAttribute().withName("department").build();
            saveRequestAttributes(raProfile, AttributeSetMergeMode.STATIC_ONLY, notPartOfTheCertificate);
            seeder.seedSystemDefault(raProfile);

            // when
            MockHttpServletResponse response = getFromEst("csrattrs");

            // then
            assertThat(response.getStatus()).isEqualTo(204);
            assertThat(response.getContentAsByteArray()).isEmpty();
        }

        @Test
        void returnsPlatformDefaultCsrAttrs_whenConnectorAnswersWithoutABody() throws Exception {
            // given
            seedRouteWhoseAttributeSetComesFromTheConnector(WireMock.ok());

            // when
            MockHttpServletResponse response = getFromEst("csrattrs");

            // then
            assertCsrAttrsServed(response);
            assertThat(csrAttrsIn(response).toArray()).contains(COMMON_NAME);
        }

        @Test
        void holdsNoTransactionOpen_whenTheConnectorIsAsked() throws Exception {
            // given
            seedRouteWhoseAttributeSetComesFromTheConnector(
                    WireMock.okJson("[]").withFixedDelay(SLOW_CONNECTOR_MILLIS));

            // when
            CompletableFuture<MockHttpServletResponse> served = getFromEstInTheBackground("csrattrs");
            List<Long> openTransactions = sampleOpenTransactionsWhileTheConnectorIsAsked(
                    WireMock.postRequestedFor(WireMock.urlPathEqualTo(V3_REQUEST_ATTRIBUTES)));

            // then
            assertThat(openTransactions).contains(0L);
            assertThat(served.get(30, TimeUnit.SECONDS).getStatus()).isEqualTo(200);
        }

        @ParameterizedTest
        @MethodSource({"failingConnectorAnswers", "undecodableConnectorAnswers"})
        void answersServiceUnavailable_whenAttributeSetCannotBeResolved(ResponseDefinitionBuilder connectorAnswer)
                throws Exception {
            // given
            seedRouteWhoseAttributeSetComesFromTheConnector(connectorAnswer);

            // when
            MockHttpServletResponse response = getFromEst("csrattrs");

            // then
            assertPlainTextError(response, EstError.SERVICE_UNAVAILABLE);
            connectorServer.verify(WireMock.postRequestedFor(WireMock.urlPathEqualTo(V3_REQUEST_ATTRIBUTES)));
        }

        @ParameterizedTest
        @MethodSource("failingConnectorAnswers")
        void logsNoTextOfTheConnector_whenAttributeSetCannotBeResolved(ResponseDefinitionBuilder connectorAnswer)
                throws Exception {
            // given
            seedRouteWhoseAttributeSetComesFromTheConnector(connectorAnswer);

            try (SecretLeakProbe probe = SecretLeakProbe.capture()) {
                // when
                getFromEst("csrattrs");

                // then
                SecretLeakProbe.assertNoneReveals(probe.logged(), CONNECTOR_TEXT);
            }
        }

        @ParameterizedTest
        @MethodSource("undecodableConnectorAnswers")
        void logsOnlyTheClassName_whenConnectorAnswerCannotBeDecoded(ResponseDefinitionBuilder connectorAnswer)
                throws Exception {
            // given
            RaProfile raProfile = seedRouteWhoseAttributeSetComesFromTheConnector(connectorAnswer);

            try (LoggedBy logged = LoggedBy.capture(EstServiceImpl.class)) {
                // when
                getFromEst("csrattrs");

                // then
                assertFailureLoggedByClassNameOnly(logged, raProfile, WebClientResponseException.class);
            }
        }

        @Test
        void answersServiceUnavailable_whenAttributeSetNamesAnUnknownRdnCode() throws Exception {
            // given
            var unknownRdnCode = "NO-SUCH-RDN";
            RaProfile raProfile = seeder.seedRaProfile("devices-ra");
            DataAttributeV3 unresolvable = aMappedDataAttribute()
                    .withName("unknown")
                    .mappingRdn(unknownRdnCode)
                    .build();
            saveRequestAttributes(raProfile, AttributeSetMergeMode.STATIC_ONLY, unresolvable);
            seeder.seedSystemDefault(raProfile);

            // when
            MockHttpServletResponse response = getFromEst("csrattrs");

            // then
            assertPlainTextError(response, EstError.SERVICE_UNAVAILABLE);
        }

        @Test
        void ignoresCredentials_whenCsrAttrsAreRequested() throws Exception {
            // given
            RaProfile raProfile = seeder.seedRaProfile("devices-ra");
            saveRequestAttributes(raProfile, AttributeSetMergeMode.STATIC_ONLY, commonName());
            seeder.seedSystemDefault(raProfile);
            var basicCredentials = "Basic "
                    + Base64.getEncoder().encodeToString("client:wrong-password".getBytes(StandardCharsets.UTF_8));
            var notACertificate = "not-a-certificate";

            // when
            MockHttpServletResponse response = mockMvc
                    .perform(get(EST_BASE + "csrattrs")
                            .contextPath(CONTEXT_PATH)
                            .header(HttpHeaders.AUTHORIZATION, basicCredentials)
                            .header(CERTIFICATE_HEADER, notACertificate))
                    .andReturn()
                    .getResponse();

            // then
            assertCsrAttrsServed(response);
            assertThat(csrAttrsIn(response).toArray()).containsExactly(COMMON_NAME);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        static Stream<Arguments> failingConnectorAnswers() {
            return Stream
                    .of(arguments(named("a server error", WireMock.serverError().withBody(CONNECTOR_TEXT))),
                            arguments(named("a refusal",
                                    WireMock
                                            .status(422)
                                            .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                                            .withBody("[\"" + CONNECTOR_TEXT + "\"]"))));
        }

        static Stream<Arguments> undecodableConnectorAnswers() {
            return Stream
                    .of(arguments(named("a type that nothing reads", answerOfATypeNothingReads())),
                            arguments(named("an object where a list is expected",
                                    WireMock.okJson("{\"" + CONNECTOR_TEXT + "\": 1}"))),
                            arguments(named("text that is not JSON", WireMock.ok(CONNECTOR_TEXT))));
        }
    }

    // ── SimpleEnrollment ──────────────────────────────────────────────────────

    @Nested
    class SimpleEnrollment {

        private static final String LABEL = "devices";
        private static final String USERNAME = "device-owner";
        private static final String PASSWORD = "p4ssw0rd";

        @Test
        void answersUnauthorizedWithChallenge_whenRaBasicClientPresentsNoCredentials() throws Exception {
            // given
            seedRaBasicRoute();
            byte[] body = EstCsrFixtures.signedRequestBody();

            // when
            MockHttpServletResponse response = postToEst(LABEL + "/simpleenroll", body);

            // then
            assertPlainTextError(response, EstError.UNAUTHORIZED);
            assertThat(response.getHeader(HttpHeaders.WWW_AUTHENTICATE))
                    .isEqualTo("Basic realm=\"" + LABEL + "\", charset=\"UTF-8\"");
        }

        @Test
        void answersUnavailable_whenRaBasicCredentialsMatchAReferencedSecretAndConnectorIsUnreachable()
                throws Exception {
            // given
            seedRaBasicRoute();
            byte[] body = EstCsrFixtures.signedRequestBody();

            // when
            MockHttpServletResponse response = postToEst(LABEL + "/simpleenroll", body,
                    basicAuthorization(USERNAME, PASSWORD));

            // then
            assertPlainTextError(response, EstError.SERVICE_UNAVAILABLE);
        }

        private void seedRaBasicRoute() {
            Secret credential = secretSeeder.seedBasicAuthSecret("ra-credential", USERNAME, PASSWORD);
            seeder.seedRaBasicEstProfile(LABEL, saveRaProfile("devices-ra"), credential);
        }
    }

    // ── Refusals ──────────────────────────────────────────────────────────────

    @Nested
    class Refusals {

        @Test
        void answersNotFoundAsPlainText_whenLabelIsUnknown() throws Exception {
            // given
            var unknownLabel = "unknown-label";
            seeder.seedSystemDefault(saveRaProfile("devices-ra"));

            // when
            MockHttpServletResponse response = getFromEst(unknownLabel + "/cacerts");

            // then
            assertPlainTextError(response, EstError.NOT_FOUND);
        }

        @Test
        void answersNotFound_whenLabelMatchesBothAnEstProfileAndAnRaProfile() throws Exception {
            // given
            var sharedLabel = "devices";
            seeder.seedEstProfile(sharedLabel, true, seeder.seedRaProfile("default-ra"));
            seeder.activateEst(seeder.seedRaProfile(sharedLabel), seeder.seedEstProfile("est-activated", true, null));

            // when
            MockHttpServletResponse response = getFromEst(sharedLabel + "/cacerts");

            // then
            assertPlainTextError(response, EstError.NOT_FOUND);
        }

        @Test
        void answersMethodNotAllowed_whenCaCertificatesArePosted() throws Exception {
            // given
            seeder.seedSystemDefault(saveRaProfile("devices-ra"));

            // when
            MockHttpServletResponse response = mockMvc
                    .perform(post(EST_BASE + "cacerts").contextPath(CONTEXT_PATH))
                    .andReturn()
                    .getResponse();

            // then
            assertPlainTextError(response, EstError.METHOD_NOT_ALLOWED);
            assertThat(response.getHeader(HttpHeaders.ALLOW)).isEqualTo("GET");
        }

        @Test
        void answersPayloadTooLarge_whenUndeclaredBodyExceedsTheLimit() throws Exception {
            // given
            byte[] bodyOverTheLimit = new byte[EstRequestGuard.MAX_BODY_BYTES + 1];
            Arrays.fill(bodyOverTheLimit, (byte) 'A');
            RequestBuilder enrollmentWithUndeclaredLength = new UndeclaredLengthPostBuilder(EST_BASE + "simpleenroll")
                    .contextPath(CONTEXT_PATH)
                    .contentType(EstMediaTypes.PKCS10)
                    .content(bodyOverTheLimit);

            // when
            MockHttpServletResponse response = mockMvc
                    .perform(enrollmentWithUndeclaredLength)
                    .andReturn()
                    .getResponse();

            // then
            assertPlainTextError(response, EstError.PAYLOAD_TOO_LARGE);
        }

        @Test
        void answersBadRequest_whenEnrollmentBodyIsEmpty() throws Exception {
            // given
            seeder.seedSystemDefault(saveRaProfile("devices-ra"));
            byte[] noBody = new byte[0];

            // when
            MockHttpServletResponse response = postToEst("simpleenroll", noBody);

            // then
            assertPlainTextError(response, EstError.BAD_REQUEST);
        }

        @Test
        void answersBadRequest_whenReenrollmentBodyIsNotARequest() throws Exception {
            // given
            seeder.seedSystemDefault(saveRaProfile("devices-ra"));
            byte[] notARequest = "AAAA".getBytes(StandardCharsets.US_ASCII);

            // when
            MockHttpServletResponse response = postToEst("simplereenroll", notARequest);

            // then
            assertPlainTextError(response, EstError.BAD_REQUEST);
        }

        @Test
        void answersForbiddenBeforeDecoding_whenServerKeyGenerationIsNotEnabled() throws Exception {
            // given — the system default EST Profile does not generate keys
            seeder.seedSystemDefault(saveRaProfile("devices-ra"));
            byte[] notARequest = "AAAA".getBytes(StandardCharsets.US_ASCII);

            // when
            MockHttpServletResponse response = postToEst("serverkeygen", notARequest);

            // then
            assertPlainTextError(response, EstError.SERVER_KEYGEN_DISABLED);
        }

        @Test
        void keepsTheRequestBodyOutOfTheAuditRecord_whenAuditLogsAreVerbose() throws Exception {
            // given — a request that the re-enrolment refuses, as the client presents no certificate to renew
            turnOnAuditLogs(true);
            var label = "devices";
            seeder.seedEstProfile(label, true, saveRaProfile("devices-ra"));
            byte[] requestBody = EstCsrFixtures.signedRequestBody();

            // when
            postToEst(label + "/simplereenroll", requestBody);

            // then
            LogRecord audited = protocolRecord();
            assertThat(audited.additionalData()).containsEntry("label", label);
            assertThat(ObjectMapperFactory.auditLog().writeValueAsString(audited.additionalData()))
                    .doesNotContain(new String(requestBody, StandardCharsets.US_ASCII))
                    .doesNotContain(Base64.getEncoder().encodeToString(requestBody));
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private CompletableFuture<MockHttpServletResponse> getFromEstInTheBackground(String operationPath) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return getFromEst(operationPath);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
    }

    private static void assertCaCertificates(MockHttpServletResponse response, List<X509Certificate> chain)
            throws Exception {
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(MediaType.parseMediaType(response.getContentType()))
                .isEqualTo(MediaType.parseMediaType(EstMediaTypes.PKCS7_MIME));
        assertThat(response.getHeader("Content-Transfer-Encoding")).isEqualTo("base64");
        assertThat(certificatesIn(response)).containsExactlyInAnyOrderElementsOf(chain);
    }

    private static void assertCsrAttrsServed(MockHttpServletResponse response) {
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(MediaType.parseMediaType(response.getContentType()))
                .isEqualTo(MediaType.parseMediaType(EstMediaTypes.CSR_ATTRS));
        assertThat(response.getHeader("Content-Transfer-Encoding")).isEqualTo("base64");
    }

    private static ASN1Sequence csrAttrsIn(MockHttpServletResponse response) {
        return ASN1Sequence.getInstance(Base64.getMimeDecoder().decode(response.getContentAsByteArray()));
    }

    private static DataAttributeV3 commonName() {
        return aMappedDataAttribute().withName("cn").mappingRdn("CN").build();
    }

    private static DataAttributeV3 dnsName() {
        return aMappedDataAttribute().withName("fqdn").mappingSan(GeneralNameType.DNS).build();
    }

    private void saveRequestAttributes(RaProfile raProfile, AttributeSetMergeMode mergeMode,
            DataAttributeV3... definitions) {
        requestAttributeWriter
                .saveStaticSet(raProfile, AttributeDefinitionUtils.serialize(List.of(definitions)), mergeMode, null);
    }

    /**
     * The system default route, whose RA Profile takes the attributes of a certificate request from its authority. Only
     * a v3 connector is asked: a v2 authority serves none.
     */
    private RaProfile seedRouteWhoseAttributeSetComesFromTheConnector(ResponseDefinitionBuilder connectorAnswer) {
        connectorServer
                .stubFor(WireMock.post(WireMock.urlPathEqualTo(V3_REQUEST_ATTRIBUTES)).willReturn(connectorAnswer));
        RaProfile raProfile = saveRaProfileOnV3Authority("devices-ra");
        saveRequestAttributes(raProfile, AttributeSetMergeMode.CONNECTOR_ONLY);
        seeder.seedSystemDefault(raProfile);
        return raProfile;
    }

    /** A good answer whose content type is the text of the connector: no reader accepts it, and a message quotes it. */
    private static ResponseDefinitionBuilder answerOfATypeNothingReads() {
        return WireMock.ok("[]").withHeader(HttpHeaders.CONTENT_TYPE, "x/" + CONNECTOR_TEXT);
    }

    private static void assertFailureLoggedByClassNameOnly(LoggedBy logged, RaProfile raProfile, Class<?> failure) {
        assertThat(logged.events()).singleElement().satisfies(event -> {
            assertThat(event.getLevel()).isEqualTo(Level.ERROR);
            assertThat(event.getFormattedMessage())
                    .contains(raProfile.getUuid().toString())
                    .contains(failure.getName())
                    .doesNotContain(CONNECTOR_TEXT);
            assertThat(event.getThrowableProxy()).isNull();
        });
    }

    private static List<X509Certificate> certificatesIn(MockHttpServletResponse response) throws Exception {
        CMSSignedData signedData = new CMSSignedData(Base64.getMimeDecoder().decode(response.getContentAsByteArray()));
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        List<X509Certificate> certificates = new ArrayList<>();
        for (X509CertificateHolder holder : signedData.getCertificates().getMatches(null)) {
            certificates.add(converter.getCertificate(holder));
        }
        return certificates;
    }

    /**
     * A transaction held across the connector call is an idle session of the database for as long as the connector
     * takes, in every sample. One that another thread holds briefly is not, so a single sample without an open
     * transaction shows that this request holds none.
     */
    private List<Long> sampleOpenTransactionsWhileTheConnectorIsAsked(RequestPatternBuilder connectorRequest) {
        Awaitility
                .await()
                .atMost(Duration.ofSeconds(10))
                .until(() -> !connectorServer.findAll(connectorRequest).isEmpty());
        List<Long> samples = new ArrayList<>();
        Awaitility.await().atMost(Duration.ofSeconds(10)).pollInterval(Duration.ofMillis(100)).until(() -> {
            samples.add(jdbcTemplate.queryForObject(OPEN_TRANSACTIONS, Long.class));
            return samples.size() >= SAMPLES;
        });
        return samples;
    }

    private void turnOnAuditLogs(boolean verbose) {
        AuditLoggingSettingsDto auditLogs = new AuditLoggingSettingsDto();
        auditLogs.setOutput(AuditLogOutput.ALL);
        auditLogs.setLogAllModules(true);
        auditLogs.setLogAllResources(true);
        auditLogs.setVerbose(verbose);
        LoggingSettingsDto settings = new LoggingSettingsDto();
        settings.setAuditLogs(auditLogs);
        settings.setEventLogs(new ResourceLoggingSettingsDto());
        settingService.updateLoggingSettings(settings);
    }

    private LogRecord protocolRecord() {
        ArgumentCaptor<AuditLogMessage> messages = ArgumentCaptor.forClass(AuditLogMessage.class);
        verify(auditLogsProducer, atLeastOnce()).produceMessage(messages.capture());
        return messages
                .getAllValues()
                .stream()
                .map(AuditLogMessage::getLogRecord)
                .filter(logRecord -> logRecord.module() == Module.PROTOCOLS)
                .reduce((first, second) -> second)
                .orElseThrow(() -> new AssertionError("No audit record of the protocols module"));
    }

    /** An RA Profile whose authority speaks the v3 connector interface, with the WireMock server as its connector. */
    private RaProfile saveRaProfileOnV3Authority(String name) {
        return seeder.seedRaProfileOnV3Authority(connectorServer, name);
    }

    /**
     * What one class logs while it is captured. The capture is limited to one class because the interfaces client logs
     * an answer that it cannot decode itself, so everything the platform logs would show text that Core cannot keep
     * out. The logger of a class is a process-wide singleton, so closing the capture takes its appender off again.
     */
    private static final class LoggedBy implements AutoCloseable {

        private final Logger logger;
        private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

        private LoggedBy(Class<?> source) {
            logger = (Logger) LoggerFactory.getLogger(source);
            appender.start();
            logger.addAppender(appender);
        }

        static LoggedBy capture(Class<?> source) {
            return new LoggedBy(source);
        }

        List<ILoggingEvent> events() {
            return appender.list;
        }

        @Override
        public void close() {
            logger.detachAppender(appender);
            appender.stop();
        }
    }

    /**
     * A POST whose request reports no length, as one with a chunked body does: the request is built from the abstract
     * builder because the concrete one cannot be extended.
     */
    private static final class UndeclaredLengthPostBuilder
            extends
                AbstractMockHttpServletRequestBuilder<UndeclaredLengthPostBuilder> {

        UndeclaredLengthPostBuilder(String uriTemplate) {
            super(HttpMethod.POST);
            uri(uriTemplate);
            header(HttpHeaders.TRANSFER_ENCODING, "chunked");
        }

        @Override
        protected MockHttpServletRequest createServletRequest(ServletContext servletContext) {
            return new MockHttpServletRequest(servletContext) {
                @Override
                public int getContentLength() {
                    return -1;
                }
            };
        }
    }
}

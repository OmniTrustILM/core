package com.otilm.core.integration.service.v3;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.core.certificate.type.AuthorityCertificateTypes;
import com.otilm.core.certificate.type.CertificateTypesUnavailableException;
import com.otilm.core.certificate.type.UnsupportedCertificateTypeException;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.service.v2.ExtendedAttributeService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.builders.AuthorityFixtures;
import com.otilm.core.util.builders.V3ConnectorStubs;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * The renew, identify and request attribute schemas are optional v3 endpoints. A connector that does not serve them may
 * answer with a {@code RESOURCE_NOT_FOUND} problem document instead of a bare 404 (ms-adcs-ng and DLM route every
 * unmatched path that way); Core must resolve an empty schema, as it does for a bare 404, so renew, rekey, RA profile
 * switch, manual issue and request-attribute resolution keep working.
 */
class V3OptionalSchemaITest extends BaseSpringBootTest {

    private static final String RENEW_ATTRIBUTES_PATH = "/v3/authorityProvider/certificates/renew/attributes";
    private static final String IDENTIFY_ATTRIBUTES_PATH = "/v3/authorityProvider/certificates/identify/attributes";
    private static final String REQUEST_ATTRIBUTES_PATH = "/v3/authorityProvider/certificates/request/attributes";
    private static final String CERTIFICATE_TYPES_PATH = "/v3/authorityProvider/authorities/certificateTypes";
    private static final String NOT_FOUND_PROBLEM = """
            {
              "type": "https://docs.otilm.com/problems/common/RESOURCE_NOT_FOUND",
              "title": "Resource not found",
              "status": 404,
              "detail": "No endpoint matched the request path.",
              "errorCode": "RESOURCE_NOT_FOUND",
              "timestamp": "2026-09-28T10:00:00Z",
              "retryable": false
            }
            """;

    @Autowired
    private ExtendedAttributeService extendedAttributeService;
    @Autowired
    private AuthorityCertificateTypes authorityCertificateTypes;

    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;

    private WireMockServer wireMockServer;
    private AuthorityFixtures.Fixture fixture;

    @BeforeEach
    void setUp() {
        wireMockServer = new WireMockServer(LoopbackWireMock.options());
        wireMockServer.start();
        WireMock.configureFor(LoopbackWireMock.HOST, wireMockServer.port());
        fixture = AuthorityFixtures
                .v3Authority(new AuthorityFixtures.Repos(connectorRepository, functionGroupRepository,
                        connector2FunctionGroupRepository, authorityInstanceReferenceRepository, raProfileRepository,
                        connectorInterfaceRepository), wireMockServer);
        V3ConnectorStubs.stubAttributesAndValidate(wireMockServer);
        for (String path : List.of(RENEW_ATTRIBUTES_PATH, IDENTIFY_ATTRIBUTES_PATH, REQUEST_ATTRIBUTES_PATH)) {
            wireMockServer
                    .stubFor(post(urlEqualTo(path))
                            .willReturn(aResponse()
                                    .withStatus(404)
                                    .withHeader("Content-Type", "application/problem+json")
                                    .withBody(NOT_FOUND_PROBLEM)));
        }
    }

    @AfterEach
    void tearDown() {
        wireMockServer.stop();
    }

    @Test
    void renewSchemaNotFoundProblem_validatesAgainstEmptySchema() {
        Assertions
                .assertDoesNotThrow(
                        () -> extendedAttributeService.mergeAndValidateRenewAttributes(fixture.raProfile(), List.of()),
                        "renew and rekey validate against the renew schema before any successor exists");
        wireMockServer.verify(1, postRequestedFor(urlEqualTo(RENEW_ATTRIBUTES_PATH)));
    }

    @Test
    void identifySchemaNotFoundProblem_validatesAgainstEmptySchema() {
        Assertions
                .assertDoesNotThrow(
                        () -> extendedAttributeService
                                .mergeAndValidateIdentifyAttributes(fixture.raProfile(), List.of()),
                        "an RA profile switch validates against the identify schema of the target profile");
        wireMockServer.verify(1, postRequestedFor(urlEqualTo(IDENTIFY_ATTRIBUTES_PATH)));
    }

    @Test
    void requestSchemaNotFoundProblem_resolvesEmptySchema() throws Exception {
        Assertions
                .assertEquals(List.of(),
                        extendedAttributeService.listCertificateRequestAttributes(fixture.raProfile()));
        wireMockServer.verify(1, postRequestedFor(urlEqualTo(REQUEST_ATTRIBUTES_PATH)));
    }

    // ── CertificateTypes ──────────────────────────────────────────────────────

    @Nested
    class CertificateTypes {

        @Test
        void reportsTheListedTypes_whenTheConnectorServesTheOperation() throws Exception {
            // given
            stubCertificateTypes(okJson("[{\"certificateType\":\"SSH\"}]"));

            // when
            Set<CertificateType> types = authorityCertificateTypes.supportedTypes(fixture.raProfile().getUuid());

            // then
            assertThat(types).containsExactly(CertificateType.SSH);
        }

        @Test
        void refusesX509_whenTheConnectorListsOnlyAnotherType() {
            // given
            stubCertificateTypes(okJson("[{\"certificateType\":\"SSH\"}]"));

            // when
            ThrowingCallable check = () -> authorityCertificateTypes
                    .requireSupport(CertificateType.X509, fixture.raProfile());

            // then
            assertThatThrownBy(check)
                    .isInstanceOf(UnsupportedCertificateTypeException.class)
                    .hasMessageContaining(fixture.raProfile().getName());
        }

        @Test
        void reportsX509Only_whenTheConnectorDoesNotServeTheOperation() throws Exception {
            // given — the connector has no route for the certificate types, so it answers 404

            // when
            Set<CertificateType> types = authorityCertificateTypes.supportedTypes(fixture.raProfile().getUuid());

            // then
            assertThat(types).containsExactly(CertificateType.X509);
            wireMockServer.verify(1, postRequestedFor(urlEqualTo(CERTIFICATE_TYPES_PATH)));
        }

        @ParameterizedTest
        @MethodSource("answersListingNothing")
        void reportsX509Only_whenTheConnectorListsNothing(ResponseDefinitionBuilder listingNothing) throws Exception {
            // given
            stubCertificateTypes(listingNothing);

            // when
            Set<CertificateType> types = authorityCertificateTypes.supportedTypes(fixture.raProfile().getUuid());

            // then
            assertThat(types).containsExactly(CertificateType.X509);
        }

        @Test
        void refusesWithoutTheConnectorsWords_whenTheConnectorFails() {
            // given
            var connectorText = "text written by the connector";
            stubCertificateTypes(aResponse().withStatus(500).withBody(connectorText));

            // when
            ThrowingCallable check = () -> authorityCertificateTypes
                    .requireSupport(CertificateType.X509, fixture.raProfile());

            // then
            assertThatThrownBy(check)
                    .isInstanceOf(CertificateTypesUnavailableException.class)
                    .hasMessageContaining(fixture.raProfile().getName())
                    .hasMessageNotContaining(connectorText);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        static Stream<Arguments> answersListingNothing() {
            return Stream
                    .of(arguments(named("an empty list", okJson("[]"))), arguments(named("no body",
                            aResponse().withStatus(200).withHeader("Content-Type", "application/json"))));
        }

        private void stubCertificateTypes(ResponseDefinitionBuilder answer) {
            wireMockServer.stubFor(post(urlEqualTo(CERTIFICATE_TYPES_PATH)).willReturn(answer));
        }
    }
}

package com.otilm.core.integration.service.v3;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.builders.AuthorityFixtures;
import com.otilm.core.util.builders.V3ConnectorStubs;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;

/**
 * Integration test for the identify half of the operation-attribute round trip: values submitted with an RA-profile
 * switch are validated against the connector's identify schema, carried on the identify wire, and surface on the
 * certificate detail.
 */
class V3IdentifyITest extends BaseSpringBootTest {

    private static final String V3_IDENTIFY_PATH = "/v3/authorityProvider/certificates/identify";
    private static final String V3_IDENTIFY_ATTRIBUTES_PATH = "/v3/authorityProvider/certificates/identify/attributes";

    @Autowired
    private CertificateInternalService certificateInternalService;
    @Autowired
    private CertificateExternalService certificateExternalService;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;

    // Fixture builder repos
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

    @BeforeEach
    void setUpWireMock() {
        wireMockServer = new WireMockServer(LoopbackWireMock.options());
        wireMockServer.start();
        WireMock.configureFor(LoopbackWireMock.HOST, wireMockServer.port());
    }

    @AfterEach
    void tearDownWireMock() {
        wireMockServer.stop();
    }

    @Test
    void raProfileSwitch_carriesIdentifyAttributeValuesOnTheWireAndDetail() throws Exception {
        AuthorityFixtures.Fixture fixture = AuthorityFixtures
                .v3Authority(new AuthorityFixtures.Repos(connectorRepository, functionGroupRepository,
                        connector2FunctionGroupRepository, authorityInstanceReferenceRepository, raProfileRepository,
                        connectorInterfaceRepository), wireMockServer);
        V3ConnectorStubs.stubAttributesAndValidate(wireMockServer);
        wireMockServer
                .stubFor(post(urlEqualTo(V3_IDENTIFY_ATTRIBUTES_PATH))
                        .willReturn(
                                aResponse().withStatus(200).withHeader("Content-Type", "application/json").withBody("""
                                        [ {
                                          "uuid": "2c8f3d4b-0000-4000-8000-000000000001",
                                          "name": "agentReference",
                                          "type": "data",
                                          "version": 3,
                                          "contentType": "string",
                                          "properties": { "label": "Agent Reference", "visible": true,
                                                          "required": false, "readOnly": false,
                                                          "list": false, "multiSelect": false }
                                        } ]
                                        """)));
        wireMockServer
                .stubFor(post(urlEqualTo(V3_IDENTIFY_PATH))
                        .willReturn(aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"meta\": []}")));

        CertificateContent content = certificateContentRepository.save(new CertificateContent());
        Certificate certificate = new Certificate();
        certificate.setSubjectDn("CN=identify-" + UUID.randomUUID());
        certificate.setIssuerDn("CN=test-issuer");
        certificate.setSerialNumber(UUID.randomUUID().toString());
        certificate.setCertificateContent(content);
        certificate.setCertificateContentId(content.getId());
        certificate.setState(CertificateState.ISSUED);
        certificate.setValidationStatus(CertificateValidationStatus.VALID);
        certificate = certificateRepository.save(certificate);

        RequestAttributeV3 identifyValue = new RequestAttributeV3(
                UUID.fromString("2c8f3d4b-0000-4000-8000-000000000001"), "agentReference", AttributeContentType.STRING,
                List.of(new StringAttributeContentV3("agent-42")));
        certificateInternalService
                .switchRaProfile(certificate.getSecuredUuid(), fixture.raProfile().getSecuredUuid(),
                        List.of(identifyValue));

        wireMockServer
                .verify(1, postRequestedFor(urlEqualTo(V3_IDENTIFY_PATH))
                        .withRequestBody(matchingJsonPath("$.attributes[0].name", equalTo("agentReference")))
                        .withRequestBody(matchingJsonPath("$.attributes[0].content[0].data", equalTo("agent-42"))));

        // The submitted values surface on the certificate detail, keyed to the new authority's connector.
        CertificateDetailDto detail = certificateExternalService
                .getCertificate(SecuredUUID.fromUUID(certificate.getUuid()));
        Assertions
                .assertEquals(1, detail.getIdentifyAttributes().size(),
                        "identify attributes must surface on the certificate detail");
        Assertions.assertEquals("agentReference", detail.getIdentifyAttributes().getFirst().getName());
    }
}

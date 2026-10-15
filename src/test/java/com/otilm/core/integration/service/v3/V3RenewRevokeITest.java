package com.otilm.core.integration.service.v3;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.certificate.CertificateRelationType;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.v2.ClientCertificateRekeyRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRevocationDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeOperation;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.CertificateRelation;
import com.otilm.core.dao.entity.CertificateRequestEntity;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRelationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CertificateRequestRepository;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.service.v2.ExtendedAttributeService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateTestUtil;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.builders.AuthorityFixtures;
import com.otilm.core.util.builders.CertificateRequestEntityBuilder;
import com.otilm.core.util.builders.V3ConnectorStubs;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.absent;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;

/**
 * Integration tests for renew and revoke against a v3 authority. These operations dispatch through
 * {@code AuthorityProviderAdapterFactory}; a v3 authority does not serve the v2 endpoints, so the tests pin that the
 * request lands on the v3 wire and never on the v2 endpoints.
 */
class V3RenewRevokeITest extends BaseSpringBootTest {

    private static final String V3_RENEW_PATH = "/v3/authorityProvider/certificates/renew";
    private static final String V3_RENEW_ATTRIBUTES_PATH = "/v3/authorityProvider/certificates/renew/attributes";
    private static final String V3_REVOKE_PATH = "/v3/authorityProvider/certificates/revoke";
    private static final String V2_RENEW_PATTERN = "/v2/authorityProvider/authorities/[^/]+/certificates/renew";
    private static final String V2_REVOKE_PATTERN = "/v2/authorityProvider/authorities/[^/]+/certificates/revoke";

    @Autowired
    private ClientOperationInternalService clientOperationInternalService;
    @Autowired
    private CertificateExternalService certificateExternalService;
    @Autowired
    private ExtendedAttributeService extendedAttributeService;
    @Autowired
    private AttributeEngine attributeEngine;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private CertificateRequestRepository certificateRequestRepository;
    @Autowired
    private CertificateRelationRepository certificateRelationRepository;

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
    void renew_async202_parksSuccessorPendingIssue_viaV3_notV2() throws Exception {
        AuthorityFixtures.Fixture fixture = buildV3Fixture();
        V3ConnectorStubs.stubAttributesAndValidate(wireMockServer);
        UUID predecessorUuid = seedRenewalPair(fixture);
        UUID successorUuid = successorUuid(predecessorUuid);

        wireMockServer
                .stubFor(post(urlEqualTo(V3_RENEW_PATH))
                        .willReturn(aResponse()
                                .withStatus(202)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"certificateData\": null, \"meta\": []}")));

        Assertions
                .assertDoesNotThrow(() -> clientOperationInternalService
                        .renewCertificateAction(successorUuid, ClientCertificateRenewRequestDto.builder().build(),
                                true));

        Assertions
                .assertEquals(CertificateState.PENDING_ISSUE, reloadCert(successorUuid).getState(),
                        "an accepted async v3 renew (202) must park the successor in PENDING_ISSUE");
        Assertions
                .assertEquals(CertificateState.ISSUED, reloadCert(predecessorUuid).getState(),
                        "the predecessor must stay ISSUED while the successor awaits asynchronous completion");
        wireMockServer.verify(1, postRequestedFor(urlEqualTo(V3_RENEW_PATH)));
        wireMockServer.verify(0, postRequestedFor(urlPathMatching(V2_RENEW_PATTERN)));
    }

    @Test
    void renew_carriesSeededRequestContent_whenConnectorAdvertisesStructured() throws Exception {
        AuthorityFixtures.Fixture fixture = AuthorityFixtures
                .v3Authority(repos(), wireMockServer, FeatureFlag.CERTIFICATE_REQUEST_STRUCTURED);
        V3ConnectorStubs.stubAttributesAndValidate(wireMockServer);
        UUID predecessorUuid = seedRenewalPairWithRealPredecessor(fixture);
        UUID successorUuid = successorUuid(predecessorUuid);
        stubRenewSchemaAndAccept();

        Assertions
                .assertDoesNotThrow(() -> clientOperationInternalService
                        .renewCertificateAction(successorUuid, ClientCertificateRenewRequestDto.builder().build(),
                                true));

        wireMockServer
                .verify(1,
                        postRequestedFor(urlEqualTo(V3_RENEW_PATH))
                                .withRequestBody(matchingJsonPath("$.requestContent.certificateType", equalTo("X.509")))
                                .withRequestBody(matchingJsonPath("$.requestContent.subject[0].type", equalTo("CN")))
                                .withRequestBody(matchingJsonPath("$.requestContent.subject[0].value",
                                        equalTo("predecessor.example.com")))
                                .withRequestBody(matchingJsonPath("$.requestContent.subjectAltNames[0].value",
                                        equalTo("predecessor.example.com"))));
    }

    @Test
    void rekey_seedsFromAnUploadedCsr_notThePredecessor() throws Exception {
        AuthorityFixtures.Fixture fixture = AuthorityFixtures
                .v3Authority(repos(), wireMockServer, FeatureFlag.CERTIFICATE_REQUEST_STRUCTURED);
        V3ConnectorStubs.stubAttributesAndValidate(wireMockServer);
        UUID predecessorUuid = seedRenewalPairWithRealPredecessor(fixture);
        UUID successorUuid = successorUuid(predecessorUuid);
        // An uploaded rekey CSR keeps the predecessor's DN (the entry validates that) but may carry a different
        // SAN, which is the operator's own statement and must not be overridden by the predecessor's.
        String uploaded = pkcs10WithSan("CN=predecessor.example.com", "uploaded.example.com");
        CertificateRequestEntity uploadedCsr = CertificateRequestEntityBuilder
                .aCertificateRequest()
                .withContent(uploaded)
                .build();
        certificateRequestRepository.save(uploadedCsr);
        Certificate successor = reloadCert(successorUuid);
        successor.setCertificateRequest(uploadedCsr);
        successor.setCertificateRequestUuid(uploadedCsr.getUuid());
        certificateRepository.save(successor);
        stubRenewSchemaAndAccept();

        ClientCertificateRekeyRequestDto request = new ClientCertificateRekeyRequestDto();
        request.setRequest(uploaded);

        Assertions
                .assertDoesNotThrow(
                        () -> clientOperationInternalService.rekeyCertificateAction(successorUuid, request, true));

        wireMockServer
                .verify(1,
                        postRequestedFor(urlEqualTo(V3_RENEW_PATH))
                                .withRequestBody(matchingJsonPath("$.requestContent.subjectAltNames[0].value",
                                        equalTo("uploaded.example.com"))));
    }

    private String pkcs10WithSan(String subjectDn, String dnsName) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(new X500Name(subjectDn),
                kp.getPublic());
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen
                .addExtension(Extension.subjectAlternativeName, false,
                        new GeneralNames(new GeneralName(GeneralName.dNSName, dnsName)));
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return Base64.getEncoder().encodeToString(builder.build(signer).getEncoded());
    }

    @Test
    void renew_omitsRequestContent_whenConnectorDoesNotAdvertiseStructured() throws Exception {
        AuthorityFixtures.Fixture fixture = buildV3Fixture();
        V3ConnectorStubs.stubAttributesAndValidate(wireMockServer);
        UUID predecessorUuid = seedRenewalPairWithRealPredecessor(fixture);
        UUID successorUuid = successorUuid(predecessorUuid);
        stubRenewSchemaAndAccept();

        Assertions
                .assertDoesNotThrow(() -> clientOperationInternalService
                        .renewCertificateAction(successorUuid, ClientCertificateRenewRequestDto.builder().build(),
                                true));

        wireMockServer
                .verify(1, postRequestedFor(urlEqualTo(V3_RENEW_PATH))
                        .withRequestBody(matchingJsonPath("$.requestContent", absent())));
    }

    /**
     * Seeds the renewal pair with a predecessor whose stored content is a real certificate carrying a DNS SAN, so the
     * renew wire has an identity to seed from.
     */
    private UUID seedRenewalPairWithRealPredecessor(AuthorityFixtures.Fixture fixture) throws Exception {
        X509Certificate predecessorCertificate = CertificateTestUtil
                .createCertificateWithSubjectAndSans("CN=predecessor.example.com",
                        new GeneralName(GeneralName.dNSName, "predecessor.example.com"));
        UUID predecessorUuid = seedRenewalPair(fixture);
        Certificate predecessor = reloadCert(predecessorUuid);
        CertificateContent content = predecessor.getCertificateContent();
        content.setContent(Base64.getEncoder().encodeToString(predecessorCertificate.getEncoded()));
        certificateContentRepository.save(content);
        return predecessorUuid;
    }

    @Test
    void renew_carriesPersistedRenewAttributeValuesOnTheWire() throws Exception {
        AuthorityFixtures.Fixture fixture = buildV3Fixture();
        V3ConnectorStubs.stubAttributesAndValidate(wireMockServer);
        UUID predecessorUuid = seedRenewalPair(fixture);
        UUID successorUuid = successorUuid(predecessorUuid);
        stubRenewSchemaAndAccept();
        persistRenewValue(fixture, successorUuid);

        Assertions
                .assertDoesNotThrow(() -> clientOperationInternalService
                        .renewCertificateAction(successorUuid, ClientCertificateRenewRequestDto.builder().build(),
                                true));

        wireMockServer
                .verify(1,
                        postRequestedFor(urlEqualTo(V3_RENEW_PATH))
                                .withRequestBody(matchingJsonPath("$.attributes[0].name", equalTo("validityOverride")))
                                .withRequestBody(matchingJsonPath("$.attributes[0].content[0].data", equalTo("P90D"))));
    }

    @Test
    void renewAttributeValuesSurfaceOnSuccessorDetail() throws Exception {
        AuthorityFixtures.Fixture fixture = buildV3Fixture();
        V3ConnectorStubs.stubAttributesAndValidate(wireMockServer);
        UUID predecessorUuid = seedRenewalPair(fixture);
        UUID successorUuid = successorUuid(predecessorUuid);
        stubRenewSchemaAndAccept();
        persistRenewValue(fixture, successorUuid);

        Assertions
                .assertDoesNotThrow(() -> clientOperationInternalService
                        .renewCertificateAction(successorUuid, ClientCertificateRenewRequestDto.builder().build(),
                                true));

        // The persisted values surface on the successor's detail, like issue/revoke/register values do.
        CertificateDetailDto detail = certificateExternalService.getCertificate(SecuredUUID.fromUUID(successorUuid));
        Assertions
                .assertEquals(1, detail.getRenewAttributes().size(),
                        "renew attributes must surface on the successor certificate detail");
        Assertions.assertEquals("validityOverride", detail.getRenewAttributes().getFirst().getName());
    }

    /** Connector offers a renew schema (more specific than the blanket empty stub, so it wins) and accepts renew. */
    private void stubRenewSchemaAndAccept() {
        wireMockServer
                .stubFor(post(urlEqualTo(V3_RENEW_ATTRIBUTES_PATH))
                        .willReturn(
                                aResponse().withStatus(200).withHeader("Content-Type", "application/json").withBody("""
                                        [ {
                                          "uuid": "1b7f2c3a-0000-4000-8000-000000000001",
                                          "name": "validityOverride",
                                          "type": "data",
                                          "version": 3,
                                          "contentType": "string",
                                          "properties": { "label": "Validity Override", "visible": true,
                                                          "required": false, "readOnly": false,
                                                          "list": false, "multiSelect": false }
                                        } ]
                                        """)));
        wireMockServer
                .stubFor(post(urlEqualTo(V3_RENEW_PATH))
                        .willReturn(aResponse()
                                .withStatus(202)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"certificateData\": null, \"meta\": []}")));
    }

    /**
     * Persists a renew value on the successor the way the synchronous renew entry does (validate against the connector
     * schema, then write the CERTIFICATE_RENEW slot), so the action's adapter read-back finds it.
     */
    private void persistRenewValue(AuthorityFixtures.Fixture fixture, UUID successorUuid) throws Exception {
        RequestAttributeV3 renewValue = new RequestAttributeV3(UUID.fromString("1b7f2c3a-0000-4000-8000-000000000001"),
                "validityOverride", AttributeContentType.STRING, List.of(new StringAttributeContentV3("P90D")));
        extendedAttributeService.mergeAndValidateRenewAttributes(fixture.raProfile(), List.of(renewValue));
        attributeEngine
                .updateObjectDataAttributesContent(ObjectAttributeContentInfo
                        .builder(Resource.CERTIFICATE, successorUuid)
                        .connector(fixture.raProfile().getAuthorityInstanceReference().getConnectorUuid())
                        .operation(AttributeOperation.CERTIFICATE_RENEW)
                        .build(), List.of(renewValue));
    }

    @Test
    void renew_sync200_postAcceptanceLocalFailure_leavesSuccessorPendingIssue() throws Exception {
        AuthorityFixtures.Fixture fixture = buildV3Fixture();
        V3ConnectorStubs.stubAttributesAndValidate(wireMockServer);
        UUID predecessorUuid = seedRenewalPair(fixture);
        UUID successorUuid = successorUuid(predecessorUuid);

        // 200 with certificate data the connector accepted but Core cannot parse: the local
        // issueRequestedCertificate step fails after the connector already issued. The successor must stay
        // PENDING_ISSUE (not FAILED) so it can be reconciled against the authority.
        wireMockServer
                .stubFor(post(urlEqualTo(V3_RENEW_PATH))
                        .willReturn(aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"certificateData\": \"bm90LWEtY2VydA==\", \"meta\": []}")));

        Assertions
                .assertThrows(Exception.class,
                        () -> clientOperationInternalService
                                .renewCertificateAction(successorUuid,
                                        ClientCertificateRenewRequestDto.builder().build(), true));

        Assertions
                .assertEquals(CertificateState.PENDING_ISSUE, reloadCert(successorUuid).getState(),
                        "a post-acceptance local failure must leave the successor PENDING_ISSUE, not FAILED");
        Assertions
                .assertEquals(CertificateState.ISSUED, reloadCert(predecessorUuid).getState(),
                        "the predecessor must stay ISSUED");
    }

    @Test
    void revoke_sync200_transitionsToRevoked_viaV3_notV2() {
        AuthorityFixtures.Fixture fixture = buildV3Fixture();
        V3ConnectorStubs.stubAttributesAndValidate(wireMockServer);
        Certificate cert = seedCertificate(fixture, CertificateState.ISSUED);

        wireMockServer
                .stubFor(post(urlEqualTo(V3_REVOKE_PATH))
                        .willReturn(aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"certificateData\": null, \"meta\": []}")));

        ClientCertificateRevocationDto request = new ClientCertificateRevocationDto();
        request.setAttributes(List.of());

        Assertions
                .assertDoesNotThrow(
                        () -> clientOperationInternalService.revokeCertificateAction(cert.getUuid(), request, true));

        Assertions
                .assertEquals(CertificateState.REVOKED, reloadCert(cert.getUuid()).getState(),
                        "a synchronous v3 revoke (200) must transition the certificate to REVOKED");
        wireMockServer.verify(1, postRequestedFor(urlEqualTo(V3_REVOKE_PATH)));
        wireMockServer.verify(0, postRequestedFor(urlPathMatching(V2_REVOKE_PATTERN)));
    }

    @Test
    void revoke_async202_parksPendingRevoke_viaV3() {
        AuthorityFixtures.Fixture fixture = buildV3Fixture();
        V3ConnectorStubs.stubAttributesAndValidate(wireMockServer);
        Certificate cert = seedCertificate(fixture, CertificateState.ISSUED);

        wireMockServer
                .stubFor(post(urlEqualTo(V3_REVOKE_PATH))
                        .willReturn(aResponse()
                                .withStatus(202)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"certificateData\": null, \"meta\": []}")));

        ClientCertificateRevocationDto request = new ClientCertificateRevocationDto();
        request.setAttributes(List.of());

        Assertions
                .assertDoesNotThrow(
                        () -> clientOperationInternalService.revokeCertificateAction(cert.getUuid(), request, true));

        Assertions
                .assertEquals(CertificateState.PENDING_REVOKE, reloadCert(cert.getUuid()).getState(),
                        "an accepted async v3 revoke (202) must park the certificate in PENDING_REVOKE");
        wireMockServer.verify(1, postRequestedFor(urlEqualTo(V3_REVOKE_PATH)));
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private AuthorityFixtures.Repos repos() {
        return new AuthorityFixtures.Repos(connectorRepository, functionGroupRepository,
                connector2FunctionGroupRepository, authorityInstanceReferenceRepository, raProfileRepository,
                connectorInterfaceRepository);
    }

    private AuthorityFixtures.Fixture buildV3Fixture() {
        return AuthorityFixtures.v3Authority(repos(), wireMockServer);
    }

    private Certificate seedCertificate(AuthorityFixtures.Fixture fixture, CertificateState state) {
        CertificateContent content = certificateContentRepository.save(new CertificateContent());
        Certificate cert = new Certificate();
        cert.setSubjectDn("CN=v3-op-" + UUID.randomUUID());
        cert.setIssuerDn("CN=test-issuer");
        cert.setSerialNumber(UUID.randomUUID().toString());
        cert.setCertificateContent(content);
        cert.setCertificateContentId(content.getId());
        cert.setState(state);
        cert.setValidationStatus(CertificateValidationStatus.VALID);
        cert.setRaProfile(fixture.raProfile());
        return certificateRepository.save(cert);
    }

    /**
     * Seeds an ISSUED predecessor and a REQUESTED successor (with a CSR) linked by a PENDING relation, as the
     * renew/rekey actions require. Returns the predecessor UUID.
     */
    private UUID seedRenewalPair(AuthorityFixtures.Fixture fixture) {
        Certificate predecessor = seedCertificate(fixture, CertificateState.ISSUED);

        CertificateRequestEntity csr = CertificateRequestEntityBuilder
                .aCertificateRequest()
                .withContent("content")
                .build();
        certificateRequestRepository.save(csr);

        Certificate successor = seedCertificate(fixture, CertificateState.REQUESTED);
        successor.setCertificateRequest(csr);
        successor.setCertificateRequestUuid(csr.getUuid());
        certificateRepository.save(successor);

        CertificateRelation relation = new CertificateRelation();
        relation.setSuccessorCertificate(successor);
        relation.setPredecessorCertificate(predecessor);
        relation.setRelationType(CertificateRelationType.PENDING);
        certificateRelationRepository.save(relation);

        return predecessor.getUuid();
    }

    private UUID successorUuid(UUID predecessorUuid) {
        return certificateRelationRepository
                .findAll()
                .stream()
                .filter(r -> predecessorUuid.equals(r.getPredecessorCertificate().getUuid()))
                .map(r -> r.getSuccessorCertificate().getUuid())
                .findFirst()
                .orElseThrow(() -> new AssertionError("No successor relation for " + predecessorUuid));
    }

    private Certificate reloadCert(UUID uuid) {
        return certificateRepository
                .findByUuid(uuid)
                .orElseThrow(() -> new AssertionError("Certificate not found: " + uuid));
    }
}

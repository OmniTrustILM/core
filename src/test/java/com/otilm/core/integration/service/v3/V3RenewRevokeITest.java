package com.otilm.core.integration.service.v3;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRevocationDto;
import com.otilm.api.model.core.certificate.CertificateRelationType;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
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
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.builders.AuthorityFixtures;
import com.otilm.core.util.builders.V3ConnectorStubs;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;

/**
 * Integration tests for renew and revoke against a v3 authority. These operations dispatch through
 * {@code AuthorityProviderAdapterFactory}; a v3 authority does not serve the v2 endpoints, so the tests
 * pin that the request lands on the v3 wire and never on the v2 endpoints.
 */
class V3RenewRevokeITest extends BaseSpringBootTest {

    private static final String V3_RENEW_PATH  = "/v3/authorityProvider/certificates/renew";
    private static final String V3_REVOKE_PATH = "/v3/authorityProvider/certificates/revoke";
    private static final String V2_RENEW_PATTERN  = "/v2/authorityProvider/authorities/[^/]+/certificates/renew";
    private static final String V2_REVOKE_PATTERN = "/v2/authorityProvider/authorities/[^/]+/certificates/revoke";

    @Autowired
    private ClientOperationInternalService clientOperationInternalService;
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
        wireMockServer = new WireMockServer(0);
        wireMockServer.start();
        WireMock.configureFor("localhost", wireMockServer.port());
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

        wireMockServer.stubFor(post(urlEqualTo(V3_RENEW_PATH))
                .willReturn(aResponse().withStatus(202)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"certificateData\": null, \"meta\": []}")));

        Assertions.assertDoesNotThrow(() ->
                clientOperationInternalService.renewCertificateAction(
                        successorUuid, ClientCertificateRenewRequestDto.builder().build(), true));

        Assertions.assertEquals(CertificateState.PENDING_ISSUE, reloadCert(successorUuid).getState(),
                "an accepted async v3 renew (202) must park the successor in PENDING_ISSUE");
        Assertions.assertEquals(CertificateState.ISSUED, reloadCert(predecessorUuid).getState(),
                "the predecessor must stay ISSUED while the successor awaits asynchronous completion");
        wireMockServer.verify(1, postRequestedFor(urlEqualTo(V3_RENEW_PATH)));
        wireMockServer.verify(0, postRequestedFor(urlPathMatching(V2_RENEW_PATTERN)));
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
        wireMockServer.stubFor(post(urlEqualTo(V3_RENEW_PATH))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"certificateData\": \"bm90LWEtY2VydA==\", \"meta\": []}")));

        Assertions.assertThrows(Exception.class, () ->
                clientOperationInternalService.renewCertificateAction(
                        successorUuid, ClientCertificateRenewRequestDto.builder().build(), true));

        Assertions.assertEquals(CertificateState.PENDING_ISSUE, reloadCert(successorUuid).getState(),
                "a post-acceptance local failure must leave the successor PENDING_ISSUE, not FAILED");
        Assertions.assertEquals(CertificateState.ISSUED, reloadCert(predecessorUuid).getState(),
                "the predecessor must stay ISSUED");
    }

    @Test
    void revoke_sync200_transitionsToRevoked_viaV3_notV2() {
        AuthorityFixtures.Fixture fixture = buildV3Fixture();
        V3ConnectorStubs.stubAttributesAndValidate(wireMockServer);
        Certificate cert = seedCertificate(fixture, CertificateState.ISSUED);

        wireMockServer.stubFor(post(urlEqualTo(V3_REVOKE_PATH))
                .willReturn(aResponse().withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"certificateData\": null, \"meta\": []}")));

        ClientCertificateRevocationDto request = new ClientCertificateRevocationDto();
        request.setAttributes(List.of());

        Assertions.assertDoesNotThrow(() ->
                clientOperationInternalService.revokeCertificateAction(cert.getUuid(), request, true));

        Assertions.assertEquals(CertificateState.REVOKED, reloadCert(cert.getUuid()).getState(),
                "a synchronous v3 revoke (200) must transition the certificate to REVOKED");
        wireMockServer.verify(1, postRequestedFor(urlEqualTo(V3_REVOKE_PATH)));
        wireMockServer.verify(0, postRequestedFor(urlPathMatching(V2_REVOKE_PATTERN)));
    }

    @Test
    void revoke_async202_parksPendingRevoke_viaV3() {
        AuthorityFixtures.Fixture fixture = buildV3Fixture();
        V3ConnectorStubs.stubAttributesAndValidate(wireMockServer);
        Certificate cert = seedCertificate(fixture, CertificateState.ISSUED);

        wireMockServer.stubFor(post(urlEqualTo(V3_REVOKE_PATH))
                .willReturn(aResponse().withStatus(202)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"certificateData\": null, \"meta\": []}")));

        ClientCertificateRevocationDto request = new ClientCertificateRevocationDto();
        request.setAttributes(List.of());

        Assertions.assertDoesNotThrow(() ->
                clientOperationInternalService.revokeCertificateAction(cert.getUuid(), request, true));

        Assertions.assertEquals(CertificateState.PENDING_REVOKE, reloadCert(cert.getUuid()).getState(),
                "an accepted async v3 revoke (202) must park the certificate in PENDING_REVOKE");
        wireMockServer.verify(1, postRequestedFor(urlEqualTo(V3_REVOKE_PATH)));
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private AuthorityFixtures.Repos repos() {
        return new AuthorityFixtures.Repos(
                connectorRepository,
                functionGroupRepository,
                connector2FunctionGroupRepository,
                authorityInstanceReferenceRepository,
                raProfileRepository,
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
     * Seeds an ISSUED predecessor and a REQUESTED successor (with a CSR) linked by a PENDING relation,
     * as the renew/rekey actions require. Returns the predecessor UUID.
     */
    private UUID seedRenewalPair(AuthorityFixtures.Fixture fixture) throws Exception {
        Certificate predecessor = seedCertificate(fixture, CertificateState.ISSUED);

        CertificateRequestEntity csr = new CertificateRequestEntity();
        csr.setContent("content");
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
        return certificateRelationRepository.findAll().stream()
                .filter(r -> predecessorUuid.equals(r.getPredecessorCertificate().getUuid()))
                .map(r -> r.getSuccessorCertificate().getUuid())
                .findFirst()
                .orElseThrow(() -> new AssertionError("No successor relation for " + predecessorUuid));
    }

    private Certificate reloadCert(UUID uuid) {
        return certificateRepository.findByUuid(uuid)
                .orElseThrow(() -> new AssertionError("Certificate not found: " + uuid));
    }
}

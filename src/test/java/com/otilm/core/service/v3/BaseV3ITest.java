package com.otilm.core.service.v3;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.CertificateRequestEntity;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CertificateRequestRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.util.BaseSpringBootTest;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.UUID;

/**
 * Shared setup for v3 authority integration tests. Each subclass gets a fresh
 * WireMock server, a persisted v3 connector row with a ConnectorInterfaceEntity
 * (AUTHORITY / "v3"), an AuthorityInstanceReference that points at it, and a
 * default enabled RaProfile wired to that authority.
 *
 * The base class does NOT set up a Certificate — each test creates its own
 * depending on what state it needs.
 */
public abstract class BaseV3ITest extends BaseSpringBootTest {

    // --- v3 WireMock stubs for certificate operations ---
    protected static final String V3_ISSUE_PATH   = "/v3/authorityProvider/certificates/issue";
    protected static final String V3_RENEW_PATH   = "/v3/authorityProvider/certificates/renew";
    protected static final String V3_REVOKE_PATH  = "/v3/authorityProvider/certificates/revoke";
    protected static final String V3_REGISTER_PATH = "/v3/authorityProvider/certificates/register";
    protected static final String V3_ISSUE_STATUS_PATH  = "/v3/authorityProvider/certificates/issue/status";
    protected static final String V3_ISSUE_CANCEL_PATH  = "/v3/authorityProvider/certificates/issue/cancel";
    protected static final String V3_REGISTER_STATUS_PATH  = "/v3/authorityProvider/certificates/register/status";
    protected static final String V3_REGISTER_CANCEL_PATH  = "/v3/authorityProvider/certificates/register/cancel";
    protected static final String V3_AUTHORITY_PATH = "/v3/authorityProvider/authorities";

    // A minimal valid base64 DER of a self-signed cert (not a real cert — tests only check state).
    // This is the same PEM from ClientOperationServiceV2Test decoded just enough to satisfy the parser.
    // For state-level tests we use an actual loaded cert; for simple wire stub responses we use this placeholder.
    protected static final String FAKE_CERT_B64 = "MIICpDCCAYwCCQDU+pQ4pHgSpDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls" +
            "b2NhbGhvc3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAUMRIwEAYD" +
            "VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7" +
            "o4qne60TB3wolGLlFfPqBSWI6uLIaHyWgLMxSuLKWQbdHHcPBR8DxZgq0QnimCg" +
            "JqQmZnXFkPMN+w2KoI8uaG6r2ZPjMBCG3j2OGzQC/UQBZ69w1EECJqSXEe+RFWI" +
            "xnQpBEwb1VCfJKtdJi6JfnwZvEPeRfJCgYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
            "AAAAAAAAAAAAAAAAAAAAAAAAAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAC6Z2pu4hF" +
            "QKP9wGlIHhDOOOVEV1jCmS7ioGPy3mS4dlCJjEyVqKvIZ44sG2Gq84W7yKHjLGi" +
            "8E9qYaFkAkx/VFmQiPJjDGvzLeFLjKuqHf0ZnDCQV3fRVbVIlr2aSXkEzrgAAAAA";

    @Autowired protected ConnectorRepository connectorRepository;
    @Autowired protected ConnectorInterfaceRepository connectorInterfaceRepository;
    @Autowired protected AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired protected RaProfileRepository raProfileRepository;
    @Autowired protected CertificateRepository certificateRepository;
    @Autowired protected CertificateContentRepository certificateContentRepository;
    @Autowired protected CertificateRequestRepository certificateRequestRepository;

    protected WireMockServer mockServer;
    protected Connector connector;
    protected ConnectorInterfaceEntity v3Interface;
    protected AuthorityInstanceReference authority;
    protected RaProfile raProfile;

    @BeforeEach
    public void setUpV3() {
        mockServer = new WireMockServer(0);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        connector = new Connector();
        connector.setName("v3-connector-" + UUID.randomUUID());
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector.setVersion(ConnectorVersion.V2);
        connector = connectorRepository.save(connector);

        v3Interface = new ConnectorInterfaceEntity();
        v3Interface.setConnectorUuid(connector.getUuid());
        v3Interface.setInterfaceCode(ConnectorInterface.AUTHORITY);
        v3Interface.setVersion("v3");
        v3Interface.setFeatures(List.of(FeatureFlag.CERTIFICATE_REGISTRATION));
        v3Interface = connectorInterfaceRepository.save(v3Interface);

        connector.getInterfaces().add(v3Interface);
        connectorRepository.save(connector);

        authority = new AuthorityInstanceReference();
        authority.setName("v3-authority-" + UUID.randomUUID());
        authority.setConnectorUuid(connector.getUuid());
        authority.setConnector(connector);
        authority.setConnectorInterface(v3Interface);
        authority.setConnectorInterfaceUuid(v3Interface.getUuid());
        authority.setAuthorityInstanceUuid(UUID.randomUUID().toString());
        authority.setKind("V3TestKind");
        authority = authorityInstanceReferenceRepository.save(authority);

        raProfile = new RaProfile();
        raProfile.setName("v3-ra-" + UUID.randomUUID());
        raProfile.setAuthorityInstanceReference(authority);
        raProfile.setAuthorityInstanceReferenceUuid(authority.getUuid());
        raProfile.setEnabled(true);
        raProfile = raProfileRepository.save(raProfile);
    }

    @AfterEach
    public void tearDownV3() {
        if (mockServer != null && mockServer.isRunning()) {
            mockServer.stop();
        }
    }

    protected Certificate buildCertificateInState(CertificateState state) {
        CertificateContent content = new CertificateContent();
        content.setContent(FAKE_CERT_B64);
        content = certificateContentRepository.save(content);

        Certificate cert = new Certificate();
        cert.setState(state);
        cert.setComplianceStatus(ComplianceStatus.NOT_CHECKED);
        cert.setValidationStatus(CertificateValidationStatus.NOT_CHECKED);
        cert.setCertificateType(CertificateType.X509);
        cert.setRaProfile(raProfile);
        cert.setRaProfileUuid(raProfile.getUuid());
        cert.setCertificateContent(content);
        cert.setCertificateContentId(content.getId());
        return certificateRepository.save(cert);
    }

    protected Certificate buildCertInStateWithCsr(CertificateState state, String csrBase64) throws Exception {
        Certificate cert = buildCertificateInState(state);

        CertificateRequestEntity csr = new CertificateRequestEntity();
        csr.setContent(csrBase64);
        csr.setCertificateRequestFormat(CertificateRequestFormat.PKCS10);
        csr = certificateRequestRepository.save(csr);

        cert.setCertificateRequest(csr);
        cert.setCertificateRequestUuid(csr.getUuid());
        return certificateRepository.save(cert);
    }

    protected String syncIssueBody(String certB64) {
        return """
                {"certificateData":"%s","certificateType":"X.509"}
                """.formatted(certB64).strip();
    }

    protected String asyncAcceptedBody() {
        return "{}";
    }

    protected String asyncAcceptedBodyWithMeta(String metaName, String metaValue) {
        return """
                {"meta":[{"uuid":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","name":"%s","type":"meta","contentType":"string","description":"test","content":[{"reference":null,"data":"%s"}],"properties":{"label":"%s","global":true,"overwrite":false,"visible":true}}]}
                """.formatted(metaName, metaValue, metaName).strip();
    }

    protected String statusResponseBody(String status) {
        return """
                {"status":"%s"}
                """.formatted(status).strip();
    }

    protected String statusResponseBodyWithCert(String status, String certB64) {
        return """
                {"status":"%s","certificateData":"%s"}
                """.formatted(status, certB64).strip();
    }

    protected String problemJsonBody(String errorCode) {
        return """
                {"errorCode":"%s","message":"test error"}
                """.formatted(errorCode).strip();
    }
}

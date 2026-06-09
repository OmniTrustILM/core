package com.czertainly.core.service.v3;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.v2.ClientCertificateSignRequestDto;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.v2.ClientOperationService;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Sync issue happy path: operator calls issueCertificate, v3 connector returns 200
 * with cert data, cert ends in ISSUED state.
 *
 * The test exercises:
 *   - AuthorityProviderAdapterFactory routing to AuthorityProviderV3Adapter
 *   - AuthorityProviderV3Adapter.issue → 200 → SYNC_OK
 *   - issueCertificateAction writing cert data and transitioning to ISSUED
 */
class V3AuthorityCertificateOperationITest extends BaseV3ITest {

    @Autowired
    @Qualifier("clientOperationServiceImplV2")
    private ClientOperationService clientOperationService;

    @Test
    void syncIssueHappyPath_certEndsInIssuedState() throws Exception {
        // Load a real X.509 cert so certificateService can parse it
        InputStream ks = getClass().getClassLoader().getResourceAsStream("client1.p12");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(ks, "123456".toCharArray());
        X509Certificate x509 = (X509Certificate) keyStore.getCertificate("1");
        String certB64 = Base64.getEncoder().encodeToString(x509.getEncoded());

        // Stub: v3 issue endpoint returns 200 with cert data
        mockServer.stubFor(WireMock.post(WireMock.urlEqualTo(V3_ISSUE_PATH))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(syncIssueBody(certB64))));

        // Create a cert in REQUESTED state with a CSR (needed by issueCertificateAction)
        String csrB64 = Base64.getEncoder().encodeToString(
                V3TestCertHelper.generateSelfSignedCsrDer());
        Certificate cert = buildCertInStateWithCsr(CertificateState.REQUESTED, csrB64);

        // Act: trigger issueCertificateAction which drives adapter.issue
        clientOperationService.issueCertificateAction(cert.getUuid(), true);

        // Assert: cert is ISSUED and the WireMock endpoint was called exactly once
        Certificate refreshed = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertEquals(CertificateState.ISSUED, refreshed.getState(),
                "Certificate should be in ISSUED state after sync 200 from connector");
        assertNotNull(refreshed.getCertificateContent(),
                "Certificate content must be persisted after issue");

        mockServer.verify(1, WireMock.postRequestedFor(WireMock.urlEqualTo(V3_ISSUE_PATH)));
    }

    @Test
    void listAvailableOperations_v3AuthorityReturnsAsyncAndRegisterSupported() throws Exception {
        SecuredParentUUID authoritySecured = SecuredParentUUID.fromUUID(authority.getUuid());
        SecuredUUID raSecured = raProfile.getSecuredUuid();

        var ops = clientOperationService.listAvailableOperations(authoritySecured, raSecured);

        assertNotNull(ops);
        assertNotNull(ops.getOperations());
        // v3 adapter implements AsyncOperationCapability and RegisterCapability;
        // FeatureFlag.CERTIFICATE_REGISTRATION is present → REGISTER should be supported + async
        var registerOp = ops.getOperations().stream()
                .filter(o -> "REGISTER".equals(o.getOperation()))
                .findFirst().orElse(null);
        assertNotNull(registerOp, "REGISTER operation should be present");
        assertEquals(true, registerOp.isSupported());
        assertEquals(true, registerOp.isAsyncSupported());
    }
}

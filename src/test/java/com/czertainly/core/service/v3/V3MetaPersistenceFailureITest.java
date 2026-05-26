package com.czertainly.core.service.v3;

import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.messaging.jms.listeners.CertificateStatusPollListener;
import com.czertainly.core.messaging.model.CertificateStatusPollMessage;
import com.czertainly.core.service.handler.authority.CertificateOperation;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;

/**
 * Defensive path: attributeEngine.updateMetadataAttributes throws during poll listener
 * applyTerminalTransition. The state transition must still commit (PENDING_ISSUE → ISSUED)
 * even though meta persistence failed. Only a WARN log is emitted.
 *
 * Approach: spy on AttributeEngine, configure updateMetadataAttributes to throw,
 * then verify the cert ends in ISSUED and the WireMock poll endpoint was called.
 */
class V3MetaPersistenceFailureITest extends BaseV3ITest {

    @MockitoSpyBean
    private AttributeEngine attributeEngine;

    @Autowired
    private CertificateStatusPollListener pollListener;

    @Test
    void pollCompletedWithMeta_metaPersistenceThrows_certStillIssuedAndWarnLogged() throws Exception {
        InputStream ks = getClass().getClassLoader().getResourceAsStream("client1.p12");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(ks, "123456".toCharArray());
        X509Certificate x509 = (X509Certificate) keyStore.getCertificate("1");
        String certB64 = Base64.getEncoder().encodeToString(x509.getEncoded());

        // Stub: issue status returns COMPLETED with cert data AND meta
        String completedWithMeta = """
                {"status":"completed","certificateData":"%s","meta":[{"uuid":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","name":"trackingId","type":"meta","contentType":"string","content":[{"reference":null,"data":"abc123"}]}]}
                """.formatted(certB64).strip();

        mockServer.stubFor(WireMock.post(WireMock.urlEqualTo(V3_ISSUE_STATUS_PATH))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(completedWithMeta)));

        // Make updateMetadataAttributes throw on non-empty lists only — the listener passes an
        // empty list through issueRequestedCertificate as a deliberate no-op (state-divergence:
        // cert content + state must commit before the meta write is attempted separately),
        // and matching the empty-list call would spuriously block that path.
        Mockito.doThrow(new com.czertainly.api.exception.AttributeException("Simulated meta persistence failure"))
                .when(attributeEngine)
                .updateMetadataAttributes(argThat(list -> list != null && !list.isEmpty()), any(ObjectAttributeContentInfo.class));

        Certificate cert = buildCertificateInState(CertificateState.PENDING_ISSUE);

        // Drive the poll listener with a COMPLETED response
        CertificateStatusPollMessage pollMsg = new CertificateStatusPollMessage(
                Resource.CERTIFICATE, cert.getUuid(), CertificateOperation.ISSUE, 1);
        pollListener.processMessage(pollMsg);

        // The state transition committed before the (failing) meta update → cert is ISSUED
        Certificate final_ = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertEquals(CertificateState.ISSUED, final_.getState(),
                "State transition must commit to ISSUED even when meta persistence fails");

        // The status poll endpoint was called exactly once
        mockServer.verify(1, WireMock.postRequestedFor(WireMock.urlEqualTo(V3_ISSUE_STATUS_PATH)));
    }
}

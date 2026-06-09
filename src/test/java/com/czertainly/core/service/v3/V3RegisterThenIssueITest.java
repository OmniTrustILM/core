package com.czertainly.core.service.v3;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.v2.ClientCertificateRegistrationDto;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.messaging.jms.listeners.CertificateStatusPollListener;
import com.czertainly.core.messaging.model.CertificateStatusPollMessage;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.handler.authority.CertificateOperation;
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
 * Register-then-issue flow:
 * 1. registerCertificate → connector returns 202 with meta (ejbcaUsername=joe).
 * 2. Poll listener transitions cert to REGISTERED.
 * 3. issueCertificateAction — check that meta was carried to the issue request.
 * 4. Cert ends in ISSUED.
 */
class V3RegisterThenIssueITest extends BaseV3ITest {

    @Autowired
    @Qualifier("clientOperationServiceImplV2")
    private ClientOperationService clientOperationService;

    @Autowired
    private CertificateStatusPollListener pollListener;

    @Test
    void registerAsyncThenIssueSync_metaCarriedThrough() throws Exception {
        InputStream ks = getClass().getClassLoader().getResourceAsStream("client1.p12");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(ks, "123456".toCharArray());
        X509Certificate x509 = (X509Certificate) keyStore.getCertificate("1");
        String certB64 = Base64.getEncoder().encodeToString(x509.getEncoded());

        // Stub: register → 202 with meta
        mockServer.stubFor(WireMock.post(WireMock.urlEqualTo(V3_REGISTER_PATH))
                .willReturn(WireMock.aResponse()
                        .withStatus(202)
                        .withHeader("Content-Type", "application/json")
                        .withBody(asyncAcceptedBodyWithMeta("ejbcaUsername", "joe"))));

        // Stub: register status → COMPLETED
        mockServer.stubFor(WireMock.post(WireMock.urlEqualTo(V3_REGISTER_STATUS_PATH))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(statusResponseBody("completed"))));

        // Stub: issue → 200 with cert data
        mockServer.stubFor(WireMock.post(WireMock.urlEqualTo(V3_ISSUE_PATH))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(syncIssueBody(certB64))));

        // Step 1: register
        ClientCertificateRegistrationDto regReq = new ClientCertificateRegistrationDto();
        regReq.setSubjectDn("CN=test-register,O=Test");
        regReq.setSubjectAltName("DNS:test.example.com");
        regReq.setAttributes(List.of());
        var regResp = clientOperationService.registerCertificate(
                SecuredParentUUID.fromUUID(authority.getUuid()),
                raProfile.getSecuredUuid(),
                regReq);
        assertNotNull(regResp);
        assertNotNull(regResp.getUuid());

        Certificate certAfterReg = certificateRepository.findByUuid(
                java.util.UUID.fromString(regResp.getUuid())).orElseThrow();
        assertEquals(CertificateState.PENDING_REGISTRATION, certAfterReg.getState(),
                "After async register, cert should be PENDING_REGISTRATION");

        // Step 2: poll listener drives PENDING_REGISTRATION → REGISTERED
        CertificateStatusPollMessage pollMsg = new CertificateStatusPollMessage(
                Resource.CERTIFICATE, certAfterReg.getUuid(), CertificateOperation.REGISTER, 1);
        pollListener.processMessage(pollMsg);

        Certificate certAfterPoll = certificateRepository.findByUuid(certAfterReg.getUuid()).orElseThrow();
        assertEquals(CertificateState.REGISTERED, certAfterPoll.getState(),
                "After COMPLETED poll, cert should be REGISTERED");

        // Step 3: operator finalizes the registration with a CSR via the real endpoint.
        // issueExistingCertificate accepts {REQUESTED, REGISTERED} and, for REGISTERED, attaches
        // the supplied CSR to the existing cert row before firing the ISSUE ActionMessage.
        String csrB64 = Base64.getEncoder().encodeToString(V3TestCertHelper.generateSelfSignedCsrDer());
        com.otilm.api.model.core.v2.ClientCertificateSignRequestDto signReq =
                new com.otilm.api.model.core.v2.ClientCertificateSignRequestDto();
        signReq.setRequest(csrB64);
        signReq.setFormat(com.otilm.api.model.core.enums.CertificateRequestFormat.PKCS10);

        clientOperationService.issueExistingCertificate(
                SecuredParentUUID.fromUUID(authority.getUuid()),
                raProfile.getSecuredUuid(),
                certAfterPoll.getUuid().toString(),
                signReq);

        // ActionMessage is JMS-mocked in this test profile; drive the action directly so the
        // adapter.issue path runs (would normally be invoked by ActionsListener).
        clientOperationService.issueCertificateAction(certAfterPoll.getUuid(), true);

        // Step 4: cert ends in ISSUED
        Certificate certFinal = certificateRepository.findByUuid(certAfterPoll.getUuid()).orElseThrow();
        assertEquals(CertificateState.ISSUED, certFinal.getState(),
                "After sync issue, cert should be ISSUED");

        // Verify the /issue request body carried the meta from the register response —
        // proves V3Adapter.issue replays stored meta via the unified meta bag.
        mockServer.verify(1, WireMock.postRequestedFor(WireMock.urlEqualTo(V3_ISSUE_PATH))
                .withRequestBody(WireMock.matchingJsonPath("$.meta[?(@.name == 'ejbcaUsername')]"))
                .withRequestBody(WireMock.matchingJsonPath("$.meta[?(@.content[0].data == 'joe')]")));
        // Verify the /register request body carried subjectDn + SAN — proves
        // V3Adapter.register actually forwards operator-supplied identity fields.
        mockServer.verify(1, WireMock.postRequestedFor(WireMock.urlEqualTo(V3_REGISTER_PATH))
                .withRequestBody(WireMock.matchingJsonPath("$.subjectDn", WireMock.equalTo("CN=test-register,O=Test")))
                .withRequestBody(WireMock.matchingJsonPath("$.subjectAltName", WireMock.equalTo("DNS:test.example.com"))));
        mockServer.verify(1, WireMock.postRequestedFor(WireMock.urlEqualTo(V3_REGISTER_STATUS_PATH)));
    }
}

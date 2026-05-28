package com.czertainly.core.service.v3;

import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.authority.CertificateRevocationReason;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.v2.ClientCertificateRevocationDto;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.messaging.jms.listeners.CertificateStatusPollListener;
import com.czertainly.core.messaging.model.CertificateStatusPollMessage;
import com.czertainly.core.service.handler.authority.CertificateOperation;
import com.czertainly.core.service.v2.ClientOperationService;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Async revoke flow: connector returns 202 on /revoke, then COMPLETED on /revoke/status.
 * The poll listener must transition PENDING_REVOKE → REVOKED, clear pendingRevokeAttributes
 * and pendingRevokeDestroyKey fields, and (best-effort) honor the operator's destroyKey
 * request via a post-commit call to the key service. Mirrors manuallyConfirmRevoke
 * cleanup behavior — without this, async revoke completion drops the destroyKey signal
 * and leaves stale data on the cert row.
 */
class V3AsyncRevokeITest extends BaseV3ITest {

    @Autowired
    @Qualifier("clientOperationServiceImplV2")
    private ClientOperationService clientOperationService;

    @Autowired
    private CertificateStatusPollListener pollListener;

    @Test
    void asyncRevoke_completedClearsPendingFieldsAndTransitionsToRevoked() throws Exception {
        // Stub: revoke returns 202 Accepted with empty body
        mockServer.stubFor(WireMock.post(WireMock.urlEqualTo(V3_REVOKE_PATH))
                .willReturn(WireMock.aResponse()
                        .withStatus(202)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{}")));

        // Stub: revoke status returns COMPLETED
        mockServer.stubFor(WireMock.post(WireMock.urlEqualTo("/v3/authorityProvider/certificates/revoke/status"))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(statusResponseBody("completed"))));

        Certificate cert = buildCertificateInState(CertificateState.ISSUED);

        ClientCertificateRevocationDto revokeReq = new ClientCertificateRevocationDto();
        revokeReq.setReason(CertificateRevocationReason.KEY_COMPROMISE);
        revokeReq.setAttributes(List.<RequestAttribute>of());

        // Use revokeCertificateAction (the adapter-routed path) rather than the
        // operator-facing revokeCertificate which still calls legacy v2 attribute
        // endpoints for pre-validation — a pre-existing gap not in this task's scope.
        clientOperationService.revokeCertificateAction(cert.getUuid(), revokeReq, true);

        Certificate afterRevoke = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertEquals(CertificateState.PENDING_REVOKE, afterRevoke.getState(),
                "After 202, cert must be in PENDING_REVOKE");

        // Drive poll: COMPLETED → REVOKED
        CertificateStatusPollMessage pollMsg = new CertificateStatusPollMessage(
                Resource.CERTIFICATE, cert.getUuid(), CertificateOperation.REVOKE, 1);
        pollListener.processMessage(pollMsg);

        Certificate final_ = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertEquals(CertificateState.REVOKED, final_.getState(),
                "After COMPLETED revoke status, cert must be REVOKED");
        assertNull(final_.getPendingRevokeAttributes(),
                "pendingRevokeAttributes must be cleared on async revoke completion");
        assertNull(final_.getPendingRevokeDestroyKey(),
                "pendingRevokeDestroyKey must be cleared on async revoke completion");

        // Exactly one revoke + one status call
        mockServer.verify(1, WireMock.postRequestedFor(WireMock.urlEqualTo(V3_REVOKE_PATH)));
        mockServer.verify(1, WireMock.postRequestedFor(WireMock.urlEqualTo("/v3/authorityProvider/certificates/revoke/status")));
    }

    @Test
    void syncRevoke_200WithMeta_transitionsToRevokedWithoutError() throws Exception {
        // A v3 connector may complete a revoke synchronously with HTTP 200 carrying meta only
        // (vs 204 no-content). This must map to a terminal REVOKED transition — NOT be rejected
        // as "Unexpected SYNC_OK", which previously left the cert ISSUED while the connector had
        // already revoked it (connector-vs-DB divergence).
        mockServer.stubFor(WireMock.post(WireMock.urlEqualTo(V3_REVOKE_PATH))
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(asyncAcceptedBodyWithMeta("revokedAt", "2026-05-27T00:00:00Z"))));

        Certificate cert = buildCertificateInState(CertificateState.ISSUED);

        ClientCertificateRevocationDto revokeReq = new ClientCertificateRevocationDto();
        revokeReq.setReason(CertificateRevocationReason.KEY_COMPROMISE);
        revokeReq.setAttributes(List.<RequestAttribute>of());

        clientOperationService.revokeCertificateAction(cert.getUuid(), revokeReq, true);

        Certificate afterRevoke = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertEquals(CertificateState.REVOKED, afterRevoke.getState(),
                "200 (SYNC_OK, meta-only) revoke must transition the cert to REVOKED");

        mockServer.verify(1, WireMock.postRequestedFor(WireMock.urlEqualTo(V3_REVOKE_PATH)));
        // No async poll should be scheduled for a synchronous revoke
        mockServer.verify(0, WireMock.postRequestedFor(WireMock.urlEqualTo("/v3/authorityProvider/certificates/revoke/status")));
    }

    @Test
    void listIssueAttributes_v3WireBodyCarriesAuthorityAndRaProfileAttrs() throws Exception {
        // The v3 /issue/attributes body must be a CertificateAttributeListRequestDto carrying
        // BOTH authorityAttributes (to identify/authenticate the upstream CA) AND
        // raProfileAttributes (to scope the returned dynamic-attribute schema to a specific
        // profile). A bare List<RequestAttribute> would be ambiguous and prevent
        // profile-specific schemas. Regression guard for M4-D4.
        String v3IssueAttrs = "/v3/authorityProvider/certificates/issue/attributes";
        mockServer.stubFor(WireMock.post(WireMock.urlEqualTo(v3IssueAttrs))
                .willReturn(WireMock.okJson("[]")));

        var issueAttrs = clientOperationService.listIssueCertificateAttributes(
                SecuredParentUUID.fromUUID(authority.getUuid()),
                raProfile.getSecuredUuid());
        assertEquals(0, issueAttrs.size(), "stubbed empty schema");

        // Substring match — matchingJsonPath treats empty arrays as absent in WireMock; we just
        // need both field names present in the serialized body.
        mockServer.verify(1, WireMock.postRequestedFor(WireMock.urlEqualTo(v3IssueAttrs))
                .withRequestBody(WireMock.containing("\"authorityAttributes\""))
                .withRequestBody(WireMock.containing("\"raProfileAttributes\"")));
    }

    @Test
    void operatorRevoke_onV3Authority_validatesViaV3NotV2() throws Exception {
        // M4-D1: the operator-facing revokeCertificate pre-validates revoke attributes. It must
        // route through the v3 /revoke/attributes endpoint, NOT the legacy v2
        // /v2/authorityProvider/authorities/{uuid}/certificates/revoke/attributes endpoints.
        String v3RevokeAttrs = "/v3/authorityProvider/certificates/revoke/attributes";
        mockServer.stubFor(WireMock.post(WireMock.urlEqualTo(v3RevokeAttrs))
                .willReturn(WireMock.okJson("[]")));
        // If the v2 path is hit, fail loudly (no stub → 404 → ConnectorException).

        Certificate cert = buildCertificateInState(CertificateState.ISSUED);

        ClientCertificateRevocationDto revokeReq = new ClientCertificateRevocationDto();
        revokeReq.setReason(CertificateRevocationReason.UNSPECIFIED);
        revokeReq.setAttributes(List.<RequestAttribute>of());

        // Should not throw — validation resolves via the v3 adapter; the actual revoke is
        // enqueued as an ActionMessage (JMS mocked in the test profile).
        clientOperationService.revokeCertificate(
                SecuredParentUUID.fromUUID(authority.getUuid()),
                raProfile.getSecuredUuid(),
                cert.getUuid().toString(),
                revokeReq);

        mockServer.verify(1, WireMock.postRequestedFor(WireMock.urlEqualTo(v3RevokeAttrs)));
        mockServer.verify(0, WireMock.postRequestedFor(
                WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/revoke/attributes.*")));
    }
}

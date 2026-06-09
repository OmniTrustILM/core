package com.czertainly.core.service.v3;

import com.otilm.api.model.client.certificate.CancelPendingCertificateRequestDto;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.exception.ValidationException;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.v2.ClientOperationService;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Three cancel scenarios against a v3 connector:
 * 1. 204 → CANCELLED → cert transitions PENDING_ISSUE → FAILED.
 * 2. 404 with OPERATION_NOT_TRACKED → treated as soft success → cert transitions to FAILED.
 * 3. 422 with OPERATION_PAST_POINT_OF_NO_RETURN → hard refusal → cert stays PENDING_ISSUE.
 */
class V3CancelOperationITest extends BaseV3ITest {

    @Autowired
    @Qualifier("clientOperationServiceImplV2")
    private ClientOperationService clientOperationService;

    @Test
    void cancelReturns204_certTransitionsToFailed() throws Exception {
        // Stub: cancel returns 204 No Content
        mockServer.stubFor(WireMock.post(WireMock.urlEqualTo(V3_ISSUE_CANCEL_PATH))
                .willReturn(WireMock.aResponse().withStatus(204)));

        Certificate cert = buildCertificateInState(CertificateState.PENDING_ISSUE);

        CancelPendingCertificateRequestDto req = new CancelPendingCertificateRequestDto();
        req.setReason("test cancel 204");

        clientOperationService.cancelPendingCertificateOperation(
                SecuredParentUUID.fromUUID(authority.getUuid()),
                raProfile.getSecuredUuid(),
                cert.getUuid().toString(),
                req);

        Certificate refreshed = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertEquals(CertificateState.FAILED, refreshed.getState(),
                "After 204 cancel, cert should be FAILED");
        mockServer.verify(1, WireMock.postRequestedFor(WireMock.urlEqualTo(V3_ISSUE_CANCEL_PATH)));
    }

    @Test
    void cancelReturns404NotTracked_certStillTransitionsToFailed() throws Exception {
        // Stub: cancel returns 404 with OPERATION_NOT_TRACKED — problem+json so it parses as ConnectorProblemException
        mockServer.stubFor(WireMock.post(WireMock.urlEqualTo(V3_ISSUE_CANCEL_PATH))
                .willReturn(WireMock.aResponse()
                        .withStatus(404)
                        .withHeader("Content-Type", "application/problem+json")
                        .withBody(problemJsonBody("OPERATION_NOT_TRACKED"))));

        Certificate cert = buildCertificateInState(CertificateState.PENDING_ISSUE);

        CancelPendingCertificateRequestDto req = new CancelPendingCertificateRequestDto();
        req.setReason("test cancel 404");

        clientOperationService.cancelPendingCertificateOperation(
                SecuredParentUUID.fromUUID(authority.getUuid()),
                raProfile.getSecuredUuid(),
                cert.getUuid().toString(),
                req);

        Certificate refreshed = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        // NOT_TRACKED is treated as a soft success: the connector doesn't know about it,
        // so we proceed with local cancel → FAILED.
        assertEquals(CertificateState.FAILED, refreshed.getState(),
                "After 404 NOT_TRACKED, cert should still be FAILED (local cancel proceeds)");
        mockServer.verify(1, WireMock.postRequestedFor(WireMock.urlEqualTo(V3_ISSUE_CANCEL_PATH)));
    }

    @Test
    void cancelReturns422PastPointOfNoReturn_certStaysPendingIssue() throws Exception {
        // Stub: cancel returns 422 with OPERATION_PAST_POINT_OF_NO_RETURN
        mockServer.stubFor(WireMock.post(WireMock.urlEqualTo(V3_ISSUE_CANCEL_PATH))
                .willReturn(WireMock.aResponse()
                        .withStatus(422)
                        .withHeader("Content-Type", "application/problem+json")
                        .withBody(problemJsonBody("OPERATION_PAST_POINT_OF_NO_RETURN"))));

        Certificate cert = buildCertificateInState(CertificateState.PENDING_ISSUE);

        CancelPendingCertificateRequestDto req = new CancelPendingCertificateRequestDto();
        req.setReason("test cancel 422 past ponr");

        assertThrows(ValidationException.class, () ->
                clientOperationService.cancelPendingCertificateOperation(
                        SecuredParentUUID.fromUUID(authority.getUuid()),
                        raProfile.getSecuredUuid(),
                        cert.getUuid().toString(),
                        req),
                "422 PAST_POINT_OF_NO_RETURN must throw ValidationException");

        Certificate refreshed = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();
        assertEquals(CertificateState.PENDING_ISSUE, refreshed.getState(),
                "After hard refusal, cert must stay in PENDING_ISSUE");
        mockServer.verify(1, WireMock.postRequestedFor(WireMock.urlEqualTo(V3_ISSUE_CANCEL_PATH)));
    }
}

package com.otilm.core.api.tsp;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.core.aop.AuditResultOverride;
import com.otilm.core.signing.tsa.TsaService;
import com.otilm.core.signing.tsa.messages.TspResponse;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import java.math.BigInteger;
import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TspSigningProfileControllerImplTest {

    private static final String PROFILE_NAME = "test-signing-profile";

    private TsaService tsaService;
    private AuditResultOverride auditResultOverride;
    private TspSigningProfileControllerImpl controller;

    @BeforeEach
    void setUp() {
        tsaService = mock(TsaService.class);
        auditResultOverride = mock(AuditResultOverride.class);
        controller = new TspSigningProfileControllerImpl(tsaService, auditResultOverride);
    }

    @Test
    void serviceReturnsGranted_wrapsTokenInGrantedResponse() throws Exception {
        // given
        var timestampToken = contentInfoBytes();
        when(tsaService.processTspRequestForSigningProfile(eq(PROFILE_NAME), any()))
                .thenReturn(TspResponse.granted(timestampToken));

        // when
        ResponseEntity<byte[]> response = controller.timestamp(PROFILE_NAME, validSha256RequestBytes());

        // then
        assertEquals(200, response.getStatusCode().value());
        TimeStampResp decoded = TimeStampResp.getInstance(response.getBody());
        assertEquals(PKIStatus.GRANTED, decoded.getStatus().getStatus().intValueExact());
        assertNotNull(decoded.getTimeStampToken(), "granted response must carry the timestamp token");
        assertArrayEquals(timestampToken, decoded.getTimeStampToken().getEncoded("DER"));
        verify(auditResultOverride, never()).setFailure();
    }

    @Test
    void serviceReturnsRejected_buildsRejectionWithServiceFailureInfo() throws Exception {
        // given
        var serviceFailureInfo = TspFailureInfo.UNACCEPTED_POLICY;
        var serviceStatusString = "Policy not accepted";
        when(tsaService.processTspRequestForSigningProfile(eq(PROFILE_NAME), any()))
                .thenReturn(TspResponse.rejected(serviceFailureInfo, serviceStatusString));

        // when
        ResponseEntity<byte[]> response = controller.timestamp(PROFILE_NAME, validSha256RequestBytes());

        // then
        assertRejection(response, PKIFailureInfo.unacceptedPolicy, serviceStatusString);
        verify(auditResultOverride).setFailure();
    }

    @Test
    void serviceThrowsTspException_buildsRejectionWithClientMessageNotInternalMessage() throws Exception {
        // given
        var failureInfo = TspFailureInfo.BAD_ALG;
        var internalMessage = "Unknown hash algorithm OID: 1.2.3.4 leaked-detail";
        var clientMessage = "Unknown hash algorithm";
        when(tsaService.processTspRequestForSigningProfile(eq(PROFILE_NAME), any()))
                .thenThrow(new TspException(failureInfo, internalMessage, clientMessage));

        // when
        ResponseEntity<byte[]> response = controller.timestamp(PROFILE_NAME, validSha256RequestBytes());

        // then
        assertRejection(response, PKIFailureInfo.badAlg, clientMessage);
        verify(auditResultOverride).setFailure();
    }

    @Test
    void serviceThrowsNotFound_buildsBadRequestRejection() throws Exception {
        // given
        when(tsaService.processTspRequestForSigningProfile(eq(PROFILE_NAME), any()))
                .thenThrow(new NotFoundException("SigningProfile", PROFILE_NAME));

        // when
        ResponseEntity<byte[]> response = controller.timestamp(PROFILE_NAME, validSha256RequestBytes());

        // then
        assertRejection(response, PKIFailureInfo.badRequest, "Resource not found. See logs for details.");
        verify(auditResultOverride).setFailure();
    }

    @Test
    void serviceThrowsUnexpectedException_buildsSystemFailureRejection() throws Exception {
        // given
        var leakyMessage = "could not execute statement; SQL [n/a]; constraint [signing_profile_pkey]";
        when(tsaService.processTspRequestForSigningProfile(eq(PROFILE_NAME), any()))
                .thenThrow(new RuntimeException(leakyMessage));

        // when
        ResponseEntity<byte[]> response = controller.timestamp(PROFILE_NAME, validSha256RequestBytes());

        // then
        assertRejection(response, PKIFailureInfo.systemFailure, "An unexpected error occurred during timestamping.");
        verify(auditResultOverride).setFailure();
    }

    @Test
    void malformedRequest_buildsBadRequestRejectionWithoutCallingService() {
        // given
        var malformedRequest = new byte[]{0x00, 0x01, 0x02, 0x03};

        // when
        ResponseEntity<byte[]> response = controller.timestamp(PROFILE_NAME, malformedRequest);

        // then
        assertRejection(response, PKIFailureInfo.badRequest, "Malformed request");
        verify(auditResultOverride).setFailure();
    }

    private static void assertRejection(ResponseEntity<byte[]> response, int expectedFailInfo, String expectedStatusString) {
        assertEquals(200, response.getStatusCode().value());
        byte[] body = response.getBody();
        assertNotNull(body);
        TimeStampResponse decoded = decode(body);
        assertEquals(PKIStatus.REJECTION, decoded.getStatus());
        assertNotNull(decoded.getFailInfo(), "rejection must carry a PKIFailureInfo");
        assertEquals(expectedFailInfo, decoded.getFailInfo().intValue());
        assertEquals(expectedStatusString, decoded.getStatusString());
    }

    private static TimeStampResponse decode(byte[] body) {
        try {
            return new TimeStampResponse(body);
        } catch (Exception e) {
            throw new IllegalStateException("Response is not a valid RFC 3161 TimeStampResp", e);
        }
    }

    /**
     * Minimal well-formed CMS {@link ContentInfo} standing in for a timestamp token. The controller's granted
     * branch only re-wraps these bytes — it never inspects the token content — so a real signed SignedData/TSTInfo
     * (exercised end-to-end by {@code TspProtocolFlowITest}) is unnecessary here.
     */
    private static byte[] contentInfoBytes() throws Exception {
        var content = new DEROctetString(new byte[]{1, 2, 3});
        return new ContentInfo(CMSObjectIdentifiers.signedData, content).getEncoded("DER");
    }

    private static byte[] validSha256RequestBytes() throws Exception {
        byte[] imprint = MessageDigest.getInstance("SHA-256").digest("payload".getBytes());
        var nonce = BigInteger.valueOf(42);
        return new TimeStampRequestGenerator().generate(TSPAlgorithms.SHA256, imprint, nonce).getEncoded();
    }
}

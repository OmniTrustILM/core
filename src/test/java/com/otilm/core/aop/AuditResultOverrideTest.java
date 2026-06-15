package com.otilm.core.aop;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.core.api.tsp.TspControllerImpl;
import com.otilm.core.signing.tsa.TsaService;
import com.otilm.core.signing.tsa.messages.TspResponse;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuditResultOverrideTest {

    private static final String PROFILE_NAME = "test-tsp-profile";

    private TsaService tsaService;
    private AuditResultOverride auditResultOverride;
    private TspControllerImpl controller;

    @BeforeEach
    void setUp() {
        tsaService = mock(TsaService.class);
        auditResultOverride = new AuditResultOverride();
        controller = new TspControllerImpl();
        controller.setTspService(tsaService);
        controller.setAuditResultOverride(auditResultOverride);
    }

    // ── Bean mechanics ────────────────────────────────────────────────────────

    @Test
    void get_whenNothingSet_returnsNull() {
        // given — a fresh instance

        // when
        OperationResult result = auditResultOverride.get();

        // then
        assertNull(result);
    }

    @Test
    void get_afterSetFailure_returnsFailure() {
        // given
        auditResultOverride.setFailure();

        // when
        OperationResult result = auditResultOverride.get();

        // then
        assertEquals(OperationResult.FAILURE, result);
    }

    // ── TspControllerImpl sets the override on every rejection path ───────────

    @Test
    void tspController_setsFailureOverride_whenTspExceptionThrown() throws Exception {
        // given
        var failureInfo = TspFailureInfo.BAD_ALG;
        when(tsaService.processTspRequestForTspProfile(eq(PROFILE_NAME), any()))
                .thenThrow(new TspException(failureInfo, "internal detail", "client message"));

        // when
        controller.timestamp(PROFILE_NAME, validSha256RequestBytes());

        // then
        assertEquals(OperationResult.FAILURE, auditResultOverride.get());
    }

    @Test
    void tspController_setsFailureOverride_whenNotFoundExceptionThrown() throws Exception {
        // given
        when(tsaService.processTspRequestForTspProfile(eq(PROFILE_NAME), any()))
                .thenThrow(new NotFoundException("TspProfile", PROFILE_NAME));

        // when
        controller.timestamp(PROFILE_NAME, validSha256RequestBytes());

        // then
        assertEquals(OperationResult.FAILURE, auditResultOverride.get());
    }

    @Test
    void tspController_setsFailureOverride_whenUnexpectedExceptionThrown() throws Exception {
        // given
        when(tsaService.processTspRequestForTspProfile(eq(PROFILE_NAME), any()))
                .thenThrow(new RuntimeException("unexpected failure"));

        // when
        controller.timestamp(PROFILE_NAME, validSha256RequestBytes());

        // then
        assertEquals(OperationResult.FAILURE, auditResultOverride.get());
    }

    @Test
    void tspController_doesNotSetFailureOverride_whenGranted() throws Exception {
        // given
        when(tsaService.processTspRequestForTspProfile(eq(PROFILE_NAME), any()))
                .thenReturn(TspResponse.granted(contentInfoBytes()));

        // when
        controller.timestamp(PROFILE_NAME, validSha256RequestBytes());

        // then
        assertNull(auditResultOverride.get());
    }

    @Test
    void tspController_setsFailureOverride_whenRequestIsMalformed() {
        // given
        var malformedRequest = new byte[]{0x00, 0x01, 0x02, 0x03};

        // when — parser throws TspException before the service is even called
        controller.timestamp(PROFILE_NAME, malformedRequest);

        // then
        assertEquals(OperationResult.FAILURE, auditResultOverride.get());
    }

    // ── Test data helpers ─────────────────────────────────────────────────────

    private static byte[] contentInfoBytes() throws Exception {
        var content = new DEROctetString(new byte[]{1, 2, 3});
        return new ContentInfo(CMSObjectIdentifiers.signedData, content).getEncoded("DER");
    }

    private static byte[] validSha256RequestBytes() throws Exception {
        byte[] imprint = MessageDigest.getInstance("SHA-256").digest("payload".getBytes());
        return new TimeStampRequestGenerator().generate(TSPAlgorithms.SHA256, imprint, BigInteger.valueOf(42)).getEncoded();
    }
}

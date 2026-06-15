package com.otilm.core.service.handler.authority;

import com.otilm.api.model.connector.v3.certificate.CertificateOperationStatus;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AdapterOperationResultTest {

    @Test
    void syncOkFactory() {
        AdapterOperationResult r = AdapterOperationResult.syncOk("data", List.of(), null);
        assertEquals(AdapterOperationOutcome.SYNC_OK, r.outcome());
        assertEquals("data", r.certificateData());
        assertFalse(r.isAsync());
    }

    @Test
    void asyncAcceptedFactory() {
        AdapterOperationResult r = AdapterOperationResult.asyncAccepted(List.of());
        assertEquals(AdapterOperationOutcome.ASYNC_ACCEPTED, r.outcome());
        assertNull(r.certificateData());
        assertTrue(r.isAsync());
    }

    @Test
    void syncNoContentFactory() {
        AdapterOperationResult r = AdapterOperationResult.syncNoContent();
        assertEquals(AdapterOperationOutcome.SYNC_NO_CONTENT, r.outcome());
        assertFalse(r.isAsync());
    }

    @Test
    void cancelOutcomeAllValues() {
        assertNotNull(CancelOutcome.CANCELLED);
        assertNotNull(CancelOutcome.NOT_TRACKED);
        assertNotNull(CancelOutcome.REFUSED_PAST_POINT_OF_NO_RETURN);
    }

    @Test
    void certificateOperationAllValues() {
        assertNotNull(CertificateOperation.ISSUE);
        assertNotNull(CertificateOperation.RENEW);
        assertNotNull(CertificateOperation.REVOKE);
        assertNotNull(CertificateOperation.REGISTER);
    }

    @Test
    void statusPollResultRecord() {
        StatusPollResult r = new StatusPollResult(CertificateOperationStatus.COMPLETED, "data", List.of(), null);
        assertEquals(CertificateOperationStatus.COMPLETED, r.status());
        assertEquals("data", r.certificateData());
    }

    @Test
    void cancelResultRecord() {
        CancelResult r = new CancelResult(CancelOutcome.CANCELLED);
        assertEquals(CancelOutcome.CANCELLED, r.outcome());
    }
}

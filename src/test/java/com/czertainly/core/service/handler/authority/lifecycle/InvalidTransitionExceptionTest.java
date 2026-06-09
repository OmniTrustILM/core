package com.czertainly.core.service.handler.authority.lifecycle;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InvalidTransitionExceptionTest {

    @Test
    void messageIncludesFromAndToStateLabels() {
        UUID uuid = UUID.randomUUID();
        InvalidTransitionException ex = new InvalidTransitionException(
            Resource.CERTIFICATE, uuid,
            CertificateState.REVOKED, CertificateState.ISSUED);

        assertTrue(ex.getMessage().contains(uuid.toString()),
            "message should contain UUID: " + ex.getMessage());
        assertTrue(ex.getMessage().contains(CertificateState.REVOKED.getLabel()),
            "message should contain from-state label: " + ex.getMessage());
        assertTrue(ex.getMessage().contains(CertificateState.ISSUED.getLabel()),
            "message should contain to-state label: " + ex.getMessage());
        assertEquals(Resource.CERTIFICATE, ex.getResource());
        assertEquals(uuid, ex.getResourceUuid());
        assertEquals(CertificateState.REVOKED, ex.getFromState());
        assertEquals(CertificateState.ISSUED, ex.getToStateAttempted());
    }
}

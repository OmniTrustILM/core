package com.czertainly.core.service.acme.impl;

import com.otilm.api.model.core.authority.CertificateRevocationReason;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

public class ExtendedAcmeHelperServiceTest {

    @Test
    public void testRevokeCertificate_wrongReason() {
        int code = 123;
        final CertificateRevocationReason reason = CertificateRevocationReason.fromReasonCode(code);

        Assertions.assertNull(reason);
        final String details = "Allowed revocation reason codes: " + Arrays.toString(Arrays.stream(CertificateRevocationReason.values()).map(CertificateRevocationReason::getReasonCode).toArray());

        Assertions.assertTrue(details.contains("[0"));
    }

}

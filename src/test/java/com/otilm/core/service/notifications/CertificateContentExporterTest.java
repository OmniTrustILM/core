package com.otilm.core.service.notifications;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertificateContentExporterTest {

    @Mock
    private CertificateRepository certificateRepository;

    private CertificateContentExporter exporter() {
        return new CertificateContentExporter(certificateRepository);
    }

    @Test
    void exportsStoredBase64DerForIssuedCertificate() {
        UUID certificateUuid = UUID.randomUUID();
        Certificate certificate = mock(Certificate.class);
        when(certificate.getContentData()).thenReturn("MIIBbase64der");
        when(certificateRepository.findByUuid(certificateUuid)).thenReturn(Optional.of(certificate));

        assertEquals(Optional.of("MIIBbase64der"), exporter().export(certificateUuid));
    }

    @Test
    void certificateWithoutStoredContentYieldsNothing() {
        // Request and pre-registered states have no DER yet; absence is best-effort, not an error.
        UUID certificateUuid = UUID.randomUUID();
        Certificate certificate = mock(Certificate.class);
        when(certificate.getContentData()).thenReturn(null);
        when(certificateRepository.findByUuid(certificateUuid)).thenReturn(Optional.of(certificate));

        assertTrue(exporter().export(certificateUuid).isEmpty());
    }

    @Test
    void missingCertificateYieldsNothing() {
        UUID certificateUuid = UUID.randomUUID();
        when(certificateRepository.findByUuid(certificateUuid)).thenReturn(Optional.empty());

        assertTrue(exporter().export(certificateUuid).isEmpty());
    }

    @Test
    void declaresCertificateResourceAndDerFormat() {
        assertEquals(Resource.CERTIFICATE, exporter().resource());
        assertEquals("X509_DER_BASE64", exporter().format());
    }
}

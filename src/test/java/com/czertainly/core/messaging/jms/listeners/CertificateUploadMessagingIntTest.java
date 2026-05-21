package com.czertainly.core.messaging.jms.listeners;

import com.czertainly.api.model.client.certificate.UploadCertificateRequestDto;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.helpers.CertificateGeneratorHelper;
import com.czertainly.core.service.CertificateService;
import com.czertainly.core.util.BaseMessagingIntTest;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;

import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * End-to-end integration test for the certificate upload async flow using a real RabbitMQ container.
 *
 * <p>Flow: {@link CertificateService#uploadAsync} → EventProducer → RabbitMQ exchange/queue →
 * EventListener → CertificateUploadedEventHandler → certificate persisted in DB.</p>
 *
 * <p>Kept separate from {@link JmsListenerIntegrationTest} because that class mocks
 * {@code EventListener} at the bean level, which prevents the real handler chain from running.</p>
 */
@ActiveProfiles(value = {"messaging-int-test"}, inheritProfiles = false)
class CertificateUploadMessagingIntTest extends BaseMessagingIntTest {

    @Autowired
    private CertificateService certificateService;

    @Autowired
    private CertificateRepository certificateRepository;

    @Test
    void testCertificateUploadedEvent() throws Exception {
        X509Certificate certificate = CertificateGeneratorHelper.generateCACertificate(null, "CN=TestCA");
        String content = Base64.getEncoder().encodeToString(certificate.getEncoded());
        UploadCertificateRequestDto request = new UploadCertificateRequestDto();
        request.setCertificate(content);

        String fingerprint = certificateService.uploadAsync(request).getFingerprint();

        assertThat(fingerprint).isNotNull();
        await().atMost(10, TimeUnit.SECONDS).until(() ->
                certificateRepository.findByFingerprint(fingerprint).isPresent()
        );
        Assertions.assertTrue(certificateRepository.findByFingerprint(fingerprint).isPresent());
    }
}

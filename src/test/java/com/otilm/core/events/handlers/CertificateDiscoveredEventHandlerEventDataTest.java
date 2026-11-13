package com.otilm.core.events.handlers;

import com.otilm.api.model.common.events.data.CertificateDiscoveredEventData;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.evaluator.CertificateTriggerEvaluator;
import com.otilm.core.util.CertificateUtil;
import java.util.Date;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class CertificateDiscoveredEventHandlerEventDataTest {

    @Mock
    private CertificateRepository certificateRepository;

    @Mock
    private CertificateTriggerEvaluator triggerEvaluator;

    private CertificateDiscoveredEventHandler handler;

    @BeforeEach
    void createHandler() {
        handler = new CertificateDiscoveredEventHandler(certificateRepository, triggerEvaluator);
    }

    @Test
    void namesTheCertificateByItsCommonName_whenBuildingTheDiscoveredEventData() {
        // given
        String commonName = "holder";
        X509CertificateEntity certificate = aCertificate()
                .withCommonName(commonName)
                .withNotBefore(new Date())
                .withNotAfter(new Date())
                .build();

        // when
        CertificateDiscoveredEventData eventData = (CertificateDiscoveredEventData) handler
                .getEventData(certificate, null);

        // then
        assertThat(eventData.getDisplayName()).isEqualTo(commonName);
    }

    @Test
    void namesTheCertificateByThePlaceholder_whenItHasNoCommonName() {
        // given
        X509CertificateEntity certificate = aCertificate()
                .withCommonName(null)
                .withNotBefore(new Date())
                .withNotAfter(new Date())
                .build();

        // when
        CertificateDiscoveredEventData eventData = (CertificateDiscoveredEventData) handler
                .getEventData(certificate, null);

        // then
        assertThat(eventData.getDisplayName()).isEqualTo(CertificateUtil.EMPTY_COMMON_NAME_PLACEHOLDER);
    }
}

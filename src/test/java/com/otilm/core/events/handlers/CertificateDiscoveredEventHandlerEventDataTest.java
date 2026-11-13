package com.otilm.core.events.handlers;

import com.otilm.api.model.common.events.data.CertificateDiscoveredEventData;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.evaluator.CertificateTriggerEvaluator;
import com.otilm.core.util.CertificateUtil;
import java.util.Date;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class CertificateDiscoveredEventHandlerEventDataTest {

    private final CertificateDiscoveredEventHandler handler = new CertificateDiscoveredEventHandler(
            mock(CertificateRepository.class), mock(CertificateTriggerEvaluator.class));

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
        var eventData = (CertificateDiscoveredEventData) handler.getEventData(certificate, null);

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
        var eventData = (CertificateDiscoveredEventData) handler.getEventData(certificate, null);

        // then
        assertThat(eventData.getDisplayName()).isEqualTo(CertificateUtil.EMPTY_COMMON_NAME_PLACEHOLDER);
    }
}

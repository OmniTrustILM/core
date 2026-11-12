package com.otilm.core.events.data;

import com.otilm.api.model.common.events.data.CertificateExpiringEventData;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.util.CertificateUtil;
import java.util.Date;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class EventDataBuilderTest {

    @Test
    void namesTheCertificateByItsCommonName_whenBuildingTheExpiringEventData() {
        // given
        X509CertificateEntity certificate = certificate("holder");

        // when
        CertificateExpiringEventData eventData = EventDataBuilder.getCertificateExpiringEventData(certificate);

        // then
        assertThat(eventData.getDisplayName()).isEqualTo("holder");
    }

    @Test
    void namesTheCertificateByThePlaceholder_whenItHasNoCommonName() {
        // given
        X509CertificateEntity certificate = certificate(null);

        // when
        CertificateExpiringEventData eventData = EventDataBuilder.getCertificateExpiringEventData(certificate);

        // then
        assertThat(eventData.getDisplayName()).isEqualTo(CertificateUtil.EMPTY_COMMON_NAME_PLACEHOLDER);
    }

    private static X509CertificateEntity certificate(String commonName) {
        var certificate = new X509CertificateEntity();
        certificate.setUuid(UUID.randomUUID());
        certificate.setCommonName(commonName);
        certificate.setNotBefore(new Date());
        certificate.setNotAfter(new Date());
        return certificate;
    }
}

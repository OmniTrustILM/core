package com.otilm.core.events.data;

import com.otilm.api.model.common.events.data.CertificateExpiringEventData;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.util.CertificateUtil;
import java.util.Date;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;

class EventDataBuilderTest {

    @Test
    void namesTheCertificateByItsCommonName_whenBuildingTheExpiringEventData() {
        // given
        String commonName = "holder";
        X509CertificateEntity certificate = aCertificate()
                .withCommonName(commonName)
                .withNotBefore(new Date())
                .withNotAfter(new Date())
                .build();

        // when
        CertificateExpiringEventData eventData = EventDataBuilder.getCertificateExpiringEventData(certificate);

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
        CertificateExpiringEventData eventData = EventDataBuilder.getCertificateExpiringEventData(certificate);

        // then
        assertThat(eventData.getDisplayName()).isEqualTo(CertificateUtil.EMPTY_COMMON_NAME_PLACEHOLDER);
    }
}

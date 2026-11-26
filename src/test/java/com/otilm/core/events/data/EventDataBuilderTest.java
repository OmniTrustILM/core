package com.otilm.core.events.data;

import com.otilm.api.model.common.events.data.CertificateExpiringEventData;
import com.otilm.api.model.common.events.data.CertificateRenewalDueEventData;
import com.otilm.api.model.core.certificate.RenewalWindowSource;
import com.otilm.core.dao.entity.CertificateRenewalInfo;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.util.CertificateUtil;
import java.time.Instant;
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

    @Test
    void copiesTheRenewalWindow_whenBuildingTheRenewalDueEventData() {
        // given
        var windowStart = Instant.parse("2026-12-01T10:00:00Z");
        var windowEnd = Instant.parse("2026-12-08T10:00:00Z");
        var explanationUrl = "https://ca.example.com/why";
        X509CertificateEntity certificate = aCertificate()
                .withCommonName("holder")
                .withNotBefore(new Date())
                .withNotAfter(new Date())
                .build();
        CertificateRenewalInfo renewalInfo = new CertificateRenewalInfo();
        renewalInfo.setWindowStart(windowStart);
        renewalInfo.setWindowEnd(windowEnd);
        renewalInfo.setExplanationUrl(explanationUrl);
        renewalInfo.setSource(RenewalWindowSource.AUTHORITY);
        renewalInfo.setAdvanced(true);
        certificate.setRenewalInfo(renewalInfo);

        // when
        CertificateRenewalDueEventData eventData = EventDataBuilder.getCertificateRenewalDueEventData(certificate);

        // then
        assertThat(eventData.getWindowStart().toInstant()).isEqualTo(windowStart);
        assertThat(eventData.getWindowEnd().toInstant()).isEqualTo(windowEnd);
        assertThat(eventData.getExplanationUrl()).isEqualTo(explanationUrl);
        assertThat(eventData.getSource()).isEqualTo(RenewalWindowSource.AUTHORITY);
        assertThat(eventData.isAdvanced()).isTrue();
        assertThat(eventData.getDisplayName()).isEqualTo("holder");
        assertThat(eventData.getExpiresAt()).isNotNull();
    }

    @Test
    void leavesTheWindowEmpty_whenTheCertificateHasNoRenewalWindow() {
        // given
        X509CertificateEntity certificate = aCertificate().withNotBefore(new Date()).withNotAfter(new Date()).build();

        // when
        CertificateRenewalDueEventData eventData = EventDataBuilder.getCertificateRenewalDueEventData(certificate);

        // then
        assertThat(eventData.getWindowStart()).isNull();
        assertThat(eventData.getWindowEnd()).isNull();
        assertThat(eventData.getSource()).isNull();
        assertThat(eventData.isAdvanced()).isFalse();
    }
}

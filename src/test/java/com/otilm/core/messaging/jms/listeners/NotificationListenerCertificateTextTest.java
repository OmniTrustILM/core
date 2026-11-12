package com.otilm.core.messaging.jms.listeners;

import com.otilm.api.model.common.events.data.CertificateEventData;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class NotificationListenerCertificateTextTest {

    @Test
    void describesTheCertificateByDnSerialNumberAndIssuer_whenItHasAll() {
        // given
        String subjectDn = "CN=holder";
        String serialNumber = "1a2b";
        String issuerDn = "CN=issuer";
        var data = eventData("holder", subjectDn, serialNumber, issuerDn);

        // when
        String text = NotificationListener.describeCertificate(data);

        // then
        assertThat(text)
                .isEqualTo("identified as '%s' with serial number '%s' issued by '%s'"
                        .formatted(subjectDn, serialNumber, issuerDn));
    }

    @Test
    void describesTheCertificateByDisplayNameOnly_whenItsTypeHasNoDnSerialNumberOrIssuer() {
        // given
        String displayName = "ssh-key-id";
        var data = eventData(displayName, null, null, null);

        // when
        String text = NotificationListener.describeCertificate(data);

        // then
        assertThat(text).isEqualTo("identified as '%s'".formatted(displayName));
    }

    @Test
    void leavesOutTheSerialNumber_whenTheCertificateIsRegisteredAndNotIssued() {
        // given
        String subjectDn = "CN=holder";
        String issuerDn = "CN=issuer";
        var data = eventData("holder", subjectDn, null, issuerDn);

        // when
        String text = NotificationListener.describeCertificate(data);

        // then
        assertThat(text).isEqualTo("identified as '%s' issued by '%s'".formatted(subjectDn, issuerDn));
    }

    @Test
    void givesNoIssuanceDetail_whenTheCertificateHasNeitherSerialNumberNorIssuer() {
        // given
        var data = eventData("ssh-key-id", null, null, null);

        // when
        String detail = NotificationListener.describeIssuance(data);

        // then
        assertThat(detail).isNull();
    }

    @Test
    void givesOnlyTheSerialNumber_whenTheCertificateHasNoIssuer() {
        // given
        String serialNumber = "1a2b";
        var data = eventData("holder", null, serialNumber, null);

        // when
        String detail = NotificationListener.describeIssuance(data);

        // then
        assertThat(detail).isEqualTo("Certificate serial number '%s'".formatted(serialNumber));
    }

    @Test
    void givesOnlyTheIssuer_whenTheCertificateHasNoSerialNumber() {
        // given
        String issuerDn = "CN=issuer";
        var data = eventData("holder", null, null, issuerDn);

        // when
        String detail = NotificationListener.describeIssuance(data);

        // then
        assertThat(detail).isEqualTo("Certificate issued by '%s'".formatted(issuerDn));
    }

    @Test
    void givesTheSerialNumberAndTheIssuer_whenTheCertificateHasBoth() {
        // given
        String serialNumber = "1a2b";
        String issuerDn = "CN=issuer";
        var data = eventData("holder", null, serialNumber, issuerDn);

        // when
        String detail = NotificationListener.describeIssuance(data);

        // then
        assertThat(detail).isEqualTo("Certificate serial number '%s' issued by '%s'".formatted(serialNumber, issuerDn));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static CertificateEventData eventData(String displayName, String subjectDn, String serialNumber,
            String issuerDn) {
        var data = new CertificateEventData();
        data.setDisplayName(displayName);
        data.setSubjectDn(subjectDn);
        data.setSerialNumber(serialNumber);
        data.setIssuerDn(issuerDn);
        return data;
    }
}

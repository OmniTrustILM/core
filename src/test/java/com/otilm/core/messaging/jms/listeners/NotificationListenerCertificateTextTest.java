package com.otilm.core.messaging.jms.listeners;

import com.otilm.api.model.common.events.data.CertificateEventData;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class NotificationListenerCertificateTextTest {

    @Test
    void describesTheCertificateByDnSerialNumberAndIssuer_whenItHasAll() {
        // given
        var data = new CertificateEventData();
        data.setDisplayName("holder");
        data.setSubjectDn("CN=holder");
        data.setSerialNumber("1a2b");
        data.setIssuerDn("CN=issuer");

        // when
        String text = NotificationListener.describeCertificate(data);

        // then
        assertThat(text).isEqualTo("identified as 'CN=holder' with serial number '1a2b' issued by 'CN=issuer'");
    }

    @Test
    void describesTheCertificateByDisplayNameOnly_whenItsTypeHasNoDnSerialNumberOrIssuer() {
        // given
        var data = new CertificateEventData();
        data.setDisplayName("ssh-key-id");

        // when
        String text = NotificationListener.describeCertificate(data);

        // then
        assertThat(text).isEqualTo("identified as 'ssh-key-id'");
    }

    @Test
    void leavesOutTheSerialNumber_whenTheCertificateIsRegisteredAndNotIssued() {
        // given
        var data = new CertificateEventData();
        data.setDisplayName("holder");
        data.setSubjectDn("CN=holder");
        data.setIssuerDn("CN=issuer");

        // when
        String text = NotificationListener.describeCertificate(data);

        // then
        assertThat(text).isEqualTo("identified as 'CN=holder' issued by 'CN=issuer'");
    }
}

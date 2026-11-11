package com.otilm.core.certificate.type;

import com.otilm.api.model.core.enums.CertificateRequestFormat;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ParsedContentEqualityTest {

    @Test
    void treatsCertificatesWithTheSameContentAsEqual() {
        // given
        var first = new ParsedCertificate("X.509", new byte[]{1, 2, 3}, null);
        var second = new ParsedCertificate("X.509", new byte[]{1, 2, 3}, null);

        // when
        boolean equal = first.equals(second);

        // then
        assertThat(equal).isTrue();
        assertThat(first).hasSameHashCodeAs(second);
    }

    @Test
    void treatsCertificatesWithOtherContentAsDifferent() {
        // given
        var first = new ParsedCertificate("X.509", new byte[]{1, 2, 3}, null);
        var other = new ParsedCertificate("X.509", new byte[]{1, 2, 4}, null);

        // when
        boolean equal = first.equals(other);

        // then
        assertThat(equal).isFalse();
    }

    @Test
    void treatsRequestsWithTheSameContentAsEqual() {
        // given
        var first = new ParsedRequest("X.509", CertificateRequestFormat.PKCS10, new byte[]{1, 2}, "holder", null);
        var second = new ParsedRequest("X.509", CertificateRequestFormat.PKCS10, new byte[]{1, 2}, "holder", null);

        // when
        boolean equal = first.equals(second);

        // then
        assertThat(equal).isTrue();
        assertThat(first).hasSameHashCodeAs(second);
    }

    @Test
    void showsTheSizeAndNotTheBytes_whenPrintingAParsedRequest() {
        // given
        var request = new ParsedRequest("X.509", CertificateRequestFormat.PKCS10, new byte[]{1, 2}, "holder", null);

        // when
        String printed = request.toString();

        // then
        assertThat(printed).contains("2 bytes").doesNotContain("[B@");
    }
}

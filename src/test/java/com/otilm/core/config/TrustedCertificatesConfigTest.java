package com.otilm.core.config;

import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.util.X509ObjectToString;
import java.security.cert.X509Certificate;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TrustedCertificatesConfigTest {

    private static final String TRUSTED_CERTIFICATES_PROPERTY = "trusted.certificates";

    @AfterEach
    void clearTrustedCertificatesProperty() {
        System.clearProperty(TRUSTED_CERTIFICATES_PROPERTY);
    }

    @Test
    void exposesTheParsedCertificates_whenTheBundleIsProvided() throws Exception {
        // given
        var root = CertificateGeneratorHelper.generateCACertificate(null, "CN=Test Root CA");
        var intermediate = CertificateGeneratorHelper.generateCACertificate(null, "CN=Test Intermediate CA");
        System
                .setProperty(TRUSTED_CERTIFICATES_PROPERTY,
                        X509ObjectToString.toPem(root) + "\n" + X509ObjectToString.toPem(intermediate));
        var config = new TrustedCertificatesConfig();

        // when
        config.configureGlobalTrustStore();
        List<X509Certificate> trusted = config.getTrustedCertificates();

        // then
        assertThat(trusted).containsExactly(root, intermediate);
    }

    @Test
    void exposesNoCertificates_whenNoBundleIsProvided() throws Exception {
        // given — neither TRUSTED_CERTIFICATES nor trusted.certificates is set
        var config = new TrustedCertificatesConfig();

        // when
        config.configureGlobalTrustStore();
        List<X509Certificate> trusted = config.getTrustedCertificates();

        // then
        assertThat(trusted).isEmpty();
    }
}

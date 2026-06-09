package com.otilm.core.config;

import com.otilm.core.util.CertificateUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigureOrder;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

import jakarta.annotation.PostConstruct;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

@Configuration
@AutoConfigureOrder(Ordered.HIGHEST_PRECEDENCE)
public class TrustedCertificatesConfig {

    private static final Logger logger = LoggerFactory.getLogger(TrustedCertificatesConfig.class);

    private static final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
    private static final String END_CERTIFICATE = "-----END CERTIFICATE-----";

    private TrustManager[] trustManagers;

    @PostConstruct
    public void configureGlobalTrustStore() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, KeyManagementException {
        KeyStore trustStore = loadCacertsKeyStore();

        String certString = System.getenv("TRUSTED_CERTIFICATES");
        if (certString == null) {
            // try to load from properties
            certString = System.getProperty("trusted.certificates");
        }

        if (certString != null) {
            logger.info("Adding additional trusted certificates to cacerts");
            List<X509Certificate> certificates = getTrustedCertificates(certString);

            int i = 0;
            for (X509Certificate certificate : certificates) {
                trustStore.setCertificateEntry("czertainly-trusted-" + i, certificate);
                logger.info("Certificate with serial number '{}' and DN '{}' added with alias '{}'",
                        certificate.getSerialNumber().toString(16),
                        certificate.getSubjectX500Principal(),
                        "czertainly-trusted-" + i);
                i++;
            }
        } else {
            logger.info("No trusted certificates were provided, continue with default cacerts!");
        }

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

        this.trustManagers = trustManagerFactory.getTrustManagers();

        SSLContext.setDefault(sslContext);
    }

    private KeyStore loadCacertsKeyStore() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        String relativeCacertsPath = "/lib/security/cacerts".replace("/", File.separator);
        String filename = System.getProperty("java.home") + relativeCacertsPath;

        KeyStore keyStore = null;
        FileInputStream is = new FileInputStream(filename);
        try {

            logger.debug("Loading cacert in location: {}", filename);
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            String password = "changeit";
            keyStore.load(is, password.toCharArray());
        } catch (Exception e) {
            logger.error("Failed loading cacert in location: {}", filename);
            throw e;
        }
        finally {
            is.close();
        }

        return keyStore;
    }

    private List<X509Certificate> getTrustedCertificates(String trustedCerts) {
        List<X509Certificate> certs = new ArrayList<>();

        if (!trustedCerts.contains(BEGIN_CERTIFICATE)) {
            return certs;
        }

        while (trustedCerts.contains(BEGIN_CERTIFICATE)) {
            String rfcCert = trustedCerts.substring(
                    trustedCerts.indexOf(BEGIN_CERTIFICATE),
                    trustedCerts.indexOf(END_CERTIFICATE) + END_CERTIFICATE.length()
            );

            try {
                X509Certificate certificate = CertificateUtil.parseCertificate(rfcCert);
                certs.add(certificate);
            } catch (CertificateException e) {
                logger.debug("Cannot parse trusted certificate: {}", rfcCert);
                logger.warn("Cannot parse trusted certificate", e);
            }

            trustedCerts = trustedCerts.substring(trustedCerts.indexOf(END_CERTIFICATE) + END_CERTIFICATE.length());
        }

        return certs;
    }

    public TrustManager[] getDefaultTrustManagers() {
        return this.trustManagers;
    }

}

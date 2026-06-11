package com.otilm.core.helpers;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.util.CertificateTestUtil;
import lombok.Getter;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

/**
 * Test fixture that establishes a trusted certificate authority inside the platform and issues leaf
 * certificates from it. Certificate material is produced by {@code CertificateGeneratorHelper} (pure
 * crypto) and persisted by {@link CertificateUploader} (the {@code CertificateService} boundary); this
 * class only wires the two together so a test can obtain an uploaded, trusted chain in one call.
 */
@Component
public class TestCertificateAuthority {

    private final CertificateUploader certificateUploader;

    public TestCertificateAuthority(CertificateUploader certificateUploader) {
        this.certificateUploader = certificateUploader;
    }

    /**
     * Creates and uploads a certificate signed by an external CA not present in the inventory.
     * Because the issuing CA is absent, chain validation will report an incomplete chain.
     */
    public Certificate issueUntrustedCertificate() throws Exception {
        X509Certificate x509 = CertificateTestUtil.createEndEntityCertificate();
        return certificateUploader.upload(x509);
    }

    public TrustedCa createTrustedCa(String subjectDn) throws Exception {
        KeyPair caKeyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate caX509 = CertificateGeneratorHelper.generateCACertificate(caKeyPair, subjectDn);
        Certificate caEntity = certificateUploader.upload(caX509);
        certificateUploader.markTrusted(caEntity);
        return new TrustedCa(caKeyPair, caX509, caEntity);
    }

    @Getter
    public class TrustedCa {

        private final KeyPair keyPair;
        private final X509Certificate x509;
        private final Certificate entity;

        private TrustedCa(KeyPair keyPair, X509Certificate x509, Certificate entity) {
            this.keyPair = keyPair;
            this.x509 = x509;
            this.entity = entity;
        }

        /**
         * Issues an RFC 3161 timestamping leaf for {@code leafKeyPair}, uploads it and runs validation.
         * The leaf is built from the caller's key pair so the upload associates it (by public-key
         * fingerprint) with the key the caller already holds — e.g. a token-backed key.
         */
        public Certificate issueTimestampingCertificate(KeyPair leafKeyPair, String subjectDn) throws Exception {
            X509Certificate leafX509 = CertificateGeneratorHelper.generateTimestampingCertificate(keyPair, x509, leafKeyPair, subjectDn);
            Certificate leafEntity = certificateUploader.upload(leafX509);
            certificateUploader.validate(leafEntity);
            return leafEntity;
        }

        /**
         * Issues a qualified timestamping certificate: EKU id-kp-timeStamping (critical) plus
         * id-etsi-qcs-QcCompliance in qcStatements, as required by ETSI EN 319 421 §6.2.
         */
        public Certificate issueQualifiedTimestampingCertificate(KeyPair leafKeyPair, String subjectDn) throws Exception {
            X509Certificate leafX509 = CertificateGeneratorHelper.generateQualifiedTimestampingCertificate(keyPair, x509, leafKeyPair, subjectDn);
            Certificate leafEntity = certificateUploader.upload(leafX509);
            certificateUploader.validate(leafEntity);
            return leafEntity;
        }
    }
}

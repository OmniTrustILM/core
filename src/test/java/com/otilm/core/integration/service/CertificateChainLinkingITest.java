package com.otilm.core.integration.service;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import java.security.cert.X509Certificate;
import java.util.Base64;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * The certificate-chain read links a leaf to its issuer the first time it finds the issuer in inventory. A request that
 * read the leaf before a concurrent revocation committed must write only that link, not the state it read.
 */
class CertificateChainLinkingITest extends BaseSpringBootTest {

    @Autowired
    private CertificateInternalService certificateService;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private PlatformTransactionManager transactionManager;

    @Test
    void linkingTheIssuerKeepsARevocationCommittedAfterTheLeafWasRead() throws Exception {
        CertificateGeneratorHelper.CertificateChainInfo chain = CertificateGeneratorHelper
                .generateCertificateWithIssuer(KeyAlgorithm.RSA, "CN=Linking-CA", "CN=Linking-Leaf", null);
        Certificate issuer = store(chain.getCaCertificate());
        Certificate leaf = store(chain.getEndEntityCertificate());
        TransactionTemplate separately = new TransactionTemplate(transactionManager);
        separately.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);

        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            certificateRepository.findByUuid(leaf.getUuid()).orElseThrow();
            separately
                    .executeWithoutResult(
                            revocation -> certificateRepository.transitionIssuedToRevoked(leaf.getUuid()));
            try {
                certificateService.getCertificateChain(leaf.getSecuredUuid(), false);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });

        Certificate stored = certificateRepository.findByUuid(leaf.getUuid()).orElseThrow();
        Assertions.assertEquals(CertificateState.REVOKED, stored.getState());
        Assertions.assertEquals(issuer.getUuid(), stored.getIssuerCertificateUuid());
    }

    /** Stores a certificate the way issuance leaves it: no issuer link yet. */
    private Certificate store(X509Certificate x509) throws Exception {
        CertificateContent content = new CertificateContent();
        content.setFingerprint(CertificateUtil.getThumbprint(x509));
        content.setContent(Base64.getEncoder().encodeToString(x509.getEncoded()));
        content = certificateContentRepository.save(content);

        Certificate certificate = new Certificate();
        CertificateUtil.prepareIssuedCertificate(certificate, x509);
        certificate.setCertificateContent(content);
        certificate.setCertificateContentId(content.getId());
        certificate.setIssuerCertificateUuid(null);
        certificate.setIssuerSerialNumber(null);
        return certificateRepository.save(certificate);
    }
}

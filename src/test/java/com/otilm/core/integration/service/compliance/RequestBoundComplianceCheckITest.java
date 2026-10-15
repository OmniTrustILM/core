package com.otilm.core.integration.service.compliance;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.ComplianceInternalService;
import com.otilm.core.service.compliance.BaseComplianceTest;
import com.otilm.core.util.CertificateUtil;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.orm.jpa.EntityManagerHolder;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A compliance check can run in a request's persistence context: the subjects it checks are then the copies the request
 * read, and the request's next transaction flushes whatever that context holds. The check stores its result and leaves
 * the rest of each subject as the row now stands.
 */
class RequestBoundComplianceCheckITest extends BaseComplianceTest {

    private static final String REVOKE_BEHIND_THE_REQUEST = "UPDATE certificate SET state = 'REVOKED' WHERE uuid = ?";

    @Autowired
    private ComplianceInternalService complianceService;

    @Autowired
    private EntityManagerFactory entityManagerFactory;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    /**
     * A revocation committed after the request read the certificate survives the check the request runs and the read of
     * its result that follows.
     */
    @Test
    void aCheckInARequestKeepsARevocationCommittedSinceTheRequestReadTheCertificate() throws Exception {
        // given
        answerTheProviderRule("nok");
        UUID certificateUuid = issuedCertificate();

        // when
        inARequest(request -> {
            request.find(Certificate.class, certificateUuid);
            jdbcTemplate.update(REVOKE_BEHIND_THE_REQUEST, certificateUuid);
            complianceService.checkResourceObjectComplianceAsSystem(Resource.CERTIFICATE, certificateUuid);
            return complianceService.getComplianceCheckResult(Resource.CERTIFICATE, certificateUuid);
        });

        // then
        Certificate checked = certificateRepository.findByUuid(certificateUuid).orElseThrow();
        assertThat(checked.getState()).isEqualTo(CertificateState.REVOKED);
        assertThat(checked.getComplianceStatus()).isEqualTo(ComplianceStatus.NOK);
    }

    /** A check by profiles updates the result the certificate already carries; the revocation survives it too. */
    @Test
    void aCheckByProfilesInARequestKeepsARevocationCommittedSinceTheRequestReadTheCertificate() throws Exception {
        // given
        answerTheProviderRule("nok");
        UUID certificateUuid = issuedCertificate();
        complianceService.checkResourceObjectComplianceAsSystem(Resource.CERTIFICATE, certificateUuid);

        // when
        inARequest(request -> {
            request.find(Certificate.class, certificateUuid);
            jdbcTemplate.update(REVOKE_BEHIND_THE_REQUEST, certificateUuid);
            complianceService
                    .checkCompliance(List.of(SecuredUUID.fromUUID(complianceProfile.getUuid())), Resource.CERTIFICATE,
                            null);
            return complianceService.getComplianceCheckResult(Resource.CERTIFICATE, certificateUuid);
        });

        // then
        Certificate checked = certificateRepository.findByUuid(certificateUuid).orElseThrow();
        assertThat(checked.getState()).isEqualTo(CertificateState.REVOKED);
        assertThat(checked.getComplianceStatus()).isEqualTo(ComplianceStatus.NOK);
    }

    /**
     * After the check the request reads the certificate as its row now stands, with the result the check stored and a
     * revocation committed since, not the copy it read before the check.
     */
    @Test
    void afterTheCheckTheRequestReadsTheCertificateAsItsRowNowStands() throws Exception {
        // given
        answerTheProviderRule("nok");
        UUID certificateUuid = issuedCertificate();

        // when
        Certificate read = inARequest(request -> {
            request.find(Certificate.class, certificateUuid);
            complianceService.checkResourceObjectComplianceAsSystem(Resource.CERTIFICATE, certificateUuid);
            jdbcTemplate.update(REVOKE_BEHIND_THE_REQUEST, certificateUuid);
            return certificateRepository.findByUuid(certificateUuid).orElseThrow();
        });

        // then
        assertThat(read.getState()).isEqualTo(CertificateState.REVOKED);
        assertThat(read.getComplianceStatus()).isEqualTo(ComplianceStatus.NOK);
    }

    private void answerTheProviderRule(String status) {
        WireMock
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/v2/complianceProvider/%s/compliance".formatted(KIND_V2)))
                        .willReturn(WireMock
                                .aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/json")
                                .withBody("""
                                        {
                                          "rules": [
                                            {
                                              "uuid": "%s",
                                              "name": "Rule1",
                                              "status": "%s"
                                            }
                                          ]
                                        }
                                        """.formatted(complianceV2RuleUuid, status))));
    }

    /** An issued certificate of the RA profile the compliance profile is associated with. */
    private UUID issuedCertificate() throws Exception {
        X509Certificate x509 = CertificateGeneratorHelper
                .generateCertificateWithIssuer(KeyAlgorithm.RSA, "CN=Request-Bound-CA", "CN=Request-Bound-EE", null)
                .getEndEntityCertificate();
        CertificateContent content = new CertificateContent();
        content.setFingerprint(CertificateUtil.getThumbprint(x509));
        content.setContent(Base64.getEncoder().encodeToString(x509.getEncoded()));
        content = certificateContentRepository.save(content);

        Certificate certificate = new Certificate();
        CertificateUtil.prepareIssuedCertificate(certificate, x509);
        certificate.setCertificateContent(content);
        certificate.setCertificateContentId(content.getId());
        certificate.setRaProfileUuid(associatedRaProfileUuid);
        return certificateRepository.save(certificate).getUuid();
    }

    /**
     * Runs the call with one EntityManager bound to the thread and no transaction around it, as a request that is not
     * inside a transactional method does, so the call's reads answer from that persistence context. A change the call
     * commits through JDBC is one the context cannot learn of, as a request on another node commits it.
     */
    private <T> T inARequest(RequestCall<T> call) throws Exception {
        EntityManager bound = entityManagerFactory.createEntityManager();
        TransactionSynchronizationManager.bindResource(entityManagerFactory, new EntityManagerHolder(bound));
        try {
            return call.run(bound);
        } finally {
            TransactionSynchronizationManager.unbindResource(entityManagerFactory);
            bound.close();
        }
    }

    @FunctionalInterface
    private interface RequestCall<T> {

        T run(EntityManager request) throws Exception;
    }
}

package com.otilm.core.integration.dao.entity;

import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRequestEntity;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.entity.X509CertificateRequestEntity;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CertificateRequestRepository;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.builders.CertificateRequestEntityBuilder;
import jakarta.persistence.EntityManager;
import org.hibernate.Hibernate;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;

class CertificateTypeViewITest extends BaseSpringBootTest {

    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateRequestRepository certificateRequestRepository;
    @Autowired
    private EntityManager entityManager;

    @Test
    @Transactional
    void unwrapsTheProxy_whenViewingALazyCertificateReferenceAsX509() {
        // given
        String subject = "CN=lazy-holder";
        X509CertificateEntity stored = certificateRepository.save(aCertificate().withSubjectDn(subject).build());
        entityManager.flush();
        entityManager.clear();
        Certificate reference = certificateRepository.getReferenceById(stored.getUuid());

        // when
        X509CertificateEntity viewed = X509CertificateEntity.from(reference);

        // then
        assertThat(Hibernate.unproxy(reference)).isSameAs(viewed);
        assertThat(viewed.getSubjectDn()).isEqualTo(subject);
    }

    @Test
    @Transactional
    void unwrapsTheProxy_whenViewingALazyRequestReferenceAsX509() {
        // given
        String subject = "CN=lazy-request-holder";
        X509CertificateRequestEntity request = CertificateRequestEntityBuilder
                .aCertificateRequest()
                .withContent("content")
                .withSubjectDn(subject)
                .build();
        X509CertificateRequestEntity stored = certificateRequestRepository.save(request);
        entityManager.flush();
        entityManager.clear();
        CertificateRequestEntity reference = certificateRequestRepository.getReferenceById(stored.getUuid());

        // when
        X509CertificateRequestEntity viewed = X509CertificateRequestEntity.fromOrNull(reference);

        // then
        assertThat(viewed).isNotNull();
        assertThat(viewed.getSubjectDn()).isEqualTo(subject);
    }
}

package com.otilm.core.integration.dao.entity;

import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.core.certificate.type.Validity;
import com.otilm.core.certificate.type.ValidityPrecision;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRequestEntity;
import com.otilm.core.dao.entity.CvcCertificateEntity;
import com.otilm.core.dao.entity.CvcCertificateRequestEntity;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CertificateRequestRepository;
import com.otilm.core.util.BaseSpringBootTest;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import java.time.LocalDate;
import java.time.Month;
import java.util.List;
import org.hibernate.Hibernate;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.transaction.annotation.Transactional;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;

class CvcCertificateEntityITest extends BaseSpringBootTest {

    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateRequestRepository certificateRequestRepository;
    @Autowired
    private EntityManager entityManager;

    @Test
    @Transactional
    void loadsAllCvcFields_whenACvcCertificateWasStored() {
        // given
        CvcCertificateEntity stored = certificateRepository.save(createCvcCertificate("fp-1", "SEILMTERM00001"));
        entityManager.flush();
        entityManager.clear();

        // when
        Certificate loaded = certificateRepository.findById(stored.getUuid()).orElseThrow();

        // then
        assertThat(loaded).isInstanceOf(CvcCertificateEntity.class);
        CvcCertificateEntity cvc = (CvcCertificateEntity) loaded;
        assertThat(cvc.getCertificateType()).isEqualTo(CertificateType.CVC);
        assertThat(cvc.getHolderReference()).isEqualTo("SEILMTERM00001");
        assertThat(cvc.getAuthorityReference()).isEqualTo("SEILMDV00001");
        assertThat(cvc.getRole()).isEqualTo("terminal");
        assertThat(cvc.getTerminalType()).isEqualTo("0.4.0.127.0.7.3.1.2.2");
        assertThat(cvc.getAccessRights()).isEqualTo("03");
        assertThat(cvc.getEffectiveDate()).isEqualTo(LocalDate.of(2026, Month.JANUARY, 15));
        assertThat(cvc.getExpirationDate()).isEqualTo(LocalDate.of(2026, Month.APRIL, 14));
    }

    @Test
    @Transactional
    void loadsAllCvcFields_whenACvcRequestWasStored() throws Exception {
        // given
        CvcCertificateRequestEntity request = new CvcCertificateRequestEntity();
        request.setCertificateRequestFormat(CertificateRequestFormat.CVC);
        request.setContent("AAAA");
        request.setHolderReference("SEILMTERM00002");
        request.setAuthorityReference("SEILMDV00001");
        request.setAuthenticatedBy("SEILMTERM00001");
        CvcCertificateRequestEntity stored = certificateRequestRepository.save(request);
        entityManager.flush();
        entityManager.clear();

        // when
        CertificateRequestEntity loaded = certificateRequestRepository.findById(stored.getUuid()).orElseThrow();

        // then
        assertThat(loaded).isInstanceOf(CvcCertificateRequestEntity.class);
        CvcCertificateRequestEntity cvc = (CvcCertificateRequestEntity) loaded;
        assertThat(cvc.getHolderReference()).isEqualTo("SEILMTERM00002");
        assertThat(cvc.getAuthorityReference()).isEqualTo("SEILMDV00001");
        assertThat(cvc.getAuthenticatedBy()).isEqualTo("SEILMTERM00001");
    }

    @Test
    @Transactional
    void storesBoth_whenTwoCertificatesShareAHolderReferenceAndAPublicKey() {
        // given
        CvcCertificateEntity newCertificate = createCvcCertificate("fp-new", "SEILMCVCA00002");
        CvcCertificateEntity linkCertificate = createCvcCertificate("fp-link", "SEILMCVCA00002");
        newCertificate.setPublicKeyFingerprint("same-key");
        linkCertificate.setPublicKeyFingerprint("same-key");

        // when
        certificateRepository.saveAll(List.of(newCertificate, linkCertificate));
        entityManager.flush();
        entityManager.clear();

        // then
        List<Certificate> stored = certificateRepository.findAll();
        assertThat(stored)
                .hasSize(2)
                .allSatisfy(certificate -> assertThat(((CvcCertificateEntity) certificate).getHolderReference())
                        .isEqualTo("SEILMCVCA00002"));
    }

    @Test
    @Transactional
    void sortsAndLoadsEachSubclass_whenCvcAndX509CertificatesAreStoredTogether() {
        // given
        X509CertificateEntity x509 = aCertificate().withSubjectDn("CN=mixed").build();
        x509.setNotAfter(java.util.Date.from(Instant.parse("2027-01-01T00:00:00Z")));
        certificateRepository.save(x509);
        certificateRepository.save(createCvcCertificate("fp-mixed", "SEILMTERM00003"));
        entityManager.flush();
        entityManager.clear();

        // when
        List<Certificate> byExpiry = certificateRepository.findAll(Sort.by("notAfter"));

        // then
        assertThat(byExpiry).hasSize(2);
        assertThat(byExpiry.get(0)).isInstanceOf(CvcCertificateEntity.class);
        assertThat(byExpiry.get(1)).isInstanceOf(X509CertificateEntity.class);
    }

    @Test
    @Transactional
    void unwrapsTheProxy_whenViewingALazyCertificateReferenceAsCvc() {
        // given
        CvcCertificateEntity stored = certificateRepository.save(createCvcCertificate("fp-lazy", "SEILMTERM00004"));
        entityManager.flush();
        entityManager.clear();
        Certificate reference = certificateRepository.getReferenceById(stored.getUuid());

        // when
        CvcCertificateEntity viewed = CvcCertificateEntity.fromOrNull(reference);

        // then
        assertThat(viewed).isNotNull();
        assertThat(Hibernate.unproxy(reference)).isSameAs(viewed);
        assertThat(viewed.getHolderReference()).isEqualTo("SEILMTERM00004");
    }

    @Test
    @Transactional
    void unwrapsTheProxy_whenViewingALazyRequestReferenceAsCvc() throws Exception {
        // given
        CvcCertificateRequestEntity request = new CvcCertificateRequestEntity();
        request.setCertificateRequestFormat(CertificateRequestFormat.CVC);
        request.setContent("AAAA");
        request.setHolderReference("SEILMTERM00005");
        CvcCertificateRequestEntity stored = certificateRequestRepository.save(request);
        entityManager.flush();
        entityManager.clear();
        CertificateRequestEntity reference = certificateRequestRepository.getReferenceById(stored.getUuid());

        // when
        CvcCertificateRequestEntity viewed = CvcCertificateRequestEntity.fromOrNull(reference);

        // then
        assertThat(viewed).isNotNull();
        assertThat(Hibernate.unproxy(reference)).isSameAs(viewed);
        assertThat(viewed.getHolderReference()).isEqualTo("SEILMTERM00005");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static CvcCertificateEntity createCvcCertificate(String fingerprint, String holderReference) {
        CvcCertificateEntity certificate = new CvcCertificateEntity();
        certificate.setFingerprint(fingerprint);
        certificate.setHolderReference(holderReference);
        certificate.setAuthorityReference("SEILMDV00001");
        certificate.setRole("terminal");
        certificate.setTerminalType("0.4.0.127.0.7.3.1.2.2");
        certificate.setAccessRights("03");
        certificate
                .applyValidity(new Validity(Instant.parse("2026-01-15T00:00:00Z"),
                        Instant.parse("2026-04-14T00:00:00Z"), ValidityPrecision.DATE));
        return certificate;
    }
}

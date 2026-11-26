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
import java.util.List;
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
        CvcCertificateEntity stored = certificateRepository.save(aCvcCertificate("fp-1", "SEILMTERM00001"));
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
        assertThat(cvc.getAccessRights()).isEqualTo("03");
        assertThat(cvc.getEffectiveDate()).isEqualTo(LocalDate.of(2026, 1, 15));
        assertThat(cvc.getExpirationDate()).isEqualTo(LocalDate.of(2026, 4, 14));
    }

    @Test
    @Transactional
    void loadsAllCvcFields_whenACvcRequestWasStored() throws Exception {
        // given
        CvcCertificateRequestEntity request = new CvcCertificateRequestEntity();
        request.setCertificateRequestFormat(CertificateRequestFormat.CVC);
        request.setContent("AAAA");
        request.setHolderReference("SEILMTERM00002");
        request.setAuthorityReference("SEILMTERM00001");
        CvcCertificateRequestEntity stored = certificateRequestRepository.save(request);
        entityManager.flush();
        entityManager.clear();

        // when
        CertificateRequestEntity loaded = certificateRequestRepository.findById(stored.getUuid()).orElseThrow();

        // then
        assertThat(loaded).isInstanceOf(CvcCertificateRequestEntity.class);
        CvcCertificateRequestEntity cvc = (CvcCertificateRequestEntity) loaded;
        assertThat(cvc.getHolderReference()).isEqualTo("SEILMTERM00002");
        assertThat(cvc.getAuthorityReference()).isEqualTo("SEILMTERM00001");
    }

    @Test
    @Transactional
    void storesBoth_whenTwoCertificatesShareAHolderReferenceAndAPublicKey() {
        // given
        CvcCertificateEntity newCertificate = aCvcCertificate("fp-new", "SEILMCVCA00002");
        CvcCertificateEntity linkCertificate = aCvcCertificate("fp-link", "SEILMCVCA00002");
        newCertificate.setPublicKeyFingerprint("same-key");
        linkCertificate.setPublicKeyFingerprint("same-key");

        // when
        certificateRepository.saveAll(List.of(newCertificate, linkCertificate));
        entityManager.flush();
        entityManager.clear();

        // then
        List<Certificate> stored = certificateRepository.findAll();
        assertThat(stored).hasSize(2);
        assertThat(stored)
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
        certificateRepository.save(aCvcCertificate("fp-mixed", "SEILMTERM00003"));
        entityManager.flush();
        entityManager.clear();

        // when
        List<Certificate> byExpiry = certificateRepository.findAll(Sort.by("notAfter"));

        // then
        assertThat(byExpiry).hasSize(2);
        assertThat(byExpiry.get(0)).isInstanceOf(CvcCertificateEntity.class);
        assertThat(byExpiry.get(1)).isInstanceOf(X509CertificateEntity.class);
    }

    private static CvcCertificateEntity aCvcCertificate(String fingerprint, String holderReference) {
        CvcCertificateEntity certificate = new CvcCertificateEntity();
        certificate.setFingerprint(fingerprint);
        certificate.setHolderReference(holderReference);
        certificate.setAuthorityReference("SEILMDV00001");
        certificate.setRole("terminal");
        certificate.setAccessRights("03");
        certificate
                .applyValidity(new Validity(Instant.parse("2026-01-15T00:00:00Z"),
                        Instant.parse("2026-04-14T00:00:00Z"), ValidityPrecision.DATE));
        return certificate;
    }
}

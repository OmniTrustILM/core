package com.otilm.core.integration.service;

import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.repository.X509CertificateRepository;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;

class X509CertificateRepositoryITest extends BaseSpringBootTest {

    @Autowired
    private X509CertificateRepository x509CertificateRepository;

    @Test
    void findsCertificateOfTheEntityType_whenFindingByAnInheritedQuery() {
        // given
        String fingerprint = "inherited-fingerprint";
        X509CertificateEntity stored = x509CertificateRepository
                .save(aCertificate().withFingerprint(fingerprint).build());

        // when
        Optional<X509CertificateEntity> found = x509CertificateRepository.findByFingerprint(fingerprint);

        // then
        assertThat(found).get().extracting(X509CertificateEntity::getUuid).isEqualTo(stored.getUuid());
    }

    @Test
    void findsCertificate_whenSubjectAndSerialNumberMatch() {
        // given
        X509CertificateEntity certificate = aCertificate().withSerialNumber("0a1b").build();
        certificate.setSubjectDnNormalized("cn=holder");
        X509CertificateEntity stored = x509CertificateRepository.save(certificate);

        // when
        Optional<X509CertificateEntity> found = x509CertificateRepository
                .findBySubjectDnNormalizedAndSerialNumber("cn=holder", "0a1b");

        // then
        assertThat(found).get().extracting(X509CertificateEntity::getUuid).isEqualTo(stored.getUuid());
    }

    @Test
    void findsNothing_whenSubjectMatchesButSerialNumberDoesNot() {
        // given
        X509CertificateEntity certificate = aCertificate().withSerialNumber("0a1b").build();
        certificate.setSubjectDnNormalized("cn=holder");
        x509CertificateRepository.save(certificate);

        // when
        Optional<X509CertificateEntity> found = x509CertificateRepository
                .findBySubjectDnNormalizedAndSerialNumber("cn=holder", "ffff");

        // then
        assertThat(found).isEmpty();
    }

    @Test
    void listsCertificatesWithTheSubject_whenFindingBySubject() {
        // given
        X509CertificateEntity first = aCertificate().withSerialNumber("01").build();
        first.setSubjectDnNormalized("cn=shared");
        X509CertificateEntity second = aCertificate().withSerialNumber("02").build();
        second.setSubjectDnNormalized("cn=shared");
        X509CertificateEntity other = aCertificate().withSerialNumber("03").build();
        other.setSubjectDnNormalized("cn=other");
        x509CertificateRepository.saveAll(List.of(first, second, other));

        // when
        List<X509CertificateEntity> found = x509CertificateRepository.findBySubjectDnNormalized("cn=shared");

        // then
        assertThat(found).extracting(X509CertificateEntity::getSerialNumber).containsExactlyInAnyOrder("01", "02");
    }
}

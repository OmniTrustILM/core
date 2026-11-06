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
    void findsTheCertificate_whenFindingByAnInheritedQuery() {
        // given
        String storedFingerprint = "inherited-fingerprint";
        X509CertificateEntity stored = x509CertificateRepository
                .save(aCertificate().withFingerprint(storedFingerprint).build());

        // when
        Optional<X509CertificateEntity> found = x509CertificateRepository.findByFingerprint(storedFingerprint);

        // then
        assertThat(found).get().extracting(X509CertificateEntity::getUuid).isEqualTo(stored.getUuid());
    }

    @Test
    void findsTheCertificate_whenSubjectAndSerialNumberMatch() {
        // given
        String storedSubject = "cn=holder";
        String storedSerialNumber = "0a1b";
        X509CertificateEntity stored = x509CertificateRepository
                .save(aCertificate()
                        .withSubjectDnNormalized(storedSubject)
                        .withSerialNumber(storedSerialNumber)
                        .build());

        // when
        Optional<X509CertificateEntity> found = x509CertificateRepository
                .findBySubjectDnNormalizedAndSerialNumber(storedSubject, storedSerialNumber);

        // then
        assertThat(found).get().extracting(X509CertificateEntity::getUuid).isEqualTo(stored.getUuid());
    }

    @Test
    void findsNothing_whenSubjectMatchesButSerialNumberDoesNot() {
        // given
        String storedSubject = "cn=holder";
        String serialNumberOfAnotherCertificate = "ffff";
        x509CertificateRepository
                .save(aCertificate().withSubjectDnNormalized(storedSubject).withSerialNumber("0a1b").build());

        // when
        Optional<X509CertificateEntity> found = x509CertificateRepository
                .findBySubjectDnNormalizedAndSerialNumber(storedSubject, serialNumberOfAnotherCertificate);

        // then
        assertThat(found).isEmpty();
    }

    @Test
    void listsTheCertificatesOfTheSubject_whenFindingBySubject() {
        // given
        String sharedSubject = "cn=shared";
        x509CertificateRepository
                .saveAll(List
                        .of(aCertificate().withSubjectDnNormalized(sharedSubject).withSerialNumber("01").build(),
                                aCertificate().withSubjectDnNormalized(sharedSubject).withSerialNumber("02").build(),
                                aCertificate().withSubjectDnNormalized("cn=other").withSerialNumber("03").build()));

        // when
        List<X509CertificateEntity> found = x509CertificateRepository.findBySubjectDnNormalized(sharedSubject);

        // then
        assertThat(found).extracting(X509CertificateEntity::getSerialNumber).containsExactlyInAnyOrder("01", "02");
    }
}

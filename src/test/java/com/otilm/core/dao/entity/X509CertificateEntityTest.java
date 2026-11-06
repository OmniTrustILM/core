package com.otilm.core.dao.entity;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class X509CertificateEntityTest {

    @Test
    void returnsTheSameEntity_whenViewingAnX509CertificateAsX509() {
        // given
        X509CertificateEntity certificate = aCertificate().build();

        // when
        X509CertificateEntity viewed = X509CertificateEntity.from(certificate);

        // then
        assertThat(viewed).isSameAs(certificate);
    }

    @Test
    void returnsNull_whenViewingACertificateOfAnotherTypeAsX509OrNull() {
        // given
        Certificate certificate = aCertificateOfAnotherType();

        // when
        X509CertificateEntity viewed = X509CertificateEntity.fromOrNull(certificate);

        // then
        assertThat(viewed).isNull();
    }

    @Test
    void refusesWithTheCertificateUuid_whenViewingACertificateOfAnotherTypeAsX509() {
        // given
        Certificate certificate = aCertificateOfAnotherType();

        // when
        ThrowingCallable viewingAsX509 = () -> X509CertificateEntity.from(certificate);

        // then
        assertThatThrownBy(viewingAsX509)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining(certificate.getUuid().toString());
    }

    @Test
    void returnsNullSubjectDn_whenTheCertificateIsOfAnotherType() {
        // given
        Certificate certificate = aCertificateOfAnotherType();

        // when
        String subjectDn = X509CertificateEntity.subjectDnOrNull(certificate);

        // then
        assertThat(subjectDn).isNull();
    }

    @Test
    void returnsTheSubjectDn_whenTheCertificateIsX509() {
        // given
        String subject = "CN=holder";
        X509CertificateEntity certificate = aCertificate().withSubjectDn(subject).build();

        // when
        String subjectDn = X509CertificateEntity.subjectDnOrNull(certificate);

        // then
        assertThat(subjectDn).isEqualTo(subject);
    }

    // The enum has no second type yet, so a certificate that is not X.509 is a subclass that reports the one type there
    // is.
    private static Certificate aCertificateOfAnotherType() {
        Certificate certificate = new Certificate() {
            @Override
            public CertificateRequestEntity prepareCertificateRequest(
                    CertificateRequestFormat certificateRequestFormat) {
                return null;
            }

            @Override
            public CertificateType getCertificateType() {
                return CertificateType.X509;
            }
        };
        certificate.setUuid(UUID.randomUUID());
        return certificate;
    }
}

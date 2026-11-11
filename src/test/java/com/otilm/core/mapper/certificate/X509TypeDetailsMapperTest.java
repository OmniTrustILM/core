package com.otilm.core.mapper.certificate;

import com.otilm.api.model.core.certificate.CertificateKeyUsage;
import com.otilm.api.model.core.certificate.X509CertificateRequestTypeDetailsDto;
import com.otilm.api.model.core.certificate.X509CertificateTypeDetailsDto;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.entity.X509CertificateRequestEntity;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static com.otilm.core.util.builders.CertificateRequestEntityBuilder.aCertificateRequest;
import static org.assertj.core.api.Assertions.assertThat;

class X509TypeDetailsMapperTest {

    private static final String ISSUER_DN = "CN=Details CA";

    @Test
    void carriesTheContentOfTheCertificate_whenItHasBeenIssued() {
        // given
        X509CertificateEntity certificate = aCertificate()
                .withCertificateContent(new CertificateContent())
                .withIssuerDn(ISSUER_DN)
                .withKeyUsage(CertificateKeyUsage.DIGITAL_SIGNATURE)
                .withExtendedKeyUsage("1.3.6.1.5.5.7.3.1")
                .build();

        // when
        X509CertificateTypeDetailsDto details = X509TypeDetailsMapper.toDetails(certificate);

        // then
        assertThat(details.getIssuerDn()).isEqualTo(ISSUER_DN);
        assertThat(details.getKeyUsage()).containsExactly(CertificateKeyUsage.DIGITAL_SIGNATURE);
        assertThat(details.getExtendedKeyUsage()).containsExactly("1.3.6.1.5.5.7.3.1");
    }

    @Test
    void leavesTheIssuedContentEmpty_whenTheCertificateHasNoContentYet() {
        // given
        X509CertificateEntity registration = aCertificate().withIssuerDn(ISSUER_DN).withSubjectDn("CN=holder").build();

        // when
        X509CertificateTypeDetailsDto details = X509TypeDetailsMapper.toDetails(registration);

        // then
        assertThat(details.getIssuerDn()).isNull();
        assertThat(details.getKeyUsage()).isNull();
        assertThat(details.getSubjectDn()).isEqualTo("CN=holder");
    }

    @Test
    void leavesQcStatementsEmpty_whenNoQcFieldIsSet() {
        // given
        X509CertificateEntity certificate = aCertificate().withCertificateContent(new CertificateContent()).build();

        // when
        X509CertificateTypeDetailsDto details = X509TypeDetailsMapper.toDetails(certificate);

        // then
        assertThat(details.getQcStatements()).isNull();
    }

    @Test
    void carriesQcStatements_whenAQcFieldIsSet() {
        // given
        X509CertificateEntity certificate = aCertificate()
                .withCertificateContent(new CertificateContent())
                .withQcCompliance(true)
                .build();

        // when
        X509CertificateTypeDetailsDto details = X509TypeDetailsMapper.toDetails(certificate);

        // then
        assertThat(details.getQcStatements().getQcCompliance()).isTrue();
    }

    @Test
    void carriesTheSubjectOfTheRequest_whenMappingTheRequestDetails() {
        // given
        X509CertificateRequestEntity request = aCertificateRequest()
                .withContent("content")
                .withSubjectDn("CN=request-holder")
                .build();

        // when
        X509CertificateRequestTypeDetailsDto details = X509TypeDetailsMapper.toRequestDetails(request);

        // then
        assertThat(details.getSubjectDn()).isEqualTo("CN=request-holder");
    }
}

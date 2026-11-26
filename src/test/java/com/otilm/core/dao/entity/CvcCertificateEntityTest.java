package com.otilm.core.dao.entity;

import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.core.certificate.type.Validity;
import com.otilm.core.certificate.type.ValidityPrecision;
import java.time.Instant;
import java.time.LocalDate;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;

class CvcCertificateEntityTest {

    private static final Instant EFFECTIVE_DAY = Instant.parse("2026-01-15T00:00:00Z");
    private static final Instant EXPIRATION_DAY = Instant.parse("2026-04-14T00:00:00Z");

    @Test
    void reportsTheCvcType_whenACertificateOrRequestIsCreated() {
        // given / when
        CvcCertificateEntity certificate = new CvcCertificateEntity();
        CvcCertificateRequestEntity request = new CvcCertificateRequestEntity();

        // then
        assertThat(certificate.getCertificateType()).isEqualTo(CertificateType.CVC);
        assertThat(request.getCertificateType()).isEqualTo(CertificateType.CVC);
    }

    @Test
    void storesTheStartOfTheDayAfterTheExpirationDate_whenTheValidityHasDatePrecision() {
        // given
        CvcCertificateEntity certificate = new CvcCertificateEntity();

        // when
        certificate.applyValidity(new Validity(EFFECTIVE_DAY, EXPIRATION_DAY, ValidityPrecision.DATE));

        // then
        assertThat(certificate.getNotBefore().toInstant()).isEqualTo(EFFECTIVE_DAY);
        assertThat(certificate.getNotAfter().toInstant()).isEqualTo(Instant.parse("2026-04-15T00:00:00Z"));
    }

    @Test
    void givesTheDatesBack_whenTheValidityWasStoredWithDatePrecision() {
        // given
        CvcCertificateEntity certificate = new CvcCertificateEntity();
        certificate.applyValidity(new Validity(EFFECTIVE_DAY, EXPIRATION_DAY, ValidityPrecision.DATE));

        // when / then
        assertThat(certificate.getEffectiveDate()).isEqualTo(LocalDate.of(2026, 1, 15));
        assertThat(certificate.getExpirationDate()).isEqualTo(LocalDate.of(2026, 4, 14));
    }

    @Test
    void givesNoDates_whenTheCertificateHasNoValidity() {
        // given
        CvcCertificateEntity certificate = new CvcCertificateEntity();

        // when / then
        assertThat(certificate.getEffectiveDate()).isNull();
        assertThat(certificate.getExpirationDate()).isNull();
    }

    @Test
    void viewsTheCertificateAsCvc_whenItIsCvc() {
        // given
        CvcCertificateEntity certificate = new CvcCertificateEntity();
        CvcCertificateRequestEntity request = new CvcCertificateRequestEntity();

        // when / then
        assertThat(CvcCertificateEntity.fromOrNull(certificate)).isSameAs(certificate);
        assertThat(CvcCertificateRequestEntity.fromOrNull(request)).isSameAs(request);
    }

    @Test
    void viewsNothing_whenTheCertificateIsX509() {
        // given
        X509CertificateEntity certificate = aCertificate().build();
        X509CertificateRequestEntity request = new X509CertificateRequestEntity();

        // when / then
        assertThat(CvcCertificateEntity.fromOrNull(certificate)).isNull();
        assertThat(CvcCertificateRequestEntity.fromOrNull(request)).isNull();
    }

    @Test
    void preparesACvcRequestForTheHolder_whenTheCertificateIsRenewed() {
        // given
        CvcCertificateEntity certificate = new CvcCertificateEntity();
        certificate.setHolderReference("SEILMTERM00001");
        certificate.setAuthorityReference("SEILMDV00001");
        certificate.setPublicKeyAlgorithm("ECDSA");

        // when
        CvcCertificateRequestEntity request = certificate.prepareCertificateRequest(CertificateRequestFormat.CVC);

        // then
        assertThat(request.getHolderReference()).isEqualTo("SEILMTERM00001");
        assertThat(request.getAuthorityReference()).isNull();
        assertThat(request.getPublicKeyAlgorithm()).isEqualTo("ECDSA");
        assertThat(request.getCertificateRequestFormat()).isEqualTo(CertificateRequestFormat.CVC);
        assertThat(request.getComplianceStatus()).isEqualTo(ComplianceStatus.NOT_CHECKED);
    }
}

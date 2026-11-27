package com.otilm.core.dao.entity;

import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.core.certificate.type.Validity;
import com.otilm.core.certificate.type.ValidityPrecision;
import java.time.Instant;
import java.time.LocalDate;
import java.time.Month;
import java.util.TimeZone;
import org.hibernate.annotations.DynamicUpdate;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;

class CvcCertificateEntityTest {

    private static final Instant EFFECTIVE_DAY = Instant.parse("2026-01-15T00:00:00Z");
    private static final Instant EXPIRATION_DAY = Instant.parse("2026-04-14T00:00:00Z");

    @Test
    void reportsTheCvcType_whenACertificateOrRequestIsCreated() {
        // given — nothing stored yet

        // when
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
        Validity validity = new Validity(EFFECTIVE_DAY, EXPIRATION_DAY, ValidityPrecision.DATE);

        // when
        certificate.applyValidity(validity);

        // then
        assertThat(certificate.getNotBefore().toInstant()).isEqualTo(EFFECTIVE_DAY);
        assertThat(certificate.getNotAfter().toInstant()).isEqualTo(Instant.parse("2026-04-15T00:00:00Z"));
    }

    @Test
    void givesTheDatesBack_whenTheValidityWasStoredWithDatePrecision() {
        // given
        CvcCertificateEntity certificate = new CvcCertificateEntity();
        certificate.applyValidity(new Validity(EFFECTIVE_DAY, EXPIRATION_DAY, ValidityPrecision.DATE));

        // when
        LocalDate effectiveDate = certificate.getEffectiveDate();
        LocalDate expirationDate = certificate.getExpirationDate();

        // then
        assertThat(effectiveDate).isEqualTo(LocalDate.of(2026, Month.JANUARY, 15));
        assertThat(expirationDate).isEqualTo(LocalDate.of(2026, Month.APRIL, 14));
    }

    @Test
    void givesTheUtcDates_whenTheDefaultTimeZoneIsWestOfUtc() {
        // given
        TimeZone defaultZone = TimeZone.getDefault();
        TimeZone.setDefault(TimeZone.getTimeZone("America/Los_Angeles"));
        try {
            CvcCertificateEntity certificate = new CvcCertificateEntity();
            certificate.applyValidity(new Validity(EFFECTIVE_DAY, EXPIRATION_DAY, ValidityPrecision.DATE));

            // when
            LocalDate effectiveDate = certificate.getEffectiveDate();
            LocalDate expirationDate = certificate.getExpirationDate();

            // then
            assertThat(effectiveDate).isEqualTo(LocalDate.of(2026, Month.JANUARY, 15));
            assertThat(expirationDate).isEqualTo(LocalDate.of(2026, Month.APRIL, 14));
        } finally {
            TimeZone.setDefault(defaultZone);
        }
    }

    @Test
    void updatesOnlyTheChangedColumns_whenACvcCertificateIsSaved() {
        // given — Hibernate does not inherit the annotation from Certificate

        // when
        boolean dynamic = CvcCertificateEntity.class.isAnnotationPresent(DynamicUpdate.class);

        // then
        assertThat(dynamic).isTrue();
    }

    @Test
    void givesNoDates_whenTheCertificateHasNoValidity() {
        // given
        CvcCertificateEntity certificate = new CvcCertificateEntity();

        // when
        LocalDate effectiveDate = certificate.getEffectiveDate();
        LocalDate expirationDate = certificate.getExpirationDate();

        // then
        assertThat(effectiveDate).isNull();
        assertThat(expirationDate).isNull();
    }

    @Test
    void viewsTheCertificateAndRequestAsCvc_whenTheyAreCvc() {
        // given
        CvcCertificateEntity certificate = new CvcCertificateEntity();
        CvcCertificateRequestEntity request = new CvcCertificateRequestEntity();

        // when
        CvcCertificateEntity viewedCertificate = CvcCertificateEntity.fromOrNull(certificate);
        CvcCertificateRequestEntity viewedRequest = CvcCertificateRequestEntity.fromOrNull(request);

        // then
        assertThat(viewedCertificate).isSameAs(certificate);
        assertThat(viewedRequest).isSameAs(request);
    }

    @Test
    void viewsNothing_whenTheCertificateAndRequestAreX509() {
        // given
        X509CertificateEntity certificate = aCertificate().build();
        X509CertificateRequestEntity request = new X509CertificateRequestEntity();

        // when
        CvcCertificateEntity viewedCertificate = CvcCertificateEntity.fromOrNull(certificate);
        CvcCertificateRequestEntity viewedRequest = CvcCertificateRequestEntity.fromOrNull(request);

        // then
        assertThat(viewedCertificate).isNull();
        assertThat(viewedRequest).isNull();
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

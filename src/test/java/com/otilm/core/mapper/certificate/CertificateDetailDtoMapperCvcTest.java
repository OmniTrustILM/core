package com.otilm.core.mapper.certificate;

import com.otilm.api.model.core.certificate.CertificateDetail;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.certificate.CvcCertificateDetail;
import com.otilm.api.model.core.certificate.CvcCertificateRequestDetail;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.core.certificate.type.Validity;
import com.otilm.core.certificate.type.ValidityPrecision;
import com.otilm.core.dao.entity.CvcCertificateEntity;
import com.otilm.core.dao.entity.CvcCertificateRequestEntity;
import com.otilm.core.util.CertificateUtil;
import java.time.Instant;
import java.time.LocalDate;
import java.time.Month;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateDetailDtoMapperCvcTest {

    @Test
    void mapsTheCvcFieldsAndDates_whenTheCertificateIsCvc() {
        // given
        CvcCertificateEntity certificate = createCvcCertificate();

        // when
        CertificateDetail dto = CertificateDetailDtoMapper.toDetailDto(certificate);

        // then
        assertThat(dto).isInstanceOf(CvcCertificateDetail.class);
        CvcCertificateDetail cvc = (CvcCertificateDetail) dto;
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
    void mapsTheCvcRequestFields_whenTheCertificateWasIssuedFromACvcRequest() throws Exception {
        // given
        CvcCertificateEntity certificate = createCvcCertificate();
        CvcCertificateRequestEntity request = new CvcCertificateRequestEntity();
        request.setUuid(UUID.randomUUID());
        request.setCertificateRequestFormat(CertificateRequestFormat.CVC);
        request.setContent("AAAA");
        request.setHolderReference("SEILMTERM00001");
        request.setAuthorityReference("SEILMDV00001");
        request.setAuthenticatedBy("SEILMTERM00000");
        certificate.setCertificateRequest(request);

        // when
        CertificateDetail dto = CertificateDetailDtoMapper.toDetailDto(certificate);

        // then
        assertThat(dto.getCertificateRequest()).isInstanceOf(CvcCertificateRequestDetail.class);
        CvcCertificateRequestDetail cvc = (CvcCertificateRequestDetail) dto.getCertificateRequest();
        assertThat(cvc.getHolderReference()).isEqualTo("SEILMTERM00001");
        assertThat(cvc.getAuthorityReference()).isEqualTo("SEILMDV00001");
        assertThat(cvc.getAuthenticatedBy()).isEqualTo("SEILMTERM00000");
    }

    @Test
    void usesTheHolderReferenceAsDisplayName_whenTheCertificateIsCvc() {
        // given
        CvcCertificateEntity certificate = createCvcCertificate();

        // when
        CertificateDetail dto = CertificateDetailDtoMapper.toDetailDto(certificate);

        // then
        assertThat(dto.getDisplayName()).isEqualTo("SEILMTERM00001");
        assertThat(dto.getCommonName()).isNull();
    }

    @Test
    void showsThePlaceholderAsDisplayName_whenTheCvcHolderReferenceIsBlank() {
        // given
        CvcCertificateEntity certificate = createCvcCertificate();
        String blankHolderReference = " ";
        certificate.setHolderReference(blankHolderReference);

        // when
        CertificateDetail dto = CertificateDetailDtoMapper.toDetailDto(certificate);

        // then
        assertThat(dto.getDisplayName()).isEqualTo(CertificateUtil.EMPTY_COMMON_NAME_PLACEHOLDER);
        assertThat(dto.getCommonName()).isNull();
    }

    @Test
    void usesTheHolderReferenceAsDisplayName_whenTheRequestIsCvc() throws Exception {
        // given
        CvcCertificateEntity certificate = createCvcCertificate();
        CvcCertificateRequestEntity request = new CvcCertificateRequestEntity();
        request.setUuid(UUID.randomUUID());
        request.setCertificateRequestFormat(CertificateRequestFormat.CVC);
        request.setContent("AAAA");
        request.setHolderReference("SEILMTERM00001");
        certificate.setCertificateRequest(request);

        // when
        CertificateDetail dto = CertificateDetailDtoMapper.toDetailDto(certificate);

        // then
        assertThat(dto.getCertificateRequest().getDisplayName()).isEqualTo("SEILMTERM00001");
        assertThat(dto.getCertificateRequest().getCommonName()).isNull();
    }

    @Test
    void showsThePlaceholderAsDisplayName_whenTheCvcRequestHasNoHolderReference() throws Exception {
        // given
        String missingHolderReference = null;
        CvcCertificateEntity certificate = createCertificateWithRequestOf(missingHolderReference);

        // when
        String displayName = CertificateDetailDtoMapper
                .toDetailDto(certificate)
                .getCertificateRequest()
                .getDisplayName();

        // then
        assertThat(displayName).isEqualTo(CertificateUtil.EMPTY_COMMON_NAME_PLACEHOLDER);
    }

    @Test
    void showsThePlaceholderAsDisplayName_whenTheCvcRequestHolderReferenceIsBlank() throws Exception {
        // given
        String blankHolderReference = " ";
        CvcCertificateEntity certificate = createCertificateWithRequestOf(blankHolderReference);

        // when
        String displayName = CertificateDetailDtoMapper
                .toDetailDto(certificate)
                .getCertificateRequest()
                .getDisplayName();

        // then
        assertThat(displayName).isEqualTo(CertificateUtil.EMPTY_COMMON_NAME_PLACEHOLDER);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static CvcCertificateEntity createCertificateWithRequestOf(String holderReference) throws Exception {
        CvcCertificateEntity certificate = createCvcCertificate();
        CvcCertificateRequestEntity request = new CvcCertificateRequestEntity();
        request.setUuid(UUID.randomUUID());
        request.setCertificateRequestFormat(CertificateRequestFormat.CVC);
        request.setContent("AAAA");
        request.setHolderReference(holderReference);
        certificate.setCertificateRequest(request);
        return certificate;
    }

    private static CvcCertificateEntity createCvcCertificate() {
        CvcCertificateEntity certificate = new CvcCertificateEntity();
        certificate.setUuid(UUID.randomUUID());
        certificate.setHolderReference("SEILMTERM00001");
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

package com.otilm.core.mapper.certificate;

import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.certificate.CertificateDto;
import com.otilm.api.model.core.certificate.CertificateRelationType;
import com.otilm.api.model.core.certificate.CertificateSimpleDto;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.entity.X509CertificateRequestEntity;
import com.otilm.core.util.CertificateUtil;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static com.otilm.core.util.builders.CertificateRequestEntityBuilder.aCertificateRequest;
import static org.assertj.core.api.Assertions.assertThat;

class CertificateDetailDtoMapperDisplayNameTest {

    private static final String COMMON_NAME = "display.example.com";

    @Test
    void showsTheCommonName_whenMappingTheDetail() {
        // given
        X509CertificateEntity certificate = aCertificate()
                .withUuid(UUID.randomUUID())
                .withCommonName(COMMON_NAME)
                .build();

        // when
        CertificateDetailDto dto = CertificateDetailDtoMapper.toDetailDto(certificate);

        // then
        assertThat(dto.getDisplayName()).isEqualTo(COMMON_NAME);
    }

    @Test
    void showsThePlaceholder_whenTheDetailHasNoCommonName() {
        // given
        X509CertificateEntity certificate = aCertificate().withUuid(UUID.randomUUID()).withCommonName("").build();

        // when
        CertificateDetailDto dto = CertificateDetailDtoMapper.toDetailDto(certificate);

        // then
        assertThat(dto.getDisplayName()).isEqualTo(CertificateUtil.EMPTY_COMMON_NAME_PLACEHOLDER);
    }

    @Test
    void showsTheCommonName_whenMappingTheListEntry() {
        // given
        X509CertificateEntity certificate = aCertificate()
                .withUuid(UUID.randomUUID())
                .withCommonName(COMMON_NAME)
                .build();

        // when
        CertificateDto dto = CertificateDetailDtoMapper.toListDto(certificate);

        // then
        assertThat(dto.getDisplayName()).isEqualTo(COMMON_NAME);
    }

    @Test
    void showsTheCommonName_whenMappingTheSimpleEntry() {
        // given
        X509CertificateEntity certificate = aCertificate()
                .withUuid(UUID.randomUUID())
                .withCommonName(COMMON_NAME)
                .build();

        // when
        CertificateSimpleDto dto = CertificateDetailDtoMapper.toSimpleDto(certificate, CertificateRelationType.RENEWAL);

        // then
        assertThat(dto.getDisplayName()).isEqualTo(COMMON_NAME);
    }

    @Test
    void showsTheCommonNameOfTheRequest_whenTheDetailCarriesOne() {
        // given
        X509CertificateRequestEntity request = aCertificateRequest().withContent("content").build();
        request.setCommonName(COMMON_NAME);
        X509CertificateEntity certificate = aCertificate()
                .withUuid(UUID.randomUUID())
                .withCertificateRequest(request)
                .build();

        // when
        CertificateDetailDto dto = CertificateDetailDtoMapper.toDetailDto(certificate);

        // then
        assertThat(dto.getCertificateRequest().getDisplayName()).isEqualTo(COMMON_NAME);
    }
}

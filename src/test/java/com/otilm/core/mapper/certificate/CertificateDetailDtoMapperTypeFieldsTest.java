package com.otilm.core.mapper.certificate;

import com.otilm.api.model.core.certificate.CertificateDetail;
import com.otilm.api.model.core.certificate.CertificateDto;
import com.otilm.api.model.core.certificate.CertificateKeyUsage;
import com.otilm.api.model.core.certificate.CertificateRelationType;
import com.otilm.api.model.core.certificate.CertificateSimpleDto;
import com.otilm.api.model.core.certificate.X509CertificateDetail;
import com.otilm.api.model.core.certificate.X509CertificateRequestDetail;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.entity.X509CertificateRequestEntity;
import com.otilm.core.util.CertificateUtil;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static com.otilm.core.util.builders.CertificateRequestEntityBuilder.aCertificateRequest;
import static org.assertj.core.api.Assertions.assertThat;

class CertificateDetailDtoMapperTypeFieldsTest {

    private static final String COMMON_NAME = "display.example.com";

    @Test
    void showsTheCommonName_whenMappingTheDetail() {
        // given
        X509CertificateEntity certificate = aCertificate()
                .withUuid(UUID.randomUUID())
                .withCommonName(COMMON_NAME)
                .build();

        // when
        CertificateDetail dto = CertificateDetailDtoMapper.toDetailDto(certificate);

        // then
        assertThat(dto.getDisplayName()).isEqualTo(COMMON_NAME);
    }

    @Test
    void showsThePlaceholder_whenTheDetailHasNoCommonName() {
        // given
        X509CertificateEntity certificate = aCertificate().withUuid(UUID.randomUUID()).withCommonName("").build();

        // when
        CertificateDetail dto = CertificateDetailDtoMapper.toDetailDto(certificate);

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
        CertificateDetail dto = CertificateDetailDtoMapper.toDetailDto(certificate);

        // then
        assertThat(dto.getCertificateRequest().getDisplayName()).isEqualTo(COMMON_NAME);
    }

    @Test
    void buildsTheX509Subclass_whenTheCertificateIsX509() {
        // given
        X509CertificateEntity certificate = aCertificate()
                .withUuid(UUID.randomUUID())
                .withCommonName(COMMON_NAME)
                .withSubjectDn("CN=" + COMMON_NAME)
                .build();

        // when
        CertificateDetail dto = CertificateDetailDtoMapper.toDetailDto(certificate);

        // then
        assertThat(dto)
                .isInstanceOfSatisfying(X509CertificateDetail.class,
                        x509 -> assertThat(x509.getSubjectDn()).isEqualTo("CN=" + COMMON_NAME));
    }

    @Test
    void carriesTheContentOfTheIssuedCertificate_whenItHasBeenIssued() {
        // given
        X509CertificateEntity certificate = aCertificate()
                .withUuid(UUID.randomUUID())
                .withCertificateContent(new CertificateContent())
                .withIssuerDn("CN=Details CA")
                .withKeyUsage(CertificateKeyUsage.DIGITAL_SIGNATURE)
                .withExtendedKeyUsage("1.3.6.1.5.5.7.3.1")
                .build();

        // when
        CertificateDetail dto = CertificateDetailDtoMapper.toDetailDto(certificate);

        // then
        assertThat(dto).isInstanceOfSatisfying(X509CertificateDetail.class, x509 -> {
            assertThat(x509.getIssuerDn()).isEqualTo("CN=Details CA");
            assertThat(x509.getKeyUsage()).containsExactly(CertificateKeyUsage.DIGITAL_SIGNATURE);
            assertThat(x509.getExtendedKeyUsage()).containsExactly("1.3.6.1.5.5.7.3.1");
        });
    }

    @Test
    void leavesTheIssuedContentEmpty_whenTheCertificateHasNoContentYet() {
        // given
        X509CertificateEntity registration = aCertificate()
                .withUuid(UUID.randomUUID())
                .withIssuerDn("CN=Details CA")
                .withSubjectDn("CN=holder")
                .build();

        // when
        CertificateDetail dto = CertificateDetailDtoMapper.toDetailDto(registration);

        // then
        assertThat(dto).isInstanceOfSatisfying(X509CertificateDetail.class, x509 -> {
            assertThat(x509.getIssuerDn()).isNull();
            assertThat(x509.getKeyUsage()).isNull();
            assertThat(x509.getSubjectType()).isNull();
            assertThat(x509.getSubjectDn()).isEqualTo("CN=holder");
        });
    }

    @Test
    void leavesQcStatementsEmpty_whenNoQcFieldIsSet() {
        // given
        X509CertificateEntity certificate = aCertificate()
                .withUuid(UUID.randomUUID())
                .withCertificateContent(new CertificateContent())
                .build();

        // when
        CertificateDetail dto = CertificateDetailDtoMapper.toDetailDto(certificate);

        // then
        assertThat(dto)
                .isInstanceOfSatisfying(X509CertificateDetail.class,
                        x509 -> assertThat(x509.getQcStatements()).isNull());
    }

    @Test
    void carriesQcStatements_whenAQcFieldIsSet() {
        // given
        X509CertificateEntity certificate = aCertificate()
                .withUuid(UUID.randomUUID())
                .withCertificateContent(new CertificateContent())
                .withQcCompliance(true)
                .build();

        // when
        CertificateDetail dto = CertificateDetailDtoMapper.toDetailDto(certificate);

        // then
        assertThat(dto)
                .isInstanceOfSatisfying(X509CertificateDetail.class,
                        x509 -> assertThat(x509.getQcStatements().getQcCompliance()).isTrue());
    }

    @Test
    void buildsTheX509RequestSubclass_whenTheDetailCarriesARequest() {
        // given
        X509CertificateRequestEntity request = aCertificateRequest()
                .withContent("content")
                .withSubjectDn("CN=request-holder")
                .build();
        X509CertificateEntity certificate = aCertificate()
                .withUuid(UUID.randomUUID())
                .withCertificateRequest(request)
                .build();

        // when
        CertificateDetail dto = CertificateDetailDtoMapper.toDetailDto(certificate);

        // then
        assertThat(dto.getCertificateRequest())
                .isInstanceOfSatisfying(X509CertificateRequestDetail.class,
                        x509 -> assertThat(x509.getSubjectDn()).isEqualTo("CN=request-holder"));
    }
}

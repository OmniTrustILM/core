package com.otilm.core.integration.search;

import com.otilm.api.model.client.certificate.CertificateSearchRequestDto;
import com.otilm.api.model.core.certificate.CertificateDto;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.impl.CertificateServiceImpl;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.builders.SearchFilterRequestDtoBuilder.aPropertyFilter;

/**
 * CRL, OCSP and signature validation are not columns: each names one check inside the serialized validation result of
 * the certificate.
 */
class CertificateValidationCheckFilterITest extends BaseSpringBootTest {

    @Autowired
    private CertificateServiceImpl certificateService;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

    @BeforeEach
    void loadData() {
        seed("allValid", result("valid", "valid", "valid"));
        seed("revokedByCrl", result("valid", "revoked", "valid"));
        seed("ocspNotChecked", result("not_checked", "valid", "invalid"));
        seed("ocspFailedExpired", result("failed", "valid", "valid"));
        seed("neverValidated", null);
        seed("emptyResult", "");
    }

    private static String result(String ocsp, String crl, String signature) {
        return """
                {"ocsp_verification":{"validationCheck":"ocsp_verification","status":"%s"},
                 "crl_verification":{"validationCheck":"crl_verification","status":"%s"},
                 "signature":{"validationCheck":"signature","status":"%s"}}""".formatted(ocsp, crl, signature);
    }

    private void seed(String commonName, String validationResult) {
        CertificateContent content = new CertificateContent();
        content.setContent("1234567890-" + UUID.randomUUID());
        content = certificateContentRepository.save(content);

        Certificate certificate = new Certificate();
        certificate.setCommonName(commonName);
        certificate.setSubjectDn("CN=" + commonName);
        certificate.setIssuerDn("CN=" + commonName + "Issuer");
        certificate.setSerialNumber(UUID.randomUUID().toString().replace("-", ""));
        certificate.setState(CertificateState.ISSUED);
        certificate.setValidationStatus(CertificateValidationStatus.VALID);
        certificate.setCertificateValidationResult(validationResult);
        certificate.setCertificateContentId(content.getId());
        certificateRepository.save(certificate);
    }

    private Set<String> search(FilterField field, FilterConditionOperator condition, String value) {
        CertificateSearchRequestDto request = new CertificateSearchRequestDto();
        request.setPageNumber(1);
        request.setItemsPerPage(10);
        request.setFilters(List.of(aPropertyFilter(field, condition, new ArrayList<>(List.of(value)))));
        return certificateService
                .listCertificates(SecurityFilter.create(), request)
                .getCertificates()
                .stream()
                .map(CertificateDto::getCommonName)
                .collect(Collectors.toSet());
    }

    // Field names, not constants: touching FilterField here would initialise it before the JPA metamodel exists.
    static Stream<Arguments> equalsCases() {
        return Stream
                .of(Arguments.of("CRL_VALIDATION", "valid", Set.of("allValid", "ocspNotChecked", "ocspFailedExpired")),
                        Arguments.of("CRL_VALIDATION", "revoked", Set.of("revokedByCrl")),
                        Arguments.of("OCSP_VALIDATION", "not_checked", Set.of("ocspNotChecked")),
                        Arguments.of("OCSP_VALIDATION", "valid", Set.of("allValid", "revokedByCrl")),
                        Arguments.of("SIGNATURE_VALIDATION", "invalid", Set.of("ocspNotChecked")),
                        Arguments.of("SIGNATURE_VALIDATION", "failed", Set.of()));
    }

    @ParameterizedTest(name = "[{index}] {0} EQUALS {1}")
    @MethodSource("equalsCases")
    void equalsSelectsTheCertificatesWhoseCheckHasTheStatus(String field, String value, Set<String> expected) {
        Assertions.assertEquals(expected, search(FilterField.valueOf(field), FilterConditionOperator.EQUALS, value));
    }

    static Stream<Arguments> notEqualsCases() {
        return Stream
                .of(Arguments.of("CRL_VALIDATION", "valid", Set.of("revokedByCrl", "neverValidated", "emptyResult")),
                        Arguments
                                .of("OCSP_VALIDATION", "valid",
                                        Set.of("ocspNotChecked", "ocspFailedExpired", "neverValidated", "emptyResult")),
                        Arguments
                                .of("SIGNATURE_VALIDATION", "valid",
                                        Set.of("ocspNotChecked", "neverValidated", "emptyResult")));
    }

    @ParameterizedTest(name = "[{index}] {0} NOT_EQUALS {1}")
    @MethodSource("notEqualsCases")
    void notEqualsKeepsTheCertificatesWithAnotherStatusOrNoResult(String field, String value, Set<String> expected) {
        Assertions
                .assertEquals(expected, search(FilterField.valueOf(field), FilterConditionOperator.NOT_EQUALS, value));
    }
}

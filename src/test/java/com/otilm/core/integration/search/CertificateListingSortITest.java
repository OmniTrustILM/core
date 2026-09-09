package com.otilm.core.integration.search;

import com.otilm.api.model.client.certificate.CertificateSearchRequestDto;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchSortRequestDto;
import com.otilm.api.model.core.certificate.CertificateDto;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SortDirection;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.impl.CertificateServiceImpl;
import com.otilm.core.util.BaseSpringBootTest;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The certificate listing is the other two-phase fetch: a page of uuids in the requested order, then the DTOs by
 * {@code uuid IN (...)}. An ordering carried by the second query would replace the one the first established, so these
 * cases are what catches a sort that is accepted and then discarded.
 */
class CertificateListingSortITest extends BaseSpringBootTest {

    private static final List<String> SEEDED_NAMES = List.of("alpha", "bravo", "charlie", "delta");

    @Autowired
    private CertificateServiceImpl certificateService;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

    @BeforeEach
    void loadData() {
        // Seeded so that the alphabetical order the sort asks for is not the created-descending order the listing
        // applies by default. An assertion that only checked the returned set, or a sort that never reached the query,
        // would pass against the default order.
        seedCertificate("delta", CertificateState.ISSUED);
        seedCertificate("alpha", CertificateState.ISSUED);
        seedCertificate("charlie", CertificateState.REVOKED);
        seedCertificate("bravo", CertificateState.ISSUED);
    }

    private void seedCertificate(String commonName, CertificateState state) {
        CertificateContent content = new CertificateContent();
        content.setContent("1234567890-" + UUID.randomUUID());
        content = certificateContentRepository.save(content);

        Certificate certificate = new Certificate();
        certificate.setCommonName(commonName);
        certificate.setSubjectDn("CN=" + commonName);
        certificate.setIssuerDn("CN=" + commonName + "Issuer");
        certificate.setSerialNumber(UUID.randomUUID().toString().replace("-", ""));
        certificate.setState(state);
        certificate.setValidationStatus(CertificateValidationStatus.VALID);
        certificate.setCertificateContentId(content.getId());
        certificateRepository.save(certificate);
    }

    private List<String> listCommonNames(SearchSortRequestDto sort, List<SearchFilterRequestDto> filters,
            int pageNumber, int itemsPerPage) {
        CertificateSearchRequestDto request = new CertificateSearchRequestDto();
        request.setPageNumber(pageNumber);
        request.setItemsPerPage(itemsPerPage);
        request.setSort(sort);
        if (filters != null) {
            request.setFilters(filters);
        }

        return certificateService
                .listCertificates(SecurityFilter.create(), request)
                .getCertificates()
                .stream()
                .map(CertificateDto::getCommonName)
                .toList();
    }

    private static SearchSortRequestDto sortByCommonName(SortDirection direction) {
        return new SearchSortRequestDto(FilterFieldSource.PROPERTY, "COMMON_NAME", direction);
    }

    @Test
    void ordersTheListingByTheRequestedFieldAscending() {
        Assertions.assertEquals(SEEDED_NAMES, listCommonNames(sortByCommonName(SortDirection.ASC), null, 1, 10));
    }

    @Test
    void ordersTheListingByTheRequestedFieldDescending() {
        Assertions
                .assertEquals(SEEDED_NAMES.reversed(),
                        listCommonNames(sortByCommonName(SortDirection.DESC), null, 1, 10));
    }

    @Test
    void pagingWalksTheSortedSet() {
        List<String> paged = new ArrayList<>();
        paged.addAll(listCommonNames(sortByCommonName(SortDirection.ASC), null, 1, 2));
        paged.addAll(listCommonNames(sortByCommonName(SortDirection.ASC), null, 2, 2));

        Assertions.assertEquals(SEEDED_NAMES, paged);
    }

    /**
     * The listing's own default is created descending, and it has to survive untouched for a request that names no
     * sort. The expectation is read back from the seeded rows rather than written out, because four rows saved in one
     * test can share a created timestamp, and then the uuid tie-break rather than the seeding order decides.
     */
    @Test
    void aRequestWithoutASortKeepsTheListingDefaultOrder() {
        List<String> byDefaultOrder = certificateRepository
                .findAll()
                .stream()
                .filter(certificate -> SEEDED_NAMES.contains(certificate.getCommonName()))
                .sorted(Comparator.comparing(Certificate::getCreated).reversed().thenComparing(Certificate::getUuid))
                .map(Certificate::getCommonName)
                .toList();

        Assertions.assertEquals(byDefaultOrder, listCommonNames(null, null, 1, 10));
    }

    /**
     * A sorted listing must still return only the rows the filter admits - the ordering is applied to the filtered set,
     * not to the table.
     */
    @Test
    void sortingComposesWithAFilter() {
        List<SearchFilterRequestDto> issuedOnly = List
                .of(new SearchFilterRequestDto(FilterFieldSource.PROPERTY, "CERTIFICATE_STATE",
                        FilterConditionOperator.EQUALS, (Serializable) List.of(CertificateState.ISSUED.getCode())));

        Assertions
                .assertEquals(List.of("alpha", "bravo", "delta"),
                        listCommonNames(sortByCommonName(SortDirection.ASC), issuedOnly, 1, 10));
    }
}

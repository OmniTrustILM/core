package com.otilm.core.integration.search;

import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.core.oid.CustomOidEntryListResponseDto;
import com.otilm.api.model.core.oid.CustomOidEntryResponseDto;
import com.otilm.api.model.core.oid.ExtensionValueEncoding;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SortDirection;
import com.otilm.core.dao.entity.oid.CertificateExtensionCustomOidEntry;
import com.otilm.core.dao.entity.oid.CustomOidEntry;
import com.otilm.core.dao.entity.oid.GenericCustomOidEntry;
import com.otilm.core.dao.entity.oid.RdnAttributeTypeCustomOidEntry;
import com.otilm.core.dao.repository.CustomOidEntryRepository;
import com.otilm.core.dao.repository.SortSpecification;
import com.otilm.core.enums.FilterField;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CustomOidEntryExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.builders.SearchFilterRequestDtoBuilder.aPropertyFilter;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for filter fields whose attribute is declared on an inheritance subtype of the criteria root.
 *
 * <p>
 * Fixtures deliberately mix categories so that a filter which silently narrowed the query to the declaring subtype
 * would be visible, in the returned page and in the total alike.
 */
class SubclassFilterFieldSearchITest extends BaseSpringBootTest {

    private static final String GENERIC_OID = "1.1.1";
    private static final String EXTENSION_OID = "1.1.2";
    private static final String RDN_COMMON_NAME_OID = "1.1.3";
    private static final String RDN_ORG_UNIT_OID = "1.1.4";
    private static final String RDN_WITHOUT_CODE_OID = "1.1.5";

    @Autowired
    private CustomOidEntryExternalService customOidEntryService;

    @Autowired
    private CustomOidEntryRepository customOidEntryRepository;

    @BeforeEach
    void seedEntriesOfEveryCategory() {
        GenericCustomOidEntry generic = new GenericCustomOidEntry();
        generic.setOid(GENERIC_OID);
        generic.setCategory(OidCategory.GENERIC);
        generic.setDisplayName("generic entry");
        customOidEntryRepository.save(generic);

        CertificateExtensionCustomOidEntry extension = new CertificateExtensionCustomOidEntry();
        extension.setOid(EXTENSION_OID);
        extension.setCategory(OidCategory.CERTIFICATE_EXTENSION);
        extension.setDisplayName("extension entry");
        extension.setDefaultCritical(true);
        extension.setValueEncoding(ExtensionValueEncoding.IA5_STRING);
        customOidEntryRepository.save(extension);

        rdnEntry(RDN_COMMON_NAME_OID, "rdn common name entry", "CN", List.of("COMMON", "CN2"));
        rdnEntry(RDN_ORG_UNIT_OID, "rdn organizational unit entry", "OU", List.of("ORGUNIT"));
        rdnEntry(RDN_WITHOUT_CODE_OID, "rdn without a code entry", null, new ArrayList<>());
    }

    @Test
    void resolvesCodeDeclaredOnTheSubclass() {
        CustomOidEntryListResponseDto response = search(FilterField.OID_ENTRY_CODE, FilterConditionOperator.EQUALS,
                "CN");

        assertThat(response.getOidEntries())
                .extracting(CustomOidEntryResponseDto::getOid)
                .containsExactly(RDN_COMMON_NAME_OID);
    }

    @Test
    void resolvesAltCodesDeclaredOnTheSubclass() {
        CustomOidEntryListResponseDto response = search(FilterField.OID_ENTRY_ALT_CODES,
                FilterConditionOperator.CONTAINS, "ORGUNIT");

        assertThat(response.getOidEntries())
                .extracting(CustomOidEntryResponseDto::getOid)
                .containsExactly(RDN_ORG_UNIT_OID);
    }

    @Test
    void aSubclassFilterStillSpansEntriesOfEveryCategory() {
        CustomOidEntryListResponseDto response = search(FilterField.OID_ENTRY_CODE, FilterConditionOperator.EMPTY,
                null);

        assertThat(response.getOidEntries())
                .extracting(CustomOidEntryResponseDto::getOid)
                .containsExactlyInAnyOrder(GENERIC_OID, EXTENSION_OID, RDN_WITHOUT_CODE_OID);
    }

    @Test
    void theTotalAgreesWithThePageForANegatedSubclassFilter() {
        CustomOidEntryListResponseDto response = search(FilterField.OID_ENTRY_CODE, FilterConditionOperator.NOT_EQUALS,
                "CN");

        assertThat(response.getOidEntries())
                .extracting(CustomOidEntryResponseDto::getOid)
                .containsExactlyInAnyOrder(GENERIC_OID, EXTENSION_OID, RDN_ORG_UNIT_OID, RDN_WITHOUT_CODE_OID);
        assertThat(response.getTotalItems()).isEqualTo(4);
        assertThat(response.getTotalItems()).isEqualTo(response.getOidEntries().size());
    }

    @Test
    void theTotalAgreesWithThePageForAnEmptySubclassFilter() {
        CustomOidEntryListResponseDto response = search(FilterField.OID_ENTRY_CODE, FilterConditionOperator.EMPTY,
                null);

        assertThat(response.getTotalItems()).isEqualTo(3);
        assertThat(response.getTotalItems()).isEqualTo(response.getOidEntries().size());
    }

    @Test
    void baseClassFieldsResolveAgainstEveryCategory() {
        CustomOidEntryListResponseDto response = search(FilterField.OID_ENTRY_DISPLAY_NAME,
                FilterConditionOperator.CONTAINS, "entry");

        assertThat(response.getOidEntries())
                .extracting(CustomOidEntryResponseDto::getOid)
                .containsExactlyInAnyOrder(GENERIC_OID, EXTENSION_OID, RDN_COMMON_NAME_OID, RDN_ORG_UNIT_OID,
                        RDN_WITHOUT_CODE_OID);
    }

    /**
     * Descending, so the expected order contradicts both the fixture insertion order and the oid order.
     */
    @Test
    void ordersBySubclassDeclaredCodeAcrossEveryCategory() {
        List<CustomOidEntry> entries = customOidEntryRepository
                .findUsingSecurityFilter(SecurityFilter.create(), List.of(), null, null, null, new SortSpecification(
                        FilterFieldSource.PROPERTY, FilterField.OID_ENTRY_CODE.name(), SortDirection.DESC));

        assertThat(entries)
                .extracting(CustomOidEntry::getOid)
                .containsExactlyInAnyOrder(GENERIC_OID, EXTENSION_OID, RDN_COMMON_NAME_OID, RDN_ORG_UNIT_OID,
                        RDN_WITHOUT_CODE_OID);
        assertThat(entries)
                .extracting(CustomOidEntry::getOid)
                .filteredOn(oid -> oid.equals(RDN_COMMON_NAME_OID) || oid.equals(RDN_ORG_UNIT_OID))
                .containsExactly(RDN_ORG_UNIT_OID, RDN_COMMON_NAME_OID);
    }

    private CustomOidEntryListResponseDto search(FilterField field, FilterConditionOperator operator,
            Serializable value) {
        SearchRequestDto request = new SearchRequestDto();
        request.setFilters(List.of(aPropertyFilter(field, operator, value)));
        return customOidEntryService.listCustomOidEntries(request);
    }

    private void rdnEntry(String oid, String displayName, String code, List<String> altCodes) {
        RdnAttributeTypeCustomOidEntry entry = new RdnAttributeTypeCustomOidEntry();
        entry.setOid(oid);
        entry.setCategory(OidCategory.RDN_ATTRIBUTE_TYPE);
        entry.setDisplayName(displayName);
        entry.setCode(code);
        entry.setAltCodes(altCodes);
        customOidEntryRepository.save(entry);
    }
}

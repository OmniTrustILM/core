package com.czertainly.core.search;

import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.core.oid.CustomOidEntryListResponseDto;
import com.czertainly.api.model.core.oid.OidCategory;
import com.czertainly.api.model.core.search.FilterConditionOperator;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.core.dao.entity.oid.RdnAttributeTypeCustomOidEntry;
import com.czertainly.core.dao.repository.CustomOidEntryRepository;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.service.CustomOidEntryService;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.ArrayList;
import java.util.List;

/**
 * Integration tests for NATIVE_ARRAY filter operators using OID_ENTRY_ALT_CODES.
 *
 * Covers: EQUALS, NOT_EQUALS, EMPTY, NOT_EMPTY — all operating on a native
 * PostgreSQL text[] column (RdnAttributeTypeCustomOidEntry.altCodes).
 */
class NativeArrayFilterSearchTest extends BaseSpringBootTest {

    @Autowired
    private CustomOidEntryService customOidEntryService;

    @Autowired
    private CustomOidEntryRepository customOidEntryRepository;

    // altCodes = ["OFI", "OFI2"]
    private RdnAttributeTypeCustomOidEntry multiCode;
    // altCodes = ["ALONE"]
    private RdnAttributeTypeCustomOidEntry singleCode;
    // altCodes = [] (empty array stored as {})
    private RdnAttributeTypeCustomOidEntry noCode;

    @BeforeEach
    void setUp() {
        multiCode = rdnEntry("2.5.4.100", "Multi", "MULTI", List.of("OFI", "OFI2"));
        singleCode = rdnEntry("2.5.4.101", "Single", "SINGLE", List.of("ALONE"));
        noCode = rdnEntry("2.5.4.102", "NoCode", "NOCODE", new ArrayList<>());
    }

    // ─────────────────────────────────────────────
    // EQUALS
    // ─────────────────────────────────────────────

    @Test
    void filterByAltCodes_equals_matchesSingleEntryContainingValue() {
        List<String> oids = searchOids(FilterConditionOperator.EQUALS, "ALONE");

        Assertions.assertEquals(1, oids.size());
        Assertions.assertTrue(oids.contains(singleCode.getOid()));
    }

    @Test
    void filterByAltCodes_equals_matchesOneOfMultipleAltCodes() {
        List<String> oids = searchOids(FilterConditionOperator.EQUALS, "OFI2");

        Assertions.assertEquals(1, oids.size());
        Assertions.assertTrue(oids.contains(multiCode.getOid()));
    }

    @Test
    void filterByAltCodes_equals_noMatchForAbsentValue() {
        List<String> oids = searchOids(FilterConditionOperator.EQUALS, "NOSUCHCODE");

        Assertions.assertEquals(0, oids.size());
    }

    @Test
    void filterByAltCodes_equals_doesNotMatchEmptyArrayEntry() {
        List<String> oids = searchOids(FilterConditionOperator.EQUALS, "OFI");

        Assertions.assertFalse(oids.contains(noCode.getOid()),
                "Entry with empty altCodes array must not match EQUALS filter");
    }

    // ─────────────────────────────────────────────
    // NOT_EQUALS
    // ─────────────────────────────────────────────

    @Test
    void filterByAltCodes_notEquals_excludesEntryContainingValue() {
        List<String> oids = searchOids(FilterConditionOperator.NOT_EQUALS, "ALONE");

        Assertions.assertFalse(oids.contains(singleCode.getOid()),
                "Entry containing 'ALONE' must be excluded by NOT_EQUALS");
        Assertions.assertTrue(oids.contains(multiCode.getOid()));
        Assertions.assertTrue(oids.contains(noCode.getOid()));
    }

    @Test
    void filterByAltCodes_notEquals_includesEntryWithEmptyArray() {
        // An entry with {} does not contain "OFI", so NOT_EQUALS must include it.
        List<String> oids = searchOids(FilterConditionOperator.NOT_EQUALS, "OFI");

        Assertions.assertTrue(oids.contains(noCode.getOid()),
                "Entry with empty altCodes array must be included by NOT_EQUALS");
        Assertions.assertTrue(oids.contains(singleCode.getOid()));
        Assertions.assertFalse(oids.contains(multiCode.getOid()));
    }

    // ─────────────────────────────────────────────
    // EQUALS — multi-value (OR semantics)
    // ─────────────────────────────────────────────

    @Test
    void filterByAltCodes_equals_multiValue_matchesEntriesContainingAnyValue() {
        // Provide two values: "ALONE" (in singleCode) and "OFI2" (in multiCode).
        // EQUALS with multiple values = array contains any of them.
        List<String> oids = searchOids(FilterConditionOperator.EQUALS, List.of("ALONE", "OFI2"));

        Assertions.assertEquals(2, oids.size());
        Assertions.assertTrue(oids.contains(singleCode.getOid()));
        Assertions.assertTrue(oids.contains(multiCode.getOid()));
        Assertions.assertFalse(oids.contains(noCode.getOid()));
    }

    @Test
    void filterByAltCodes_equals_multiValue_noMatchWhenNonePresent() {
        List<String> oids = searchOids(FilterConditionOperator.EQUALS, List.of("NOSUCH1", "NOSUCH2"));

        Assertions.assertEquals(0, oids.size());
    }

    // ─────────────────────────────────────────────
    // NOT_EQUALS — multi-value (AND semantics: contains none)
    // ─────────────────────────────────────────────

    @Test
    void filterByAltCodes_notEquals_multiValue_excludesEntriesContainingAnyValue() {
        // Provide "OFI" and "ALONE": entries containing either must be excluded.
        // multiCode contains "OFI" → excluded; singleCode contains "ALONE" → excluded.
        // noCode contains neither → included.
        List<String> oids = searchOids(FilterConditionOperator.NOT_EQUALS, List.of("OFI", "ALONE"));

        Assertions.assertFalse(oids.contains(multiCode.getOid()),
                "multiCode contains 'OFI' and must be excluded");
        Assertions.assertFalse(oids.contains(singleCode.getOid()),
                "singleCode contains 'ALONE' and must be excluded");
        Assertions.assertTrue(oids.contains(noCode.getOid()),
                "noCode contains neither value and must be included");
    }

    @Test
    void filterByAltCodes_notEquals_multiValue_includesEntryNotContainingAnyValue() {
        // "OFI2" is only in multiCode; singleCode and noCode contain neither value.
        List<String> oids = searchOids(FilterConditionOperator.NOT_EQUALS, List.of("OFI2", "NOSUCH"));

        Assertions.assertFalse(oids.contains(multiCode.getOid()));
        Assertions.assertTrue(oids.contains(singleCode.getOid()));
        Assertions.assertTrue(oids.contains(noCode.getOid()));
    }

    // ─────────────────────────────────────────────
    // EMPTY
    // ─────────────────────────────────────────────

    @Test
    void filterByAltCodes_empty_matchesEntryWithEmptyArray() {
        // This is the regression for the Copilot-reported bug:
        // before the fix, IS NULL missed the non-null empty-array row.
        List<String> oids = searchOids(FilterConditionOperator.EMPTY, (String) null);

        Assertions.assertEquals(1, oids.size(),
                "EMPTY filter must match exactly the entry whose altCodes is an empty array {}");
        Assertions.assertTrue(oids.contains(noCode.getOid()));
    }

    @Test
    void filterByAltCodes_empty_doesNotMatchEntriesWithAltCodes() {
        List<String> oids = searchOids(FilterConditionOperator.EMPTY, (String) null);

        Assertions.assertFalse(oids.contains(multiCode.getOid()));
        Assertions.assertFalse(oids.contains(singleCode.getOid()));
    }

    // ─────────────────────────────────────────────
    // NOT_EMPTY
    // ─────────────────────────────────────────────

    @Test
    void filterByAltCodes_notEmpty_excludesEntryWithEmptyArray() {
        List<String> oids = searchOids(FilterConditionOperator.NOT_EMPTY, (String) null);

        Assertions.assertFalse(oids.contains(noCode.getOid()),
                "NOT_EMPTY filter must exclude the entry whose altCodes is an empty array {}");
    }

    @Test
    void filterByAltCodes_notEmpty_includesEntriesWithAltCodes() {
        List<String> oids = searchOids(FilterConditionOperator.NOT_EMPTY, (String) null);

        Assertions.assertTrue(oids.contains(multiCode.getOid()));
        Assertions.assertTrue(oids.contains(singleCode.getOid()));
    }

    // ─────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────

    private List<String> searchOids(FilterConditionOperator operator, String value) {
        SearchRequestDto request = new SearchRequestDto();
        request.setFilters(List.of(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY,
                        FilterField.OID_ENTRY_ALT_CODES.name(), operator, value)));
        CustomOidEntryListResponseDto response = customOidEntryService.listCustomOidEntries(request);
        return response.getOidEntries().stream()
                .map(item -> item.getOid())
                .toList();
    }

    private List<String> searchOids(FilterConditionOperator operator, List<String> values) {
        SearchRequestDto request = new SearchRequestDto();
        request.setFilters(List.of(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY,
                        FilterField.OID_ENTRY_ALT_CODES.name(), operator, new ArrayList<>(values))));
        CustomOidEntryListResponseDto response = customOidEntryService.listCustomOidEntries(request);
        return response.getOidEntries().stream()
                .map(item -> item.getOid())
                .toList();
    }

    private RdnAttributeTypeCustomOidEntry rdnEntry(String oid, String displayName, String code, List<String> altCodes) {
        RdnAttributeTypeCustomOidEntry entry = new RdnAttributeTypeCustomOidEntry();
        entry.setOid(oid);
        entry.setCategory(OidCategory.RDN_ATTRIBUTE_TYPE);
        entry.setDisplayName(displayName);
        entry.setDescription("test entry");
        entry.setCode(code);
        entry.setAltCodes(altCodes);
        return customOidEntryRepository.save(entry);
    }
}

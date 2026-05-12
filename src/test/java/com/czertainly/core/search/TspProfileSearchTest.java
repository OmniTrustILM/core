package com.czertainly.core.search;

import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.client.signing.protocols.tsp.TspProfileListDto;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.core.search.FilterConditionOperator;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.search.SearchFieldDataDto;
import com.czertainly.core.dao.entity.signing.TspProfile;
import com.czertainly.core.dao.repository.signing.TspProfileRepository;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.TspProfileService;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

class TspProfileSearchTest extends BaseSpringBootTest {

    @Autowired
    private TspProfileService tspProfileService;

    @Autowired
    private TspProfileRepository tspProfileRepository;

    private TspProfile alpha;
    private TspProfile beta;
    private TspProfile gamma;

    @BeforeEach
    void setUp() {
        alpha = new TspProfile();
        alpha.setName("alpha-tsp");
        alpha.setEnabled(true);
        alpha = tspProfileRepository.save(alpha);

        beta = new TspProfile();
        beta.setName("beta-tsp");
        beta.setEnabled(false);
        beta = tspProfileRepository.save(beta);

        gamma = new TspProfile();
        gamma.setName("gamma-tsp");
        gamma.setEnabled(true);
        gamma = tspProfileRepository.save(gamma);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // getSearchableFieldInformation
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void searchableFields_containsExpectedPropertyFields() {
        List<SearchFieldDataByGroupDto> groups = tspProfileService.getSearchableFieldInformation();

        Assertions.assertFalse(groups.isEmpty());
        List<String> identifiers = groups.stream()
                .flatMap(g -> g.getSearchFieldData().stream())
                .map(SearchFieldDataDto::getFieldIdentifier)
                .toList();

        Assertions.assertTrue(identifiers.contains(FilterField.TSP_PROFILE_NAME.name()));
        Assertions.assertTrue(identifiers.contains(FilterField.TSP_PROFILE_ENABLED.name()));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Filter by name
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void filterByName_equals_returnsSingleMatch() {
        List<TspProfileListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.TSP_PROFILE_NAME.name(),
                        FilterConditionOperator.EQUALS, "beta-tsp"));

        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals("beta-tsp", results.getFirst().getName());
    }

    @Test
    void filterByName_contains_returnsAllMatches() {
        List<TspProfileListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.TSP_PROFILE_NAME.name(),
                        FilterConditionOperator.CONTAINS, "-tsp"));

        Assertions.assertEquals(3, results.size());
    }

    @Test
    void filterByName_startsWith_returnsMatchingProfiles() {
        List<TspProfileListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.TSP_PROFILE_NAME.name(),
                        FilterConditionOperator.STARTS_WITH, "al"));

        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals("alpha-tsp", results.getFirst().getName());
    }

    @Test
    void filterByName_notEquals_returnsOtherProfiles() {
        List<TspProfileListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.TSP_PROFILE_NAME.name(),
                        FilterConditionOperator.NOT_EQUALS, "alpha-tsp"));

        Assertions.assertEquals(2, results.size());
        Assertions.assertTrue(results.stream().noneMatch(p -> p.getName().equals("alpha-tsp")));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Filter by enabled
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void filterByEnabled_true_returnsEnabledOnly() {
        List<TspProfileListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.TSP_PROFILE_ENABLED.name(),
                        FilterConditionOperator.EQUALS, true));

        Assertions.assertEquals(2, results.size());
        Assertions.assertTrue(results.stream().allMatch(TspProfileListDto::isEnabled));
    }

    @Test
    void filterByEnabled_false_returnsDisabledOnly() {
        List<TspProfileListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.TSP_PROFILE_ENABLED.name(),
                        FilterConditionOperator.EQUALS, false));

        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals("beta-tsp", results.getFirst().getName());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Combined filters
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void filterByNameContainsAndEnabled_returnsIntersection() {
        SearchRequestDto request = new SearchRequestDto();
        request.setFilters(List.of(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.TSP_PROFILE_NAME.name(),
                        FilterConditionOperator.CONTAINS, "-tsp"),
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.TSP_PROFILE_ENABLED.name(),
                        FilterConditionOperator.EQUALS, true)
        ));
        PaginationResponseDto<TspProfileListDto> response = tspProfileService.listTspProfiles(request, SecurityFilter.create());

        Assertions.assertEquals(2, response.getTotalItems());
        Assertions.assertTrue(response.getItems().stream().allMatch(TspProfileListDto::isEnabled));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Helper
    // ──────────────────────────────────────────────────────────────────────────

    private List<TspProfileListDto> listWithFilters(SearchFilterRequestDto... filters) {
        SearchRequestDto request = new SearchRequestDto();
        request.setFilters(List.of(filters));
        return tspProfileService.listTspProfiles(request, SecurityFilter.create()).getItems();
    }
}

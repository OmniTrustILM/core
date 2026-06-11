package com.otilm.core.search;

import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.client.signing.protocols.tsp.TspProfileListDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.TextAttributeContentV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.entity.signing.TspProfile;
import com.otilm.core.dao.repository.signing.SigningProfileRepository;
import com.otilm.core.dao.repository.signing.TspProfileRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.TspProfileService;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.UUID;

import static com.czertainly.core.util.builders.SearchFilterRequestDtoBuilder.aCustomAttributeFilter;
import static com.czertainly.core.util.builders.SearchFilterRequestDtoBuilder.aPropertyEqualsFilter;
import static com.czertainly.core.util.builders.SearchFilterRequestDtoBuilder.aPropertyFilter;
import static com.czertainly.core.util.builders.SearchFilterRequestDtoBuilder.aPropertyNotEqualsFilter;

class TspProfileSearchTest extends BaseSpringBootTest {

    private static final String CUSTOM_ATTR_NAME = "tsp-tag";
    private static final String CUSTOM_ATTR_VALUE = "alpha-tag-value";

    @Autowired
    private TspProfileService tspProfileService;

    @Autowired
    private AttributeEngine attributeEngine;

    @Autowired
    private TspProfileRepository tspProfileRepository;

    @Autowired
    private SigningProfileRepository signingProfileRepository;

    private TspProfile alpha;
    private TspProfile beta;
    private TspProfile gamma;
    private SigningProfile signingProfile;

    @BeforeEach
    void setUp() throws Exception {
        signingProfile = new SigningProfile();
        signingProfile.setName("default-signing");
        signingProfile.setEnabled(true);
        signingProfile.setSigningScheme(SigningScheme.DELEGATED);
        signingProfile.setWorkflowType(SigningWorkflowType.RAW_SIGNING);
        signingProfile.setLatestVersion(1);
        signingProfile = signingProfileRepository.save(signingProfile);

        alpha = new TspProfile();
        alpha.setName("alpha-tsp");
        alpha.setEnabled(true);
        alpha.setDefaultSigningProfile(signingProfile);
        alpha = tspProfileRepository.save(alpha);

        beta = new TspProfile();
        beta.setName("beta-tsp");
        beta.setEnabled(false);
        beta = tspProfileRepository.save(beta);

        gamma = new TspProfile();
        gamma.setName("gamma-tsp");
        gamma.setEnabled(true);
        gamma = tspProfileRepository.save(gamma);

        CustomAttributeV3 customAttr = new CustomAttributeV3();
        customAttr.setUuid(UUID.randomUUID().toString());
        customAttr.setName(CUSTOM_ATTR_NAME);
        customAttr.setType(AttributeType.CUSTOM);
        customAttr.setContentType(AttributeContentType.TEXT);
        CustomAttributeProperties props = new CustomAttributeProperties();
        props.setLabel("TSP Tag");
        customAttr.setProperties(props);
        attributeEngine.updateCustomAttributeDefinition(customAttr, List.of(Resource.TSP_PROFILE));

        RequestAttributeV3 requestAttr = new RequestAttributeV3();
        requestAttr.setUuid(UUID.fromString(customAttr.getUuid()));
        requestAttr.setName(CUSTOM_ATTR_NAME);
        requestAttr.setContent(List.of(new TextAttributeContentV3("ref-1", CUSTOM_ATTR_VALUE)));
        attributeEngine.updateObjectCustomAttributesContent(Resource.TSP_PROFILE, alpha.getUuid(), List.of(requestAttr));
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
        Assertions.assertTrue(identifiers.contains(FilterField.TSP_PROFILE_DEFAULT_SIGNING_PROFILE.name()));
    }

    @Test
    void searchableFields_defaultSigningProfileDropdownContainsExistingNames() {
        List<SearchFieldDataByGroupDto> groups = tspProfileService.getSearchableFieldInformation();

        SearchFieldDataDto defaultSpField = groups.stream()
                .flatMap(g -> g.getSearchFieldData().stream())
                .filter(f -> f.getFieldIdentifier().equals(FilterField.TSP_PROFILE_DEFAULT_SIGNING_PROFILE.name()))
                .findFirst()
                .orElseThrow();

        Assertions.assertNotNull(defaultSpField.getValue());
        Assertions.assertTrue(((List<?>) defaultSpField.getValue()).contains("default-signing"));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Filter by name
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void filterByName_equals_returnsSingleMatch() {
        List<TspProfileListDto> results = listWithFilters(
                aPropertyEqualsFilter(FilterField.TSP_PROFILE_NAME, "beta-tsp"));

        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals("beta-tsp", results.getFirst().getName());
    }

    @Test
    void filterByName_contains_returnsAllMatches() {
        List<TspProfileListDto> results = listWithFilters(
                aPropertyFilter(FilterField.TSP_PROFILE_NAME, FilterConditionOperator.CONTAINS, "-tsp"));

        Assertions.assertEquals(3, results.size());
    }

    @Test
    void filterByName_startsWith_returnsMatchingProfiles() {
        List<TspProfileListDto> results = listWithFilters(
                aPropertyFilter(FilterField.TSP_PROFILE_NAME, FilterConditionOperator.STARTS_WITH, "al"));

        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals("alpha-tsp", results.getFirst().getName());
    }

    @Test
    void filterByName_notEquals_returnsOtherProfiles() {
        List<TspProfileListDto> results = listWithFilters(
                aPropertyNotEqualsFilter(FilterField.TSP_PROFILE_NAME, "alpha-tsp"));

        Assertions.assertEquals(2, results.size());
        Assertions.assertTrue(results.stream().noneMatch(p -> p.getName().equals("alpha-tsp")));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Filter by enabled
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void filterByEnabled_true_returnsEnabledOnly() {
        List<TspProfileListDto> results = listWithFilters(
                aPropertyEqualsFilter(FilterField.TSP_PROFILE_ENABLED, true));

        Assertions.assertEquals(2, results.size());
        Assertions.assertTrue(results.stream().allMatch(TspProfileListDto::isEnabled));
    }

    @Test
    void filterByEnabled_false_returnsDisabledOnly() {
        List<TspProfileListDto> results = listWithFilters(
                aPropertyEqualsFilter(FilterField.TSP_PROFILE_ENABLED, false));

        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals("beta-tsp", results.getFirst().getName());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Filter by defaultSigningProfile (join)
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void filterByDefaultSigningProfile_equals_returnsOnlyAssociated() {
        List<TspProfileListDto> results = listWithFilters(
                aPropertyEqualsFilter(FilterField.TSP_PROFILE_DEFAULT_SIGNING_PROFILE, "default-signing"));

        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals("alpha-tsp", results.getFirst().getName());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Combined filters
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void filterByNameContainsAndEnabled_returnsIntersection() {
        SearchRequestDto request = new SearchRequestDto();
        request.setFilters(List.of(
                aPropertyFilter(FilterField.TSP_PROFILE_NAME, FilterConditionOperator.CONTAINS, "-tsp"),
                aPropertyEqualsFilter(FilterField.TSP_PROFILE_ENABLED, true)
        ));
        PaginationResponseDto<TspProfileListDto> response = tspProfileService.listTspProfiles(request, SecurityFilter.create());

        Assertions.assertEquals(2, response.getTotalItems());
        Assertions.assertTrue(response.getItems().stream().allMatch(TspProfileListDto::isEnabled));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Filter by custom attribute
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void filterByCustomAttribute_exactMatch_returnsOnlyTaggedProfile() {
        List<TspProfileListDto> results = listWithFilters(
                aCustomAttributeFilter(CUSTOM_ATTR_NAME, AttributeContentType.TEXT, FilterConditionOperator.EQUALS, CUSTOM_ATTR_VALUE));

        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals("alpha-tsp", results.getFirst().getName());
    }

    @Test
    void filterByCustomAttribute_notEquals_excludesTaggedProfile() {
        List<TspProfileListDto> results = listWithFilters(
                aCustomAttributeFilter(CUSTOM_ATTR_NAME, AttributeContentType.TEXT, FilterConditionOperator.NOT_EQUALS, CUSTOM_ATTR_VALUE));

        Assertions.assertTrue(results.stream().noneMatch(p -> p.getName().equals("alpha-tsp")));
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

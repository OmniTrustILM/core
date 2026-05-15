package com.czertainly.core.search;

import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.client.signing.profile.SigningProfileListDto;
import com.czertainly.api.model.client.signing.profile.scheme.SigningScheme;
import com.czertainly.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.core.search.FilterConditionOperator;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.search.SearchFieldDataDto;
import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.entity.signing.TimeQualityConfiguration;
import com.czertainly.core.dao.entity.signing.TspProfile;
import com.czertainly.core.dao.repository.signing.SigningProfileRepository;
import com.czertainly.core.dao.repository.signing.TimeQualityConfigurationRepository;
import com.czertainly.core.dao.repository.signing.TspProfileRepository;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.SigningProfileService;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Duration;
import java.util.List;

class SigningProfileSearchTest extends BaseSpringBootTest {

    @Autowired
    private SigningProfileService signingProfileService;

    @Autowired
    private SigningProfileRepository signingProfileRepository;

    @Autowired
    private TspProfileRepository tspProfileRepository;

    @Autowired
    private TimeQualityConfigurationRepository timeQualityConfigurationRepository;

    // Three profiles with distinct characteristics for filtering
    private SigningProfile profileA;  // DELEGATED / RAW_SIGNING, enabled, linked to tspAlpha + tqcFast
    private SigningProfile profileB;  // MANAGED   / CONTENT_SIGNING, disabled, no associations
    private SigningProfile profileC;  // DELEGATED / TIMESTAMPING, enabled, linked to tqcSlow

    private TspProfile tspAlpha;
    private TimeQualityConfiguration tqcFast;
    private TimeQualityConfiguration tqcSlow;

    @BeforeEach
    void setUp() {
        tspAlpha = new TspProfile();
        tspAlpha.setName("alpha-tsp");
        tspAlpha.setEnabled(true);
        tspAlpha = tspProfileRepository.save(tspAlpha);

        tqcFast = new TimeQualityConfiguration();
        tqcFast.setName("fast-tqc");
        tqcFast.setAccuracy(Duration.ofMillis(50));
        tqcFast.setNtpServers(List.of("pool.ntp.org"));
        tqcFast.setNtpCheckInterval(Duration.ofSeconds(30));
        tqcFast.setNtpSamplesPerServer(4);
        tqcFast.setNtpCheckTimeout(Duration.ofSeconds(3));
        tqcFast.setNtpServersMinReachable(2);
        tqcFast.setMaxClockDrift(Duration.ofMillis(100));
        tqcFast.setLeapSecondGuard(true);
        tqcFast = timeQualityConfigurationRepository.save(tqcFast);

        tqcSlow = new TimeQualityConfiguration();
        tqcSlow.setName("slow-tqc");
        tqcSlow.setAccuracy(Duration.ofSeconds(5));
        tqcSlow.setNtpServers(List.of("time.google.com"));
        tqcSlow.setNtpCheckInterval(Duration.ofSeconds(300));
        tqcSlow.setNtpSamplesPerServer(2);
        tqcSlow.setNtpCheckTimeout(Duration.ofSeconds(10));
        tqcSlow.setNtpServersMinReachable(1);
        tqcSlow.setMaxClockDrift(Duration.ofSeconds(2));
        tqcSlow.setLeapSecondGuard(false);
        tqcSlow = timeQualityConfigurationRepository.save(tqcSlow);

        profileA = new SigningProfile();
        profileA.setName("profile-alpha");
        profileA.setEnabled(true);
        profileA.setSigningScheme(SigningScheme.DELEGATED);
        profileA.setWorkflowType(SigningWorkflowType.RAW_SIGNING);
        profileA.setLatestVersion(1);
        profileA.setTspProfile(tspAlpha);
        profileA.setTimeQualityConfiguration(tqcFast);
        profileA = signingProfileRepository.save(profileA);

        profileB = new SigningProfile();
        profileB.setName("profile-beta");
        profileB.setEnabled(false);
        profileB.setSigningScheme(SigningScheme.MANAGED);
        profileB.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        profileB.setLatestVersion(1);
        profileB = signingProfileRepository.save(profileB);

        profileC = new SigningProfile();
        profileC.setName("profile-gamma");
        profileC.setEnabled(true);
        profileC.setSigningScheme(SigningScheme.DELEGATED);
        profileC.setWorkflowType(SigningWorkflowType.TIMESTAMPING);
        profileC.setLatestVersion(1);
        profileC.setTimeQualityConfiguration(tqcSlow);
        profileC = signingProfileRepository.save(profileC);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // getSearchableFieldInformation
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void searchableFields_containsExpectedPropertyFields() {
        List<SearchFieldDataByGroupDto> groups = signingProfileService.getSearchableFieldInformation();

        Assertions.assertFalse(groups.isEmpty());
        List<String> identifiers = groups.stream()
                .flatMap(g -> g.getSearchFieldData().stream())
                .map(SearchFieldDataDto::getFieldIdentifier)
                .toList();

        Assertions.assertTrue(identifiers.contains(FilterField.SIGNING_PROFILE_NAME.name()));
        Assertions.assertTrue(identifiers.contains(FilterField.SIGNING_PROFILE_ENABLED.name()));
        Assertions.assertTrue(identifiers.contains(FilterField.SIGNING_PROFILE_SIGNING_SCHEME.name()));
        Assertions.assertTrue(identifiers.contains(FilterField.SIGNING_PROFILE_WORKFLOW_TYPE.name()));
        Assertions.assertTrue(identifiers.contains(FilterField.SIGNING_PROFILE_TSP_PROFILE.name()));
        Assertions.assertTrue(identifiers.contains(FilterField.SIGNING_PROFILE_TIME_QUALITY_CONFIGURATION.name()));
    }

    @Test
    void searchableFields_tspProfileDropdownContainsExistingNames() {
        List<SearchFieldDataByGroupDto> groups = signingProfileService.getSearchableFieldInformation();

        SearchFieldDataDto tspField = groups.stream()
                .flatMap(g -> g.getSearchFieldData().stream())
                .filter(f -> f.getFieldIdentifier().equals(FilterField.SIGNING_PROFILE_TSP_PROFILE.name()))
                .findFirst()
                .orElseThrow();

        Assertions.assertNotNull(tspField.getValue());
        Assertions.assertTrue(((List<?>) tspField.getValue()).contains("alpha-tsp"));
    }

    @Test
    void searchableFields_tqcDropdownContainsExistingNames() {
        List<SearchFieldDataByGroupDto> groups = signingProfileService.getSearchableFieldInformation();

        SearchFieldDataDto tqcField = groups.stream()
                .flatMap(g -> g.getSearchFieldData().stream())
                .filter(f -> f.getFieldIdentifier().equals(FilterField.SIGNING_PROFILE_TIME_QUALITY_CONFIGURATION.name()))
                .findFirst()
                .orElseThrow();

        Assertions.assertNotNull(tqcField.getValue());
        List<?> values = (List<?>) tqcField.getValue();
        Assertions.assertTrue(values.contains("fast-tqc"));
        Assertions.assertTrue(values.contains("slow-tqc"));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Filter by name
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void filterByName_equals_returnsSingleMatch() {
        List<SigningProfileListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.SIGNING_PROFILE_NAME.name(),
                        FilterConditionOperator.EQUALS, "profile-beta"));

        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals("profile-beta", results.getFirst().getName());
    }

    @Test
    void filterByName_contains_returnsAllMatches() {
        List<SigningProfileListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.SIGNING_PROFILE_NAME.name(),
                        FilterConditionOperator.CONTAINS, "profile-"));

        Assertions.assertEquals(3, results.size());
    }

    @Test
    void filterByName_notContains_excludesMatch() {
        List<SigningProfileListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.SIGNING_PROFILE_NAME.name(),
                        FilterConditionOperator.NOT_CONTAINS, "beta"));

        Assertions.assertEquals(2, results.size());
        Assertions.assertTrue(results.stream().noneMatch(p -> p.getName().equals("profile-beta")));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Filter by enabled
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void filterByEnabled_true_returnsEnabledOnly() {
        List<SigningProfileListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.SIGNING_PROFILE_ENABLED.name(),
                        FilterConditionOperator.EQUALS, true));

        Assertions.assertEquals(2, results.size());
        Assertions.assertTrue(results.stream().allMatch(SigningProfileListDto::isEnabled));
    }

    @Test
    void filterByEnabled_false_returnsDisabledOnly() {
        List<SigningProfileListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.SIGNING_PROFILE_ENABLED.name(),
                        FilterConditionOperator.EQUALS, false));

        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals("profile-beta", results.getFirst().getName());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Filter by signingScheme
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void filterBySigningScheme_delegated_returnsDelegatedProfiles() {
        List<SigningProfileListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.SIGNING_PROFILE_SIGNING_SCHEME.name(),
                        FilterConditionOperator.EQUALS, SigningScheme.DELEGATED.getCode()));

        Assertions.assertEquals(2, results.size());
        List<String> names = results.stream().map(SigningProfileListDto::getName).toList();
        Assertions.assertTrue(names.contains("profile-alpha"));
        Assertions.assertTrue(names.contains("profile-gamma"));
    }

    @Test
    void filterBySigningScheme_managed_returnsManagedProfile() {
        List<SigningProfileListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.SIGNING_PROFILE_SIGNING_SCHEME.name(),
                        FilterConditionOperator.EQUALS, SigningScheme.MANAGED.getCode()));

        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals("profile-beta", results.getFirst().getName());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Filter by workflowType
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void filterByWorkflowType_rawSigning_returnsSingleProfile() {
        List<SigningProfileListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.SIGNING_PROFILE_WORKFLOW_TYPE.name(),
                        FilterConditionOperator.EQUALS, SigningWorkflowType.RAW_SIGNING.getCode()));

        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals("profile-alpha", results.getFirst().getName());
    }

    @Test
    void filterByWorkflowType_notEquals_excludesType() {
        List<SigningProfileListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.SIGNING_PROFILE_WORKFLOW_TYPE.name(),
                        FilterConditionOperator.NOT_EQUALS, SigningWorkflowType.CONTENT_SIGNING.getCode()));

        Assertions.assertEquals(2, results.size());
        Assertions.assertTrue(results.stream().noneMatch(p -> p.getName().equals("profile-beta")));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Filter by tspProfile (join)
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void filterByTspProfile_equals_returnsAssociatedProfile() {
        List<SigningProfileListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.SIGNING_PROFILE_TSP_PROFILE.name(),
                        FilterConditionOperator.EQUALS, "alpha-tsp"));

        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals("profile-alpha", results.getFirst().getName());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Filter by timeQualityConfiguration (join)
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void filterByTimeQualityConfiguration_fastTqc_returnsSingleProfile() {
        List<SigningProfileListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.SIGNING_PROFILE_TIME_QUALITY_CONFIGURATION.name(),
                        FilterConditionOperator.EQUALS, "fast-tqc"));

        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals("profile-alpha", results.getFirst().getName());
    }

    @Test
    void filterByTimeQualityConfiguration_slowTqc_returnsSingleProfile() {
        List<SigningProfileListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.SIGNING_PROFILE_TIME_QUALITY_CONFIGURATION.name(),
                        FilterConditionOperator.EQUALS, "slow-tqc"));

        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals("profile-gamma", results.getFirst().getName());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Combined filters
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void filterBySchemeAndEnabled_returnsIntersection() {
        // DELEGATED + enabled → profile-alpha and profile-gamma
        SearchRequestDto request = new SearchRequestDto();
        request.setFilters(List.of(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.SIGNING_PROFILE_SIGNING_SCHEME.name(),
                        FilterConditionOperator.EQUALS, SigningScheme.DELEGATED.getCode()),
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.SIGNING_PROFILE_ENABLED.name(),
                        FilterConditionOperator.EQUALS, true)
        ));
        PaginationResponseDto<SigningProfileListDto> response =
                signingProfileService.listSigningProfiles(request, SecurityFilter.create());

        Assertions.assertEquals(2, response.getTotalItems());
        Assertions.assertTrue(response.getItems().stream().allMatch(SigningProfileListDto::isEnabled));
    }

    @Test
    void filterByTspProfileAndEnabled_returnsSingleResult() {
        // tsp=alpha-tsp AND enabled=true → only profile-alpha
        SearchRequestDto request = new SearchRequestDto();
        request.setFilters(List.of(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.SIGNING_PROFILE_TSP_PROFILE.name(),
                        FilterConditionOperator.EQUALS, "alpha-tsp"),
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.SIGNING_PROFILE_ENABLED.name(),
                        FilterConditionOperator.EQUALS, true)
        ));
        PaginationResponseDto<SigningProfileListDto> response =
                signingProfileService.listSigningProfiles(request, SecurityFilter.create());

        Assertions.assertEquals(1, response.getTotalItems());
        Assertions.assertEquals("profile-alpha", response.getItems().getFirst().getName());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Helper
    // ──────────────────────────────────────────────────────────────────────────

    private List<SigningProfileListDto> listWithFilters(SearchFilterRequestDto... filters) {
        SearchRequestDto request = new SearchRequestDto();
        request.setFilters(List.of(filters));
        return signingProfileService.listSigningProfiles(request, SecurityFilter.create()).getItems();
    }
}

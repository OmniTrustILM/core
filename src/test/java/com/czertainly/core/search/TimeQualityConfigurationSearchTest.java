package com.czertainly.core.search;

import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.client.signing.timequality.TimeQualityConfigurationListDto;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.core.search.FilterConditionOperator;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.search.SearchFieldDataDto;
import com.czertainly.core.dao.entity.signing.TimeQualityConfiguration;
import com.czertainly.core.dao.repository.signing.TimeQualityConfigurationRepository;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.TimeQualityConfigurationService;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Duration;
import java.util.List;

class TimeQualityConfigurationSearchTest extends BaseSpringBootTest {

    @Autowired
    private TimeQualityConfigurationService timeQualityConfigurationService;

    @Autowired
    private TimeQualityConfigurationRepository timeQualityConfigurationRepository;

    private TimeQualityConfiguration strict;
    private TimeQualityConfiguration loose;
    private TimeQualityConfiguration guarded;

    @BeforeEach
    void setUp() {
        // strict: leapSecondGuard=true, minReachable=3, samplesPerServer=8
        strict = new TimeQualityConfiguration();
        strict.setName("strict-tqc");
        strict.setAccuracy(Duration.ofMillis(100));
        strict.setNtpServers(List.of("pool.ntp.org"));
        strict.setNtpCheckInterval(Duration.ofSeconds(60));
        strict.setNtpSamplesPerServer(8);
        strict.setNtpCheckTimeout(Duration.ofSeconds(5));
        strict.setNtpServersMinReachable(3);
        strict.setMaxClockDrift(Duration.ofMillis(200));
        strict.setLeapSecondGuard(true);
        strict = timeQualityConfigurationRepository.save(strict);

        // loose: leapSecondGuard=false, minReachable=1, samplesPerServer=2
        loose = new TimeQualityConfiguration();
        loose.setName("loose-tqc");
        loose.setAccuracy(Duration.ofSeconds(5));
        loose.setNtpServers(List.of("time.google.com"));
        loose.setNtpCheckInterval(Duration.ofSeconds(300));
        loose.setNtpSamplesPerServer(2);
        loose.setNtpCheckTimeout(Duration.ofSeconds(10));
        loose.setNtpServersMinReachable(1);
        loose.setMaxClockDrift(Duration.ofSeconds(2));
        loose.setLeapSecondGuard(false);
        loose = timeQualityConfigurationRepository.save(loose);

        // guarded: leapSecondGuard=true, minReachable=2, samplesPerServer=4
        guarded = new TimeQualityConfiguration();
        guarded.setName("guarded-tqc");
        guarded.setAccuracy(Duration.ofSeconds(1));
        guarded.setNtpServers(List.of("ntp1.example.com", "ntp2.example.com"));
        guarded.setNtpCheckInterval(Duration.ofSeconds(120));
        guarded.setNtpSamplesPerServer(4);
        guarded.setNtpCheckTimeout(Duration.ofSeconds(5));
        guarded.setNtpServersMinReachable(2);
        guarded.setMaxClockDrift(Duration.ofMillis(500));
        guarded.setLeapSecondGuard(true);
        guarded = timeQualityConfigurationRepository.save(guarded);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // getSearchableFieldInformation
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void searchableFields_containsExpectedPropertyFields() {
        List<SearchFieldDataByGroupDto> groups = timeQualityConfigurationService.getSearchableFieldInformation();

        Assertions.assertFalse(groups.isEmpty());
        List<String> identifiers = groups.stream()
                .flatMap(g -> g.getSearchFieldData().stream())
                .map(SearchFieldDataDto::getFieldIdentifier)
                .toList();

        Assertions.assertTrue(identifiers.contains(FilterField.TIME_QUALITY_CONFIGURATION_NAME.name()));
        Assertions.assertTrue(identifiers.contains(FilterField.TIME_QUALITY_CONFIGURATION_LEAP_SECOND_GUARD.name()));
        Assertions.assertTrue(identifiers.contains(FilterField.TIME_QUALITY_CONFIGURATION_NTP_SERVERS_MIN_REACHABLE.name()));
        Assertions.assertTrue(identifiers.contains(FilterField.TIME_QUALITY_CONFIGURATION_NTP_SAMPLES_PER_SERVER.name()));
        Assertions.assertTrue(identifiers.contains(FilterField.TIME_QUALITY_CONFIGURATION_NTP_SERVERS.name()));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Filter by name
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void filterByName_equals_returnsSingleMatch() {
        List<TimeQualityConfigurationListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.TIME_QUALITY_CONFIGURATION_NAME.name(),
                        FilterConditionOperator.EQUALS, "loose-tqc"));

        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals("loose-tqc", results.getFirst().getName());
    }

    @Test
    void filterByName_contains_returnsAllMatches() {
        List<TimeQualityConfigurationListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.TIME_QUALITY_CONFIGURATION_NAME.name(),
                        FilterConditionOperator.CONTAINS, "-tqc"));

        Assertions.assertEquals(3, results.size());
    }

    @Test
    void filterByName_startsWith_returnsMatchingConfigs() {
        List<TimeQualityConfigurationListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.TIME_QUALITY_CONFIGURATION_NAME.name(),
                        FilterConditionOperator.STARTS_WITH, "strict"));

        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals("strict-tqc", results.getFirst().getName());
    }

    @Test
    void filterByName_notEquals_returnsOtherConfigs() {
        List<TimeQualityConfigurationListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.TIME_QUALITY_CONFIGURATION_NAME.name(),
                        FilterConditionOperator.NOT_EQUALS, "strict-tqc"));

        Assertions.assertEquals(2, results.size());
        Assertions.assertTrue(results.stream().noneMatch(c -> c.getName().equals("strict-tqc")));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Filter by leapSecondGuard
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void filterByLeapSecondGuard_true_returnsGuardedConfigs() {
        List<TimeQualityConfigurationListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.TIME_QUALITY_CONFIGURATION_LEAP_SECOND_GUARD.name(),
                        FilterConditionOperator.EQUALS, true));

        Assertions.assertEquals(2, results.size());
        List<String> names = results.stream().map(TimeQualityConfigurationListDto::getName).toList();
        Assertions.assertTrue(names.contains("strict-tqc"));
        Assertions.assertTrue(names.contains("guarded-tqc"));
    }

    @Test
    void filterByLeapSecondGuard_false_returnsLooseConfig() {
        List<TimeQualityConfigurationListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.TIME_QUALITY_CONFIGURATION_LEAP_SECOND_GUARD.name(),
                        FilterConditionOperator.EQUALS, false));

        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals("loose-tqc", results.getFirst().getName());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Filter by ntpServersMinReachable
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void filterByNtpServersMinReachable_equals_returnsSingleMatch() {
        List<TimeQualityConfigurationListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.TIME_QUALITY_CONFIGURATION_NTP_SERVERS_MIN_REACHABLE.name(),
                        FilterConditionOperator.EQUALS, 3));

        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals("strict-tqc", results.getFirst().getName());
    }

    @Test
    void filterByNtpServersMinReachable_greater_returnsHigherMinConfigs() {
        // strict has minReachable=3, others have 1 and 2
        List<TimeQualityConfigurationListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.TIME_QUALITY_CONFIGURATION_NTP_SERVERS_MIN_REACHABLE.name(),
                        FilterConditionOperator.GREATER, 1));

        Assertions.assertEquals(2, results.size());
        List<String> names = results.stream().map(TimeQualityConfigurationListDto::getName).toList();
        Assertions.assertTrue(names.contains("strict-tqc"));
        Assertions.assertTrue(names.contains("guarded-tqc"));
    }

    @Test
    void filterByNtpServersMinReachable_lesser_returnsLowerMinConfigs() {
        // loose has minReachable=1
        List<TimeQualityConfigurationListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.TIME_QUALITY_CONFIGURATION_NTP_SERVERS_MIN_REACHABLE.name(),
                        FilterConditionOperator.LESSER, 2));

        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals("loose-tqc", results.getFirst().getName());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Filter by ntpSamplesPerServer
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void filterByNtpSamplesPerServer_equals_returnsSingleMatch() {
        List<TimeQualityConfigurationListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.TIME_QUALITY_CONFIGURATION_NTP_SAMPLES_PER_SERVER.name(),
                        FilterConditionOperator.EQUALS, 4));

        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals("guarded-tqc", results.getFirst().getName());
    }

    @Test
    void filterByNtpSamplesPerServer_greater_returnsHighSampleConfigs() {
        // strict has 8, guarded has 4, loose has 2
        List<TimeQualityConfigurationListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.TIME_QUALITY_CONFIGURATION_NTP_SAMPLES_PER_SERVER.name(),
                        FilterConditionOperator.GREATER, 3));

        Assertions.assertEquals(2, results.size());
        List<String> names = results.stream().map(TimeQualityConfigurationListDto::getName).toList();
        Assertions.assertTrue(names.contains("strict-tqc"));
        Assertions.assertTrue(names.contains("guarded-tqc"));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Filter by ntpServers
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void filterByNtpServers_equals_returnsSingleMatch() {
        // strict has pool.ntp.org only
        List<TimeQualityConfigurationListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.TIME_QUALITY_CONFIGURATION_NTP_SERVERS.name(),
                        FilterConditionOperator.EQUALS, "pool.ntp.org"));

        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals("strict-tqc", results.getFirst().getName());
    }

    @Test
    void filterByNtpServers_equals_matchesOneOfMultipleServers() {
        // guarded has ntp1.example.com and ntp2.example.com
        List<TimeQualityConfigurationListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.TIME_QUALITY_CONFIGURATION_NTP_SERVERS.name(),
                        FilterConditionOperator.EQUALS, "ntp1.example.com"));

        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals("guarded-tqc", results.getFirst().getName());
    }

    @Test
    void filterByNtpServers_notEquals_excludesMatchingConfig() {
        // NOT_EQUALS pool.ntp.org → loose (time.google.com) and guarded (ntp1/ntp2.example.com)
        List<TimeQualityConfigurationListDto> results = listWithFilters(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.TIME_QUALITY_CONFIGURATION_NTP_SERVERS.name(),
                        FilterConditionOperator.NOT_EQUALS, "pool.ntp.org"));

        Assertions.assertEquals(2, results.size());
        Assertions.assertTrue(results.stream().noneMatch(c -> c.getName().equals("strict-tqc")));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Combined filters
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void filterByLeapSecondGuardAndMinReachable_returnsIntersection() {
        // leapSecondGuard=true AND minReachable > 1 → strict (3) and guarded (2)
        // then add minReachable > 2 → only strict (3)
        SearchRequestDto request = new SearchRequestDto();
        request.setFilters(List.of(
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.TIME_QUALITY_CONFIGURATION_LEAP_SECOND_GUARD.name(),
                        FilterConditionOperator.EQUALS, true),
                new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY, FilterField.TIME_QUALITY_CONFIGURATION_NTP_SERVERS_MIN_REACHABLE.name(),
                        FilterConditionOperator.GREATER, 2)
        ));
        PaginationResponseDto<TimeQualityConfigurationListDto> response =
                timeQualityConfigurationService.listTimeQualityConfigurations(request, SecurityFilter.create());

        Assertions.assertEquals(1, response.getTotalItems());
        Assertions.assertEquals("strict-tqc", response.getItems().getFirst().getName());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Helper
    // ──────────────────────────────────────────────────────────────────────────

    private List<TimeQualityConfigurationListDto> listWithFilters(SearchFilterRequestDto... filters) {
        SearchRequestDto request = new SearchRequestDto();
        request.setFilters(List.of(filters));
        return timeQualityConfigurationService.listTimeQualityConfigurations(request, SecurityFilter.create()).getItems();
    }
}

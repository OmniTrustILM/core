package com.otilm.core.integration.service.impl;

import com.otilm.api.model.client.dashboard.SigningRecordStatisticsDto;
import com.otilm.api.model.client.dashboard.SigningRecordStatisticsPeriod;
import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.entity.signing.SigningProfileVersion;
import com.otilm.core.dao.entity.signing.SigningRecord;
import com.otilm.core.dao.repository.signing.SigningProfileRepository;
import com.otilm.core.dao.repository.signing.SigningProfileVersionRepository;
import com.otilm.core.dao.repository.signing.SigningRecordRepository;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.SigningRecordExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SigningRecordStatisticsServiceITest extends BaseSpringBootTest {

    @Autowired
    private SigningRecordExternalService signingRecordService;
    @Autowired
    private SigningRecordRepository signingRecordRepository;
    @Autowired
    private SigningProfileRepository signingProfileRepository;
    @Autowired
    private SigningProfileVersionRepository signingProfileVersionRepository;

    private Instant now;

    /**
     * Two profiles producing six retained records at known offsets from {@code now}:
     * <pre>
     *   alpha (TIMESTAMPING, MANAGED/STATIC_KEY): svc-tsa @2h TSP, svc-tsa @12h TSP, ci @3d TSP
     *   beta  (TIMESTAMPING, DELEGATED):          svc-tsa @1h CSC_API, &lt;none&gt; @10d TSP, ops @40d TSP
     * </pre>
     * Offsets sit well clear of the 24h/7d window edges so tiny clock skew never reclassifies a record.
     * One record is CSC_API under a TIMESTAMPING workflow so the by-protocol breakdown reflects the
     * persisted protocol column, not a workflow-derived guess (which would report every record as TSP).
     */
    @BeforeEach
    void seed() {
        now = Instant.now();
        SigningProfile alpha = insertProfile("alpha", SigningScheme.MANAGED, SigningWorkflowType.TIMESTAMPING);
        insertVersion(alpha, SigningScheme.MANAGED, ManagedSigningType.STATIC_KEY, SigningWorkflowType.TIMESTAMPING);
        SigningProfile beta = insertProfile("beta", SigningScheme.DELEGATED, SigningWorkflowType.TIMESTAMPING);
        insertVersion(beta, SigningScheme.DELEGATED, null, SigningWorkflowType.TIMESTAMPING);

        insertRecord(alpha, "svc-tsa", now.minus(Duration.ofHours(2)), SigningProtocol.TSP);
        insertRecord(alpha, "svc-tsa", now.minus(Duration.ofHours(12)), SigningProtocol.TSP);
        insertRecord(alpha, "ci", now.minus(Duration.ofDays(3)), SigningProtocol.TSP);
        insertRecord(beta, "svc-tsa", now.minus(Duration.ofHours(1)), SigningProtocol.CSC_API);
        insertRecord(beta, null, now.minus(Duration.ofDays(10)), SigningProtocol.TSP);
        insertRecord(beta, "ops", now.minus(Duration.ofDays(40)), SigningProtocol.TSP);
    }

    @Test
    void counts_reflectRetentionAndSigningTimeWindows() {
        SigningRecordStatisticsDto dto = statistics(SigningRecordStatisticsPeriod.LAST_7D);

        assertThat(dto.getTotalRetained()).isEqualTo(6L);
        assertThat(dto.getCountLast24h()).isEqualTo(3L);
        assertThat(dto.getCountLast7d()).isEqualTo(4L);
        assertThat(dto.getActiveProfileCount()).isEqualTo(2L);
        assertThat(dto.getDistinctRequesterCount()).isEqualTo(4L);
    }

    @Test
    void statByProfile_countsByProfileName() {
        SigningRecordStatisticsDto dto = statistics(SigningRecordStatisticsPeriod.LAST_7D);

        assertThat(dto.getStatByProfile()).containsOnly(
                org.assertj.core.api.Assertions.entry("alpha", 3L),
                org.assertj.core.api.Assertions.entry("beta", 3L));
    }

    @Test
    void statByRequester_returnsTopWithUnassignedForNull() {
        SigningRecordStatisticsDto dto = statistics(SigningRecordStatisticsPeriod.LAST_7D);

        assertThat(dto.getStatByRequester())
                .containsEntry("svc-tsa", 3L)
                .containsEntry("ci", 1L)
                .containsEntry("ops", 1L)
                .containsEntry("Unassigned", 1L);
        // highest count first
        assertThat(dto.getStatByRequester().keySet().iterator().next()).isEqualTo("svc-tsa");
    }

    @Test
    void breakdowns_useCodesAndFlattenedScheme() {
        SigningRecordStatisticsDto dto = statistics(SigningRecordStatisticsPeriod.LAST_7D);

        assertThat(dto.getStatByWorkflowType()).containsOnly(org.assertj.core.api.Assertions.entry("timestamping", 6L));
        assertThat(dto.getStatByProtocol()).containsOnly(
                org.assertj.core.api.Assertions.entry("tsp", 5L),
                org.assertj.core.api.Assertions.entry("csc_api", 1L));
        assertThat(dto.getStatByScheme()).containsOnly(
                org.assertj.core.api.Assertions.entry("managed_static_key", 3L),
                org.assertj.core.api.Assertions.entry("delegated", 3L));
    }

    @Test
    void volumeOverTime_dailyIsDenseAndSumsToWindowCount() {
        SigningRecordStatisticsDto dto = statistics(SigningRecordStatisticsPeriod.LAST_7D);

        List<String> keys = new ArrayList<>(dto.getVolumeOverTime().keySet());
        assertThat(keys).allMatch(k -> k.endsWith("T00:00:00Z"), "daily buckets keyed at UTC midnight");
        assertContiguous(keys, Duration.ofDays(1));
        assertThat(dto.getVolumeOverTime().values().stream().mapToLong(Long::longValue).sum())
                .isEqualTo(dto.getCountLast7d());
    }

    @Test
    void volumeOverTime_hourlyForLast24h() {
        SigningRecordStatisticsDto dto = statistics(SigningRecordStatisticsPeriod.LAST_24H);

        List<String> keys = new ArrayList<>(dto.getVolumeOverTime().keySet());
        assertThat(keys).allMatch(k -> k.endsWith(":00:00Z"), "hourly buckets keyed at the top of the hour");
        assertContiguous(keys, Duration.ofHours(1));
        assertThat(dto.getVolumeOverTime().values().stream().mapToLong(Long::longValue).sum())
                .isEqualTo(dto.getCountLast24h());
    }

    private SigningRecordStatisticsDto statistics(SigningRecordStatisticsPeriod period) {
        return signingRecordService.getSigningRecordStatistics(period, SecurityFilter.create());
    }

    private static void assertContiguous(List<String> isoKeys, Duration step) {
        for (int i = 1; i < isoKeys.size(); i++) {
            Instant prev = Instant.parse(isoKeys.get(i - 1));
            Instant cur = Instant.parse(isoKeys.get(i));
            assertThat(Duration.between(prev, cur)).as("gap before %s", isoKeys.get(i)).isEqualTo(step);
        }
    }

    private SigningProfile insertProfile(String name, SigningScheme scheme, SigningWorkflowType workflowType) {
        SigningProfile profile = new SigningProfile();
        profile.setName(name);
        profile.setEnabled(false);
        profile.setSigningScheme(scheme);
        profile.setWorkflowType(workflowType);
        profile.setLatestVersion(1);
        return signingProfileRepository.saveAndFlush(profile);
    }

    private void insertVersion(SigningProfile profile, SigningScheme scheme, ManagedSigningType managedType,
                               SigningWorkflowType workflowType) {
        SigningProfileVersion version = new SigningProfileVersion();
        version.setSigningProfile(profile);
        version.setVersion(1);
        version.setSigningScheme(scheme);
        version.setManagedSigningType(managedType);
        version.setWorkflowType(workflowType);
        signingProfileVersionRepository.saveAndFlush(version);
    }

    private void insertRecord(SigningProfile profile, String requestedByUsername, Instant signingTime,
                              SigningProtocol protocol) {
        SigningRecord record = new SigningRecord();
        record.setSigningProfileUuid(profile.getUuid());
        record.setSigningProfileVersion(1);
        record.setSigningTime(signingTime);
        record.setRequestedByUsername(requestedByUsername);
        record.setProtocol(protocol);
        signingRecordRepository.saveAndFlush(record);
    }
}

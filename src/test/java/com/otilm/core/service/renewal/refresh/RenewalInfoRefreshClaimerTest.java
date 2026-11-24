package com.otilm.core.service.renewal.refresh;

import com.otilm.api.model.core.settings.CertificateRenewalInfoSettingsDto;
import com.otilm.api.model.core.settings.CertificateSettingsDto;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.cluster.ClusterOperationSynchronizer.Operation;
import com.otilm.core.dao.repository.CertificateRenewalInfoRepository.RefreshClaim;
import com.otilm.core.messaging.jms.configuration.RenewalInfoProperties;
import com.otilm.core.service.SettingInternalService;
import com.otilm.core.service.writer.RenewalRefreshWriter;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.IntStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RenewalInfoRefreshClaimerTest {

    private static final Instant NOW = Instant.parse("2026-11-24T10:00:00Z");

    @Mock
    ClusterOperationSynchronizer clusterSynchronizer;
    @Mock
    RenewalRefreshWriter refreshWriter;
    @Mock
    SettingInternalService settingService;

    private RenewalInfoRefreshClaimer claimer;

    @BeforeEach
    void setUp() {
        CertificateRenewalInfoSettingsDto renewalInfo = new CertificateRenewalInfoSettingsDto();
        renewalInfo.setRefreshBatchSize(20);
        renewalInfo.setRefreshDefaultInterval(7200);
        CertificateSettingsDto certificates = new CertificateSettingsDto();
        certificates.setRenewalInfo(renewalInfo);
        PlatformSettingsDto platform = new PlatformSettingsDto();
        platform.setCertificates(certificates);
        lenient().when(settingService.getPlatformSettingsInternal()).thenReturn(platform);
        claimer = new RenewalInfoRefreshClaimer(clusterSynchronizer, refreshWriter, settingService,
                new RenewalInfoProperties(60_000, 150, 300, null, Duration.ofMinutes(10), 4));
    }

    @Test
    void claimsNothing_whenAnotherNodeHoldsTheLock() {
        // given
        when(clusterSynchronizer.tryLock(Operation.RENEWAL_INFO_REFRESH_SWEEP)).thenReturn(false);

        // when
        List<AuthorityRefresh> refreshes = claimer.claim(NOW);

        // then
        assertThat(refreshes).isEmpty();
        verifyNoInteractions(refreshWriter);
    }

    @Test
    void passesTheCapsAndTheLease_whenItHoldsTheLock() {
        // given
        when(clusterSynchronizer.tryLock(Operation.RENEWAL_INFO_REFRESH_SWEEP)).thenReturn(true);
        when(refreshWriter.claimDue(any(), anyInt(), any())).thenReturn(List.of());

        // when
        List<AuthorityRefresh> refreshes = claimer.claim(NOW);

        // then
        assertThat(refreshes).isEmpty();
        verify(refreshWriter).stopIneligibleDue(NOW);
        verify(refreshWriter).enrolEligible(NOW, 7200, 300);
        verify(refreshWriter).claimDue(NOW, 150, NOW.plus(Duration.ofMinutes(10)));
    }

    @Test
    void splitsTheCertificatesOfAnRaProfileIntoBatchesOfTheBatchSize() {
        // given
        UUID authority = UUID.randomUUID();
        UUID raProfile = UUID.randomUUID();
        List<RefreshClaim> claimed = claims(authority, raProfile, 45);
        when(clusterSynchronizer.tryLock(Operation.RENEWAL_INFO_REFRESH_SWEEP)).thenReturn(true);
        when(refreshWriter.claimDue(any(), anyInt(), any())).thenReturn(claimed);

        // when
        List<AuthorityRefresh> refreshes = claimer.claim(NOW);

        // then
        assertThat(refreshes).singleElement().satisfies(refresh -> {
            assertThat(refresh.authorityUuid()).isEqualTo(authority);
            assertThat(refresh.batches())
                    .extracting(batch -> batch.certificateUuids().size())
                    .containsExactly(20, 20, 5);
            assertThat(refresh.batches()).allMatch(batch -> batch.raProfileUuid().equals(raProfile));
            assertThat(refresh.certificateCount()).isEqualTo(45);
        });
    }

    @Test
    void keepsRaProfilesAndAuthoritiesApart() {
        // given
        UUID authorityA = UUID.randomUUID();
        UUID authorityB = UUID.randomUUID();
        UUID profileA1 = UUID.randomUUID();
        UUID profileA2 = UUID.randomUUID();
        UUID profileB = UUID.randomUUID();
        List<RefreshClaim> claimed = new ArrayList<>();
        claimed.addAll(claims(authorityA, profileA1, 3));
        claimed.addAll(claims(authorityB, profileB, 2));
        claimed.addAll(claims(authorityA, profileA2, 1));

        // when
        List<AuthorityRefresh> refreshes = RenewalInfoRefreshClaimer.group(claimed, 20);

        // then
        assertThat(refreshes).extracting(AuthorityRefresh::authorityUuid).containsExactly(authorityA, authorityB);
        assertThat(refreshes.get(0).batches())
                .extracting(RefreshBatch::raProfileUuid)
                .containsExactly(profileA1, profileA2);
        assertThat(refreshes.get(1).batches())
                .singleElement()
                .satisfies(batch -> assertThat(batch.certificateUuids()).hasSize(2));
    }

    private static List<RefreshClaim> claims(UUID authority, UUID raProfile, int count) {
        return IntStream
                .range(0, count)
                .<RefreshClaim>mapToObj(i -> new Claim(UUID.randomUUID(), raProfile, authority))
                .toList();
    }

    private record Claim(UUID certificateUuid, UUID raProfileUuid, UUID authorityUuid) implements RefreshClaim {

        @Override
        public UUID getCertificateUuid() {
            return certificateUuid;
        }

        @Override
        public UUID getRaProfileUuid() {
            return raProfileUuid;
        }

        @Override
        public UUID getAuthorityUuid() {
            return authorityUuid;
        }
    }
}

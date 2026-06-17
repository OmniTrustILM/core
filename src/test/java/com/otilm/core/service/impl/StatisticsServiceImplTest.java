package com.otilm.core.service.impl;

import com.otilm.api.model.client.dashboard.StatisticsDto;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.security.access.AccessDeniedException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;

class StatisticsServiceImplTest {

    private StatisticsServiceImpl statisticsService;

    @Mock private CertificateService certificateService;
    @Mock private DiscoveryService discoveryService;
    @Mock private GroupInternalService groupService;
    @Mock private RaProfileService raProfileService;
    @Mock private SecretInternalService secretService;
    @Mock private VaultInstanceInternalService vaultInstanceService;
    @Mock private VaultProfileInternalService vaultProfileService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        statisticsService = new StatisticsServiceImpl();
        statisticsService.setCertificateService(certificateService);
        statisticsService.setDiscoveryService(discoveryService);
        statisticsService.setGroupService(groupService);
        statisticsService.setRaProfileService(raProfileService);
        statisticsService.setSecretService(secretService);
        statisticsService.setVaultInstanceService(vaultInstanceService);
        statisticsService.setVaultProfileService(vaultProfileService);

        Mockito.when(certificateService.statisticsCertificateCount(any(), anyBoolean())).thenReturn(0L);
        Mockito.when(certificateService.addCertificateStatistics(any(), any(), anyBoolean())).thenAnswer(i -> i.getArgument(1));
        Mockito.when(discoveryService.statisticsDiscoveryCount(any())).thenReturn(0L);
        Mockito.when(groupService.statisticsGroupCount(any())).thenReturn(0L);
        Mockito.when(raProfileService.statisticsRaProfilesCount(any())).thenReturn(0L);
    }

    @Test
    void testGetStatistics_whenAccessDenied_totalsDefaultToZero() {
        Mockito.when(secretService.statisticsSecretCount(any(SecurityFilter.class)))
                .thenThrow(new AccessDeniedException("denied"));
        Mockito.when(vaultInstanceService.statisticsVaultInstanceCount(any(SecurityFilter.class)))
                .thenThrow(new AccessDeniedException("denied"));
        Mockito.when(vaultProfileService.statisticsVaultProfileCount(any(SecurityFilter.class)))
                .thenThrow(new AccessDeniedException("denied"));
        Mockito.when(secretService.addSecretStatistics(any(SecurityFilter.class), any(StatisticsDto.class)))
                .thenThrow(new AccessDeniedException("denied"));

        StatisticsDto result = statisticsService.getStatistics(false);

        Assertions.assertNotNull(result);
        Assertions.assertEquals(0L, result.getTotalSecrets());
        Assertions.assertEquals(0L, result.getTotalVaultInstances());
        Assertions.assertEquals(0L, result.getTotalVaultProfiles());
    }
}

package com.czertainly.core.service.impl;

import com.czertainly.api.model.client.dashboard.StatisticsDto;
import com.czertainly.core.security.authz.AnyPrincipalEndpoint;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.CertificateService;
import com.czertainly.core.service.DiscoveryService;
import com.czertainly.core.service.GroupService;
import com.czertainly.core.service.RaProfileService;
import com.czertainly.core.service.SecretService;
import com.czertainly.core.service.StatisticsExternalService;
import com.czertainly.core.service.VaultInstanceService;
import com.czertainly.core.service.VaultProfileService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

import jakarta.transaction.Transactional;

@Service
@Transactional
public class StatisticsServiceImpl implements StatisticsExternalService {

    private static final Logger logger = LoggerFactory.getLogger(StatisticsServiceImpl.class);

    private CertificateService certificateService;
    private DiscoveryService discoveryService;
    private GroupService groupService;
    private RaProfileService raProfileService;
    private SecretService secretService;
    private VaultInstanceService vaultInstanceService;
    private VaultProfileService vaultProfileService;


    @Override
    @AnyPrincipalEndpoint
    public StatisticsDto getStatistics(boolean includeArchived) {
        logger.info("Gathering the statistics information from database");
        StatisticsDto dto = new StatisticsDto();

        dto.setTotalCertificates(certificateService.statisticsCertificateCount(SecurityFilter.create(), includeArchived));
        try {
            dto.setTotalDiscoveries(discoveryService.statisticsDiscoveryCount(SecurityFilter.create()));
        } catch (AccessDeniedException e) {
            dto.setTotalDiscoveries(0L);
        }
        try {
            dto.setTotalGroups(groupService.statisticsGroupCount(SecurityFilter.create()));
        } catch (AccessDeniedException e) {
            dto.setTotalGroups(0L);
        }
        try {
            dto.setTotalRaProfiles(raProfileService.statisticsRaProfilesCount(SecurityFilter.create()));
        } catch (AccessDeniedException e){
            dto.setTotalRaProfiles(0L);
        }
        try {
            dto.setTotalSecrets(secretService.statisticsSecretCount(SecurityFilter.create()));
        } catch (AccessDeniedException e) {
            dto.setTotalSecrets(0L);
        }
        try {
            dto.setTotalVaultInstances(vaultInstanceService.statisticsVaultInstanceCount(SecurityFilter.create()));
        } catch (AccessDeniedException e) {
            dto.setTotalVaultInstances(0L);
        }
        try {
            dto.setTotalVaultProfiles(vaultProfileService.statisticsVaultProfileCount(SecurityFilter.create()));
        } catch (AccessDeniedException e) {
            dto.setTotalVaultProfiles(0L);
        }
        certificateService.addCertificateStatistics(SecurityFilter.create(), dto, includeArchived);
        try {
            return secretService.addSecretStatistics(SecurityFilter.create(), dto);
        } catch (AccessDeniedException e) {
            return dto;
        }
    }

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setDiscoveryService(DiscoveryService discoveryService) {
        this.discoveryService = discoveryService;
    }

    @Autowired
    public void setGroupService(GroupService groupService) {
        this.groupService = groupService;
    }

    @Autowired
    public void setRaProfileService(RaProfileService raProfileService) {
        this.raProfileService = raProfileService;
    }

    @Autowired
    public void setSecretService(SecretService secretService) {
        this.secretService = secretService;
    }

    @Autowired
    public void setVaultInstanceService(VaultInstanceService vaultInstanceService) {
        this.vaultInstanceService = vaultInstanceService;
    }

    @Autowired
    public void setVaultProfileService(VaultProfileService vaultProfileService) {
        this.vaultProfileService = vaultProfileService;
    }
}

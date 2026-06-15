package com.otilm.core.service.impl;

import com.otilm.api.model.client.dashboard.StatisticsDto;
import com.otilm.core.security.authz.AnyPrincipalEndpoint;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CertificateService;
import com.otilm.core.service.DiscoveryService;
import com.otilm.core.service.GroupInternalService;
import com.otilm.core.service.RaProfileService;
import com.otilm.core.service.SecretInternalService;
import com.otilm.core.service.StatisticsExternalService;
import com.otilm.core.service.VaultInstanceInternalService;
import com.otilm.core.service.VaultProfileInternalService;
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
    private GroupInternalService groupService;
    private RaProfileService raProfileService;
    private SecretInternalService secretService;
    private VaultInstanceInternalService vaultInstanceService;
    private VaultProfileInternalService vaultProfileService;


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
    public void setGroupService(GroupInternalService groupService) {
        this.groupService = groupService;
    }

    @Autowired
    public void setRaProfileService(RaProfileService raProfileService) {
        this.raProfileService = raProfileService;
    }

    @Autowired
    public void setSecretService(SecretInternalService secretService) {
        this.secretService = secretService;
    }

    @Autowired
    public void setVaultInstanceService(VaultInstanceInternalService vaultInstanceService) {
        this.vaultInstanceService = vaultInstanceService;
    }

    @Autowired
    public void setVaultProfileService(VaultProfileInternalService vaultProfileService) {
        this.vaultProfileService = vaultProfileService;
    }
}

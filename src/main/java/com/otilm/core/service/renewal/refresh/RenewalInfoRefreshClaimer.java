package com.otilm.core.service.renewal.refresh;

import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.repository.CertificateRenewalInfoRepository.RefreshClaim;
import com.otilm.core.messaging.jms.configuration.RenewalInfoProperties;
import com.otilm.core.service.SettingInternalService;
import com.otilm.core.service.writer.RenewalRefreshWriter;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Claims the certificates whose renewal information is due for a refresh. Every node runs the claim; the cluster lock
 * lets one node at a time claim, and the claim holds the lock only for its database statements. A claimed certificate
 * is not due again until the lease ends, so the certificates of a claim nobody completes are claimed again then.
 */
@Component
public class RenewalInfoRefreshClaimer {

    private static final Logger logger = LoggerFactory.getLogger(RenewalInfoRefreshClaimer.class);

    private final ClusterOperationSynchronizer clusterSynchronizer;
    private final RenewalRefreshWriter refreshWriter;
    private final SettingInternalService settingService;
    private final RenewalInfoProperties properties;

    public RenewalInfoRefreshClaimer(ClusterOperationSynchronizer clusterSynchronizer,
            RenewalRefreshWriter refreshWriter, SettingInternalService settingService,
            RenewalInfoProperties properties) {
        this.clusterSynchronizer = clusterSynchronizer;
        this.refreshWriter = refreshWriter;
        this.settingService = settingService;
        this.properties = properties;
    }

    /**
     * Ends the refresh of due certificates that are no longer eligible, enrols a capped number of eligible certificates
     * without refresh state, and claims the due ones. Answers nothing when another node holds the lock.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public List<AuthorityRefresh> claim(Instant now) {
        if (!clusterSynchronizer.tryLock(ClusterOperationSynchronizer.Operation.RENEWAL_INFO_REFRESH_SWEEP)) {
            logger.debug("Renewal information refresh skipped: another instance holds the lock");
            return List.of();
        }
        RenewalInfoSettings settings = RenewalInfoSettings.current(settingService);
        int stopped = refreshWriter.stopIneligibleDue(now);
        int enrolled = refreshWriter.enrolEligible(now, settings.defaultIntervalSeconds(), properties.enrolPerSweep());
        List<RefreshClaim> claimed = refreshWriter
                .claimDue(now, properties.maxPerAuthority(), now.plus(properties.lease()));
        List<AuthorityRefresh> refreshes = group(claimed, settings.batchSize());
        if (!claimed.isEmpty() || enrolled > 0 || stopped > 0) {
            logger
                    .info("Renewal information refresh claimed {} certificates in {} batches for {} authorities; "
                            + "enrolled {}, stopped {}", claimed.size(),
                            refreshes.stream().mapToInt(refresh -> refresh.batches().size()).sum(), refreshes.size(),
                            enrolled, stopped);
        }
        return refreshes;
    }

    /** Groups the claimed certificates by authority, then by RA profile into batches of at most {@code batchSize}. */
    static List<AuthorityRefresh> group(List<RefreshClaim> claimed, int batchSize) {
        Map<UUID, Map<UUID, List<UUID>>> byAuthority = new LinkedHashMap<>();
        for (RefreshClaim claim : claimed) {
            byAuthority
                    .computeIfAbsent(claim.getAuthorityUuid(), authority -> new LinkedHashMap<>())
                    .computeIfAbsent(claim.getRaProfileUuid(), raProfile -> new ArrayList<>())
                    .add(claim.getCertificateUuid());
        }
        List<AuthorityRefresh> refreshes = new ArrayList<>(byAuthority.size());
        byAuthority.forEach((authorityUuid, byRaProfile) -> {
            List<RefreshBatch> batches = new ArrayList<>();
            byRaProfile.forEach((raProfileUuid, certificateUuids) -> {
                for (int from = 0; from < certificateUuids.size(); from += batchSize) {
                    batches
                            .add(new RefreshBatch(raProfileUuid, List
                                    .copyOf(certificateUuids
                                            .subList(from, Math.min(from + batchSize, certificateUuids.size())))));
                }
            });
            refreshes.add(new AuthorityRefresh(authorityUuid, List.copyOf(batches)));
        });
        return refreshes;
    }
}

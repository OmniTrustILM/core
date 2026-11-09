package com.otilm.core.util.seeders;

import com.otilm.core.dao.entity.DiscoveryWork;
import com.otilm.core.dao.repository.DiscoveryWorkRepository;
import com.otilm.core.messaging.model.DiscoveryWorkMessage;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import com.otilm.core.service.writer.discovery.DiscoveryWorkLease;
import com.otilm.core.service.writer.discovery.DiscoveryWorkTick;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Hands a test a discovery tick it can run a worker with directly, the way the listener would: the run's agenda row is
 * leased to a fresh token, as the sweep's claim does, and the tick is admitted through the real
 * {@link DiscoveryWorkLease}. Unlike a claim, the lease leaves the row's attempt and due time as the test armed them.
 */
@Component
public class DiscoveryWorkTickSeeder {

    private static final Duration LEASE = Duration.ofMinutes(2);

    @Autowired
    private DiscoveryWorkRepository workRepository;

    @Autowired
    private DiscoveryWorkLease lease;

    /**
     * @param attempt the attempt the tick runs as, which a claim would have read from the row
     * @throws IllegalStateException when the run has no agenda row of {@code workType}: a tick for a row that does not
     * exist is never admitted
     */
    public DiscoveryWorkTick admitTick(UUID discoveryUuid, DiscoveryWorkType workType, int attempt) {
        DiscoveryWork row = workRepository
                .findAll()
                .stream()
                .filter(work -> work.getDiscoveryUuid().equals(discoveryUuid) && work.getWorkType() == workType)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "Discovery %s has no %s row to lease a tick on".formatted(discoveryUuid, workType)));
        UUID token = UUID.randomUUID();
        row.setLeaseToken(token);
        row.setLeaseExpiresAt(OffsetDateTime.now(ZoneOffset.UTC).plus(LEASE));
        workRepository.saveAndFlush(row);
        return lease
                .admit(new DiscoveryWorkMessage(discoveryUuid, workType, attempt, token))
                .orElseThrow(() -> new IllegalStateException("The lease did not admit the tick it was handed"));
    }
}

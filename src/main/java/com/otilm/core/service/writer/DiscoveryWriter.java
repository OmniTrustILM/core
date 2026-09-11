package com.otilm.core.service.writer;

import com.otilm.api.model.client.discovery.DiscoveryDetailDto;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.repository.DiscoveryCertificateRepository;
import com.otilm.core.dao.repository.DiscoveryMessageRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.mapper.discovery.DiscoveryDtoMapper;
import com.otilm.core.service.handler.discovery.DiscoveryDetailCounts;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Collection;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Writer bean for discovery bookkeeping and progress reporting.
 *
 * <p>
 * These writes must survive the rollback of the import unit whose outcome they record — otherwise the reason a
 * certificate was lost is destroyed by the failure that lost it. That isolation is the caller's responsibility, not
 * this bean's: methods here use {@code REQUIRED} so they compose, and the orchestrator wraps each call in
 * {@code TransactionHandler.runInNewTransaction(...)} after the import unit has returned. Calling them from inside a
 * doomed transaction discards the write.
 */
@Service
public class DiscoveryWriter {

    private final DiscoveryCertificateRepository discoveryCertificateRepository;
    private final DiscoveryRepository discoveryRepository;
    private final DiscoveryMessageRepository discoveryMessageRepository;
    private final DiscoveryDetailCounts detailCounts;

    public DiscoveryWriter(DiscoveryCertificateRepository discoveryCertificateRepository,
            DiscoveryRepository discoveryRepository, DiscoveryMessageRepository discoveryMessageRepository,
            DiscoveryDetailCounts detailCounts) {
        this.discoveryCertificateRepository = discoveryCertificateRepository;
        this.discoveryRepository = discoveryRepository;
        this.discoveryMessageRepository = discoveryMessageRepository;
        this.detailCounts = detailCounts;
    }

    /**
     * Marks a discovered-certificate row as handled, whether or not the outcome was a clean import.
     *
     * @param processedError the shaped reason shared by every listed row, or {@code null} when they imported cleanly or
     * were ignored
     */
    @Transactional
    public void markProcessed(Collection<UUID> discoveryCertificateUuids, String processedError) {
        discoveryCertificateRepository.markProcessed(discoveryCertificateUuids, processedError);
    }

    /**
     * Records a reason against a row that finished earlier in the run, leaving {@code processed} untouched.
     */
    @Transactional
    public void recordProcessedError(Collection<UUID> discoveryCertificateUuids, String processedError) {
        discoveryCertificateRepository.updateProcessedError(discoveryCertificateUuids, processedError);
    }

    /**
     * Reports progress by discovery identifier rather than through the shared {@code Discovery} instance — see
     * {@code DiscoverySource} for why that entity must not reach a worker.
     */
    @Transactional
    public void updateProgressMessage(UUID discoveryUuid, String message) {
        discoveryRepository.updateMessage(discoveryUuid, message);
    }

    /**
     * Releases every run's hold on the given connector interfaces, so they can cascade away with their connector rather
     * than being refused by the runs' {@code ON DELETE RESTRICT} reference. A run is history and outlives its
     * connector; what it can no longer say afterwards is which interface drove it.
     *
     * @return how many runs were released
     */
    @Transactional
    public int releaseConnectorInterfaces(Collection<UUID> interfaceUuids) {
        if (interfaceUuids.isEmpty()) {
            return 0;
        }
        return discoveryRepository.releaseConnectorInterfaces(interfaceUuids);
    }

    /**
     * Ends a run that was refused before dispatch — terminal FAILED on both statuses, the given user-visible message,
     * the end timestamp — and returns the terminal detail. Empty for an unknown uuid: the refusal path only fires for a
     * loaded run.
     *
     * <p>
     * The detail is mapped in here, inside this write's transaction, so the caller need not re-read a row it has just
     * changed. A caller in a {@code NOT_SUPPORTED} scope must not: that scope shares one first-level cache across every
     * read, so a re-read of a run it had already loaded answers with the stale, pre-refusal entity.
     * </p>
     */
    @Transactional
    public Optional<DiscoveryDetailDto> markDispatchRefused(UUID discoveryUuid, String message) {
        return discoveryRepository.findByUuid(discoveryUuid).map(discovery -> {
            discovery.setStatus(DiscoveryStatus.FAILED);
            discovery.setConnectorStatus(DiscoveryStatus.FAILED);
            discovery.setMessage(message);
            discovery.setEndTime(OffsetDateTime.now(ZoneOffset.UTC));
            return DiscoveryDtoMapper.toDetailDto(discovery, detailCounts.forRun(discovery));
        });
    }

}

package com.otilm.core.service.handler.discovery;

import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.DiscoveryCertificateRepository;
import com.otilm.core.dao.repository.DiscoveryMessageRepository;
import com.otilm.core.mapper.discovery.DiscoveryDtoMapper;
import org.springframework.stereotype.Component;

/**
 * Reads the counts a discovery detail response carries but the run row does not hold. Kept in one place because several
 * callers assemble that response, and a count taken differently in one of them would report a different number for the
 * same run.
 */
@Component
public class DiscoveryDetailCounts {

    private final DiscoveryMessageRepository messageRepository;
    private final DiscoveryCertificateRepository certificateRepository;

    public DiscoveryDetailCounts(DiscoveryMessageRepository messageRepository,
            DiscoveryCertificateRepository certificateRepository) {
        this.messageRepository = messageRepository;
        this.certificateRepository = certificateRepository;
    }

    public DiscoveryDtoMapper.DetailCounts forRun(Discovery run) {
        return new DiscoveryDtoMapper.DetailCounts(messageRepository.countByDiscoveryUuid(run.getUuid()),
                certificateRepository.countByDiscoveryAndNewlyDiscovered(run, true));
    }
}

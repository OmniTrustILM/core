package com.otilm.core.service.handler.discovery;

import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.DiscoveryItemRepository;
import com.otilm.core.dao.repository.DiscoveryMessageRepository;
import com.otilm.core.mapper.discovery.DiscoveryDtoMapper;
import org.springframework.stereotype.Component;

/**
 * Reads the counts a discovery detail response carries but the run row does not hold. Kept in one place because several
 * callers assemble that response, and a count taken differently in one of them would report a different number for the
 * same run.
 *
 * <p>
 * Every item count here spans both staging stores. Certificates keep their own table and everything else lives in
 * {@code discovery_item}, so a count taken from one of them is right for a certificates-only run and wrong for every
 * other kind -- which is the failure mode these queries exist to avoid.
 */
@Component
public class DiscoveryDetailCounts {

    private final DiscoveryMessageRepository messageRepository;
    private final DiscoveryItemRepository itemRepository;

    public DiscoveryDetailCounts(DiscoveryMessageRepository messageRepository, DiscoveryItemRepository itemRepository) {
        this.messageRepository = messageRepository;
        this.itemRepository = itemRepository;
    }

    /**
     * The three item counts are one accounting: only a newly discovered item is imported at all, so imported and failed
     * are both drawn from the newly discovered total, and whatever is left of it is still waiting. Each is counted
     * rather than derived from the others, so a run part-way through importing reports what is true of it at that
     * moment instead of what a subtraction implies.
     */
    public DiscoveryDtoMapper.DetailCounts forRun(Discovery run) {
        return new DiscoveryDtoMapper.DetailCounts(messageRepository.countByDiscoveryUuid(run.getUuid()),
                itemRepository.countItems(run.getUuid(), null, true),
                itemRepository.countNewlyDiscoveredImported(run.getUuid()),
                itemRepository.countNewlyDiscoveredFailed(run.getUuid()));
    }
}

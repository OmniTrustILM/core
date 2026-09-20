package com.otilm.core.service.handler.discovery;

import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.DiscoveryItemRepository;
import com.otilm.core.dao.repository.DiscoveryMessageRepository;
import com.otilm.core.mapper.discovery.DiscoveryDtoMapper;
import org.springframework.stereotype.Component;

/**
 * Reads the counts a discovery detail response carries but the run row does not hold, in one place so every caller
 * assembling that response reports the same number for the same run.
 *
 * <p>
 * Every item count spans both staging stores: certificates keep their own table and everything else lives in
 * {@code discovery_item}, so a count taken from one alone is right only for a certificates-only run.
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
     * Each count is taken rather than derived from the others, so a run part-way through importing reports what is true
     * of it at that moment instead of what a subtraction implies; {@link DiscoveryDtoMapper.DetailCounts} says how the
     * three item counts relate.
     */
    public DiscoveryDtoMapper.DetailCounts forRun(Discovery run) {
        return new DiscoveryDtoMapper.DetailCounts(messageRepository.countByDiscoveryUuid(run.getUuid()),
                itemRepository.countItems(run.getUuid(), null, true),
                itemRepository.countNewlyDiscoveredImported(run.getUuid()),
                itemRepository.countNewlyDiscoveredFailed(run.getUuid()));
    }
}

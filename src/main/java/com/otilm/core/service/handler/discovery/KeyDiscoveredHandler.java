package com.otilm.core.service.handler.discovery;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryItem;
import com.otilm.core.service.writer.discovery.DiscoveredKeyWriter;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Turns staged key items into key records. One record per key, whichever run or connector reported it: the item is
 * stamped with the record it became, so a repeat lands on what already exists instead of growing the inventory.
 *
 * <p>
 * A key that cannot be imported stops at its own row — the reason goes on the item and the rest of the batch carries
 * on, the way a certificate that fails to parse does.
 */
@Service
public class KeyDiscoveredHandler {

    private static final Logger logger = LoggerFactory.getLogger(KeyDiscoveredHandler.class);

    private final DiscoveredKeyWriter keyWriter;
    private final ObjectMapper objectMapper;

    public KeyDiscoveredHandler(DiscoveredKeyWriter keyWriter, ObjectMapper objectMapper) {
        this.keyWriter = keyWriter;
        this.objectMapper = objectMapper;
    }

    /**
     * Imports one batch of staged key items.
     *
     * @return how the batch went, for the caller to report on the run
     */
    public KeyImportOutcome importBatch(Discovery run, List<DiscoveryItem> items) {
        int imported = 0;
        int failed = 0;
        for (DiscoveryItem item : items) {
            if (importOne(run, item)) {
                imported++;
            } else {
                failed++;
            }
        }
        return new KeyImportOutcome(imported, failed);
    }

    private boolean importOne(Discovery run, DiscoveryItem item) {
        try {
            DiscoveredKeyDto key = objectMapper.convertValue(item.getPayload(), DiscoveredKeyDto.class);
            keyWriter.importKey(item, key);
            return true;
        } catch (Exception e) {
            // The reason a person reads is curated here; the connector's own words and the stack stay in the log,
            // where they are evidence rather than something the API hands back.
            logger
                    .warn("Discovery {} could not import key item {}: {}", run.getUuid(), item.getUniqueRef(),
                            e.getMessage(), e);
            keyWriter.markFailed(item.getUuid(), reasonFor(e));
            return false;
        }
    }

    private String reasonFor(Exception e) {
        if (e instanceof UnusableDiscoveredKeyException unusable) {
            return unusable.getMessage();
        }
        return "The key could not be imported.";
    }

    /** What one batch produced. */
    public record KeyImportOutcome(int imported, int failed) {

        public boolean isEmpty() {
            return imported == 0 && failed == 0;
        }
    }
}

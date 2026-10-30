package com.otilm.core.messaging.model;

import com.otilm.core.model.discovery.DiscoveryWorkType;
import java.util.UUID;

/**
 * A request to run one tick of pending discovery v2 work — a status poll, a drain page or a processing batch — for the
 * given run.
 *
 * <p>
 * {@code attempt} echoes the agenda row's counter at publish time, so the worker can enforce the attempt budget without
 * re-reading the row. A duplicate delivery is harmless: every tick is idempotent, and the {@code discovery_work} row —
 * not this message — owns the scheduling state.
 * </p>
 */
public record DiscoveryWorkMessage(UUID discoveryUuid, DiscoveryWorkType workType, int attempt) {
}

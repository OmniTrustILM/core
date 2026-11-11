package com.otilm.core.messaging.model;

import com.otilm.core.model.discovery.DiscoveryWorkType;
import java.util.UUID;

/**
 * A request to run one tick of pending discovery v2 work — a status poll, a drain page or a processing batch — for the
 * given run.
 *
 * <p>
 * {@code attempt} echoes the agenda row's counter at publish time, so the worker can enforce the attempt budget without
 * re-reading the row. {@code leaseToken} is the claim the publisher wrote to the {@code discovery_work} row, checked
 * when the tick is admitted ({@code DiscoveryWorkLease#admit}). It is null only on messages published by a Core version
 * without the lease.
 * </p>
 */
public record DiscoveryWorkMessage(UUID discoveryUuid, DiscoveryWorkType workType, int attempt, UUID leaseToken) {
}

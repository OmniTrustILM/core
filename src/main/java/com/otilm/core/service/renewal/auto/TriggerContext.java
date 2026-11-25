package com.otilm.core.service.renewal.auto;

import java.util.UUID;

/**
 * The trigger whose action renews a certificate, and the owner of its association, under whose identity the action
 * runs; {@code ownerUuid} is null for a trigger without an owner. {@code triggerHistoryUuid} and {@code executionUuid}
 * name the firing and its execution, so a failure found after the action returned can be added to that firing's
 * history; either may be null.
 */
public record TriggerContext(UUID triggerUuid, UUID ownerUuid, UUID triggerHistoryUuid, UUID executionUuid) {
}

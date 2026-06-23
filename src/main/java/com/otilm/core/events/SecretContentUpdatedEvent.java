package com.otilm.core.events;

import java.util.UUID;

/**
 * Published after a Secret's content (and thus its latest-version fingerprint) has changed and committed.
 * Decouples the Secret subsystem from consumers (e.g. TSP) that cache a secret's fingerprint.
 */
public record SecretContentUpdatedEvent(UUID secretUuid) {
}

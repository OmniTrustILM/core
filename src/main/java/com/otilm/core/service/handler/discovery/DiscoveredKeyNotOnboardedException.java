package com.otilm.core.service.handler.discovery;

/**
 * A discovered key Core lists on the run but does not add to the inventory, because it has no public part Core can
 * identify it by. Nothing is wrong with the key or the report; the reason on the item says why it stayed out.
 */
public final class DiscoveredKeyNotOnboardedException extends UnusableDiscoveredKeyException {

    public DiscoveredKeyNotOnboardedException(String message) {
        super(message);
    }
}

package com.czertainly.core.model.signing.timequality;

/**
 * Discriminator for {@link TimeQualityConfigurationModel} variants.
 */
public enum TimeQualitySource {

    /** Configuration explicitly provided by the user. */
    EXPLICIT,

    /** No configuration provided — fall back to the local system clock. */
    LOCAL_CLOCK
}

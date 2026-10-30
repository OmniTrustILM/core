package com.otilm.core.events.data;

import com.otilm.api.model.core.discovery.DiscoveryStatus;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class DiscoveryResult {

    private DiscoveryStatus discoveryStatus;

    private String message;

    /**
     * Whether a user asked for this ending, which a status alone does not say: a run is cancelled for several reasons.
     */
    private boolean endedByUser;

    public DiscoveryResult(DiscoveryStatus discoveryStatus, String message) {
        this(discoveryStatus, message, false);
    }
}

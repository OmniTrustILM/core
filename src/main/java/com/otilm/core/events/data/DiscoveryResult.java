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

}

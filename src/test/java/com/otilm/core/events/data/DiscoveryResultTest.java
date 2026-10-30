package com.otilm.core.events.data;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class DiscoveryResultTest {

    private final ObjectMapper mapper = new ObjectMapper();

    /** DISCOVERY_FINISHED crosses JMS as JSON, and its handler reads the payload back from a map. */
    @Test
    void whoEndedTheRunSurvivesTheEventsJsonHop() throws Exception {
        String json = mapper
                .writeValueAsString(new DiscoveryResult(DiscoveryStatus.CANCELLED, "Discovery cancelled", true));

        DiscoveryResult back = mapper.convertValue(mapper.readValue(json, Object.class), DiscoveryResult.class);

        assertThat(back.isEndedByUser()).isTrue();
        assertThat(back.getDiscoveryStatus()).isEqualTo(DiscoveryStatus.CANCELLED);
    }
}

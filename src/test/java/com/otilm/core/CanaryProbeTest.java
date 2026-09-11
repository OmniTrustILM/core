package com.otilm.core;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CanaryProbeTest {

    @Test
    void fixtureIsConstructed() {
        String certificateSubject = "CN=canary";
        assertThat(certificateSubject).isNotEmpty();
    }
}

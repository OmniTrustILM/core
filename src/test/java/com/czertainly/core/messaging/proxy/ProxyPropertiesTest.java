package com.czertainly.core.messaging.proxy;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;

import static org.assertj.core.api.Assertions.*;

class ProxyPropertiesTest {

    @Test
    void constructor_withExplicitInstanceId_usesIt() {
        ProxyProperties props = new ProxyProperties(
                "exchange", "core", "my-instance",
                Duration.ofSeconds(30), 1000, "1"
        );
        assertThat(props.instanceId()).isEqualTo("my-instance");
    }

    @Test
    void constructor_withNullInstanceId_resolvesToHostname() throws UnknownHostException {
        String expectedHostname = InetAddress.getLocalHost().getHostName();
        if (expectedHostname.contains(".")) {
            // On machines where hostname contains dots (e.g., macOS), expect validation error
            assertThatThrownBy(() -> new ProxyProperties(
                    "exchange", "core", null,
                    Duration.ofSeconds(30), 1000, "1"
            ))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("must not contain dots");
        } else {
            ProxyProperties props = new ProxyProperties(
                    "exchange", "core", null,
                    Duration.ofSeconds(30), 1000, "1"
            );
            assertThat(props.instanceId()).isEqualTo(expectedHostname);
        }
    }

    @Test
    void constructor_withBlankInstanceId_resolvesToHostname() throws UnknownHostException {
        String expectedHostname = InetAddress.getLocalHost().getHostName();
        if (expectedHostname.contains(".")) {
            // On machines where hostname contains dots (e.g., macOS), expect validation error
            assertThatThrownBy(() -> new ProxyProperties(
                    "exchange", "core", "  ",
                    Duration.ofSeconds(30), 1000, "1"
            ))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("must not contain dots");
        } else {
            ProxyProperties props = new ProxyProperties(
                    "exchange", "core", "  ",
                    Duration.ofSeconds(30), 1000, "1"
            );
            assertThat(props.instanceId()).isEqualTo(expectedHostname);
        }
    }

    @Test
    void constructor_withDotsInInstanceId_throwsIllegalArgument() {
        assertThatThrownBy(() -> new ProxyProperties(
                "exchange", "core", "core.local",
                Duration.ofSeconds(30), 1000, "1"
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not contain dots");
    }

    @Test
    void constructor_defaults_areApplied() {
        ProxyProperties props = new ProxyProperties(
                null, null, "test-instance",
                null, null, null
        );
        assertThat(props.instanceId()).isEqualTo("test-instance");
        assertThat(props.exchange()).isEqualTo("czertainly-proxy");
        assertThat(props.responseQueue()).isEqualTo("core");
        assertThat(props.requestTimeout()).isEqualTo(Duration.ofSeconds(30));
        assertThat(props.maxPendingRequests()).isEqualTo(1000);
        assertThat(props.concurrency()).isEqualTo("1");
    }
}

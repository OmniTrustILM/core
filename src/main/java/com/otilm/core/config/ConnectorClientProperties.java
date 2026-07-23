package com.otilm.core.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Tuning for the shared connector WebClient — response/connect timeouts and the connection pool
 * used for all HTTP calls to connectors and authorities. Bound from {@code connector.client.*}.
 */
@ConfigurationProperties(prefix = "connector.client")
public record ConnectorClientProperties(
        Duration connectTimeout,
        Duration responseTimeout,
        int maxConnections,
        Duration pendingAcquireTimeout) {
}

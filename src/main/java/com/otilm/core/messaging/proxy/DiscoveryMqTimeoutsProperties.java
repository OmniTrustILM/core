package com.otilm.core.messaging.proxy;

import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Per-operation timeout budgets for the discovery v2 MQ client, bound from {@code discovery.mq-timeouts.*}.
 *
 * <p>
 * <b>Customization:</b> a deployment whose connectors return large drain batches raises the drain budget here, without
 * touching the proxy-wide request timeout.
 *
 * <p>
 * <b>Validation:</b> a missing key fails at binding, naming the full property path. Positivity is enforced by
 * {@code DiscoveryMqTimeouts} itself at bean construction.
 */
@ConfigurationProperties(prefix = "discovery.mq-timeouts")
@Validated
public record DiscoveryMqTimeoutsProperties(@NotNull Duration status, @NotNull Duration drain,
        @NotNull Duration control) {
}

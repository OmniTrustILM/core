package com.otilm.core.provisioning;

import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Configuration properties for the provisioning API client.
 */
@ConfigurationProperties(prefix = "provisioning.api")
@Validated
public record ProvisioningApiProperties(@NotNull String url, @NotNull String apiKey, @NotNull Duration connectTimeout,
        @NotNull Duration readTimeout, @NotNull String installationFormat) {
}

package com.czertainly.core.provisioning;

import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

/**
 * Configuration properties for the provisioning API client.
 */
@ConfigurationProperties(prefix = "provisioning.api")
@Validated
public record ProvisioningApiProperties(
    @NotNull
    String url,
    @NotNull
    String apiKey,
    @NotNull
    Duration connectTimeout,
    @NotNull
    Duration readTimeout,
    @NotNull
    String installationFormat
) {
}
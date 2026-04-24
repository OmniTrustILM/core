package com.czertainly.core.messaging.jms.configuration;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "messaging.concurrency")
@Validated
public record MessagingConcurrencyProperties(
        @NotBlank @Pattern(regexp = "\\d+(-\\d+)?", message = "must be a number or range (e.g. '5' or '3-10')") String actions,
        @NotBlank @Pattern(regexp = "\\d+(-\\d+)?", message = "must be a number or range (e.g. '5' or '3-10')") String auditLogs,
        @NotBlank @Pattern(regexp = "\\d+(-\\d+)?", message = "must be a number or range (e.g. '5' or '3-10')") String events,
        @NotBlank @Pattern(regexp = "\\d+(-\\d+)?", message = "must be a number or range (e.g. '5' or '3-10')") String notifications,
        @NotBlank @Pattern(regexp = "\\d+(-\\d+)?", message = "must be a number or range (e.g. '5' or '3-10')") String scheduler,
        @NotBlank @Pattern(regexp = "\\d+(-\\d+)?", message = "must be a number or range (e.g. '5' or '3-10')") String validation
) {

}


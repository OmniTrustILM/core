package com.czertainly.core.provisioning;

import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestClientException;
import org.springframework.web.service.annotation.DeleteExchange;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;
import org.springframework.web.service.annotation.PostExchange;

/**
 * Client for the Proxy Provisioning API.
 * Authentication is done via X-API-Key header configured in the HTTP client.
 */
@HttpExchange("/api/v1/proxies")
public interface ProxyProvisioningApiClient {

    @PostExchange
    @Retryable(
            retryFor = RestClientException.class,
            maxAttemptsExpression = "${provisioning.api.retry.max-attempts}",
            backoff = @Backoff(
                    delayExpression = "${provisioning.api.retry.delay}",
                    maxDelayExpression = "${provisioning.api.retry.max-delay}",
                    multiplierExpression = "${provisioning.api.retry.multiplier}"
            )
    )
    void provisionProxy(@RequestBody ProxyProvisioningRequestDTO request);

    @GetExchange("/{proxyCode}/installation")
    @Retryable(
            retryFor = RestClientException.class,
            maxAttemptsExpression = "${provisioning.api.retry.max-attempts}",
            backoff = @Backoff(
                    delayExpression = "${provisioning.api.retry.delay}",
                    maxDelayExpression = "${provisioning.api.retry.max-delay}",
                    multiplierExpression = "${provisioning.api.retry.multiplier}"
            )
    )
    InstallationInstructionsDTO getInstallationInstructions(
            @PathVariable String proxyCode,
            @RequestParam String format
    );

    @DeleteExchange("/{proxyCode}")
    @Retryable(
            retryFor = RestClientException.class,
            maxAttemptsExpression = "${provisioning.api.retry.max-attempts}",
            backoff = @Backoff(
                    delayExpression = "${provisioning.api.retry.delay}",
                    maxDelayExpression = "${provisioning.api.retry.max-delay}",
                    multiplierExpression = "${provisioning.api.retry.multiplier}"
            )
    )
    void decommissionProxy(@PathVariable String proxyCode);
}

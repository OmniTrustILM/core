package com.czertainly.core.provisioning;

import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.service.annotation.DeleteExchange;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;
import org.springframework.web.service.annotation.PostExchange;

import java.util.List;

/**
 * Client for the Trusted Certificate Provisioning API.
 * Authentication is done via X-API-Key header configured in the HTTP client.
 */
@HttpExchange("/api/v1/trusted-certificates")
public interface TrustedCertificateProvisioningApiClient {

    @GetExchange
    @Retryable(
        retryFor = RestClientException.class,
        maxAttemptsExpression = "${provisioning.api.retry.max-attempts}",
        backoff = @Backoff(
            delayExpression = "${provisioning.api.retry.delay}",
            maxDelayExpression = "${provisioning.api.retry.max-delay}",
            multiplierExpression = "${provisioning.api.retry.multiplier}"
        )
    )
    List<TrustedCertificateProvisioningDTO> listTrustedCertificates();

    @GetExchange("/{uuid}")
    @Retryable(
        retryFor = RestClientException.class,
        noRetryFor = HttpClientErrorException.NotFound.class,
        maxAttemptsExpression = "${provisioning.api.retry.max-attempts}",
        backoff = @Backoff(
            delayExpression = "${provisioning.api.retry.delay}",
            maxDelayExpression = "${provisioning.api.retry.max-delay}",
            multiplierExpression = "${provisioning.api.retry.multiplier}"
        )
    )
    TrustedCertificateProvisioningDTO getTrustedCertificate(@PathVariable String uuid);

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
    TrustedCertificateProvisioningDTO createTrustedCertificate(@RequestBody TrustedCertificateProvisioningRequestDTO request);

    @DeleteExchange("/{uuid}")
    @Retryable(
        retryFor = RestClientException.class,
        noRetryFor = HttpClientErrorException.NotFound.class,
        maxAttemptsExpression = "${provisioning.api.retry.max-attempts}",
        backoff = @Backoff(
            delayExpression = "${provisioning.api.retry.delay}",
            maxDelayExpression = "${provisioning.api.retry.max-delay}",
            multiplierExpression = "${provisioning.api.retry.multiplier}"
        )
    )
    void deleteTrustedCertificate(@PathVariable String uuid);

}
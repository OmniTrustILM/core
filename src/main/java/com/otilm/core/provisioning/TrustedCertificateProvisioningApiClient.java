package com.otilm.core.provisioning;

import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.service.annotation.DeleteExchange;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;
import org.springframework.web.service.annotation.PostExchange;

/**
 * Client for the Trusted Certificate Provisioning API. Authentication is done via X-API-Key header configured in the
 * HTTP client.
 */
@HttpExchange("/api/v1/trusted-certificates")
public interface TrustedCertificateProvisioningApiClient {

    @GetExchange
    @Retryable(retryFor = RestClientException.class, maxAttemptsExpression = "${provisioning.api.retry.max-attempts}",
            backoff = @Backoff(delayExpression = "${provisioning.api.retry.delay}",
                    maxDelayExpression = "${provisioning.api.retry.max-delay}",
                    multiplierExpression = "${provisioning.api.retry.multiplier}"))
    List<TrustedCertificateProvisioningDTO> listTrustedCertificates();

    @GetExchange("/{uuid}")
    @Retryable(retryFor = RestClientException.class, noRetryFor = HttpClientErrorException.NotFound.class,
            maxAttemptsExpression = "${provisioning.api.retry.max-attempts}",
            backoff = @Backoff(delayExpression = "${provisioning.api.retry.delay}",
                    maxDelayExpression = "${provisioning.api.retry.max-delay}",
                    multiplierExpression = "${provisioning.api.retry.multiplier}"))
    TrustedCertificateProvisioningDTO getTrustedCertificate(@PathVariable String uuid);

    /**
     * Stores a certificate for the tenant. With {@code deferApply} provisioning does not deploy it on its own; a later
     * {@link #apply()} carries every deferred change in one deployment.
     */
    @PostExchange
    @Retryable(retryFor = RestClientException.class,
            noRetryFor = {HttpClientErrorException.Conflict.class, HttpClientErrorException.BadRequest.class},
            maxAttemptsExpression = "${provisioning.api.retry.max-attempts}",
            backoff = @Backoff(delayExpression = "${provisioning.api.retry.delay}",
                    maxDelayExpression = "${provisioning.api.retry.max-delay}",
                    multiplierExpression = "${provisioning.api.retry.multiplier}"))
    TrustedCertificateProvisioningDTO createTrustedCertificate(
            @RequestBody TrustedCertificateProvisioningRequestDTO request,
            @RequestParam("deferApply") boolean deferApply);

    @DeleteExchange("/{uuid}")
    @Retryable(retryFor = RestClientException.class, noRetryFor = HttpClientErrorException.NotFound.class,
            maxAttemptsExpression = "${provisioning.api.retry.max-attempts}",
            backoff = @Backoff(delayExpression = "${provisioning.api.retry.delay}",
                    maxDelayExpression = "${provisioning.api.retry.max-delay}",
                    multiplierExpression = "${provisioning.api.retry.multiplier}"))
    void deleteTrustedCertificate(@PathVariable String uuid, @RequestParam("deferApply") boolean deferApply);

    /**
     * Starts one tenant deployment carrying the deferred changes. An older provisioning without this endpoint answers
     * 404; 204 means there was nothing to deploy.
     * <p>
     * Retried only when the request cannot have reached provisioning: a pooled connection it closed while idle, which
     * answers nothing, or a refused connection. A timeout or an error status is not retried, since provisioning may
     * already have queued the deployment and a retry would queue a second one.
     */
    @PostExchange("/apply")
    @Retryable(retryFor = ResourceAccessException.class,
            exceptionExpression = "cause instanceof T(org.apache.hc.core5.http.NoHttpResponseException)"
                    + " || cause instanceof T(java.net.ConnectException)",
            maxAttemptsExpression = "${provisioning.api.retry.max-attempts}",
            backoff = @Backoff(delayExpression = "${provisioning.api.retry.delay}",
                    maxDelayExpression = "${provisioning.api.retry.max-delay}",
                    multiplierExpression = "${provisioning.api.retry.multiplier}"))
    ResponseEntity<ProvisioningApplyResponseDTO> apply();

    /**
     * Reads the state of the last deployment {@link #apply()} started; an older provisioning answers 404.
     */
    @GetExchange("/apply")
    @Retryable(retryFor = RestClientException.class, noRetryFor = HttpClientErrorException.NotFound.class,
            maxAttemptsExpression = "${provisioning.api.retry.max-attempts}",
            backoff = @Backoff(delayExpression = "${provisioning.api.retry.delay}",
                    maxDelayExpression = "${provisioning.api.retry.max-delay}",
                    multiplierExpression = "${provisioning.api.retry.multiplier}"))
    ProvisioningApplyStatusDTO getApplyStatus();

}

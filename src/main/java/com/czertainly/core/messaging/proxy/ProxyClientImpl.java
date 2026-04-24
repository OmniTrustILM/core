package com.czertainly.core.messaging.proxy;

import com.czertainly.api.clients.mq.ProxyClient;
import com.czertainly.api.clients.mq.model.ConnectorRequest;
import com.czertainly.api.clients.mq.model.ConnectorResponse;
import com.czertainly.api.clients.mq.model.CoreMessage;
import com.czertainly.api.clients.mq.model.ProxyMessage;
import com.czertainly.api.exception.*;
import com.czertainly.api.clients.ApiClientConnectorInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Implementation of ProxyClient that communicates with connectors via message queue proxy.
 *
 * <p>Sends requests to a message queue topic where a proxy service forwards them to
 * the actual connector via HTTP. Responses are received through a response queue
 * and correlated using correlation IDs.</p>
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "proxy.enabled", havingValue = "true")
public class ProxyClientImpl implements ProxyClient {

    private final CoreMessageProducer producer;
    private final ProxyMessageCorrelator correlator;
    private final ConnectorAuthConverter authConverter;
    private final ObjectMapper objectMapper;
    private final ProxyProperties proxyProperties;

    public ProxyClientImpl(
            CoreMessageProducer producer,
            ProxyMessageCorrelator correlator,
            ConnectorAuthConverter authConverter,
            ObjectMapper objectMapper,
            ProxyProperties proxyProperties) {
        this.producer = producer;
        this.correlator = correlator;
        this.authConverter = authConverter;
        this.objectMapper = objectMapper;
        this.proxyProperties = proxyProperties;
        log.info("ProxyClientImpl initialized");
    }

    @Override
    public <T> T sendRequest(
            ApiClientConnectorInfo connector,
            String path,
            String method,
            Object body,
            Class<T> responseType) throws ConnectorException {
        return sendRequest(connector, path, method, body, responseType, proxyProperties.requestTimeout());
    }

    @Override
    public <T> T sendRequest(
            ApiClientConnectorInfo connector,
            String path,
            String method,
            Object body,
            Class<T> responseType,
            Duration timeout) throws ConnectorException {
        return sendRequest(connector, path, method, null, body, responseType, timeout);
    }

    @Override
    public <T> T sendRequest(
            ApiClientConnectorInfo connector,
            String path,
            String method,
            Map<String, String> pathVariables,
            Object body,
            Class<T> responseType) throws ConnectorException {
        return sendRequest(connector, path, method, pathVariables, body, responseType, proxyProperties.requestTimeout());
    }

    private <T> T sendRequest(
            ApiClientConnectorInfo connector,
            String path,
            String method,
            Map<String, String> pathVariables,
            Object body,
            Class<T> responseType,
            Duration timeout) throws ConnectorException {
        try {
            CompletableFuture<T> future = sendRequestAsync(
                    connector, path, method, pathVariables, body, responseType, timeout);

            return future.get(timeout.toMillis() + 5000, TimeUnit.MILLISECONDS);

        } catch (TimeoutException e) {
            throw new ConnectorCommunicationException(
                    "Proxy request timed out after " + timeout, e, connector);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            // CompletableFuture.thenApply wraps thrown exceptions in CompletionException
            if (cause instanceof java.util.concurrent.CompletionException ce && ce.getCause() != null) {
                cause = ce.getCause();
            }
            if (cause instanceof ConnectorException ce) {
                throw ce;
            }
            // Handle ValidationException and other RuntimeExceptions
            if (cause instanceof RuntimeException re) {
                throw re;
            }
            throw new ConnectorCommunicationException(
                    "Proxy request failed: " + cause.getMessage(), cause, connector);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ConnectorCommunicationException(
                    "Proxy request interrupted", e, connector);
        }
    }

    @Override
    public <T> CompletableFuture<T> sendRequestAsync(
            ApiClientConnectorInfo connector,
            String path,
            String method,
            Object body,
            Class<T> responseType) {
        return sendRequestAsync(connector, path, method, null, body, responseType, proxyProperties.requestTimeout());
    }

    @Override
    public <T> CompletableFuture<T> sendRequestAsync(
            ApiClientConnectorInfo connector,
            String path,
            String method,
            Object body,
            Class<T> responseType,
            Duration timeout) {
        return sendRequestAsync(connector, path, method, null, body, responseType, timeout);
    }

    @Override
    public <T> CompletableFuture<T> sendRequestAsync(
            ApiClientConnectorInfo connector,
            String path,
            String method,
            Map<String, String> pathVariables,
            Object body,
            Class<T> responseType,
            Duration timeout) {

        String correlationId = UUID.randomUUID().toString();
        String proxyCode = connector.getProxy() != null ? connector.getProxy().getCode() : null;

        if (proxyCode == null || proxyCode.isBlank()) {
            throw new IllegalArgumentException("Connector proxy code must be set to use ProxyClient");
        }

        // Resolve path variables
        String resolvedPath = resolvePath(path, pathVariables);

        log.debug("Sending async proxy request correlationId={} proxyCode={} method={} path={}",
                correlationId, proxyCode, method, resolvedPath);

        // Build the core message
        CoreMessage message = CoreMessage.builder()
                .correlationId(correlationId)
                .messageType(toMessageType(method, resolvedPath))
                .timestamp(Instant.now())
                .connectorRequest(ConnectorRequest.builder()
                        .connectorUrl(connector.getUrl())
                        .method(method)
                        .path(resolvedPath)
                        .connectorAuth(authConverter.convert(connector))
                        .body(body)
                        .timeout(formatTimeout(timeout))
                        .build())
                .build();

        // Register for response BEFORE sending to avoid race condition
        CompletableFuture<ProxyMessage> messageFuture = correlator.registerRequest(correlationId, timeout);

        // Send the request
        producer.send(message, proxyCode);

        // Transform the response
        return messageFuture.thenApply(proxyMessage -> handleResponse(proxyMessage, responseType, connector));
    }

    /**
     * Handle proxy message and transform to expected type.
     */
    private <T> T handleResponse(ProxyMessage message, Class<T> responseType, ApiClientConnectorInfo connector) {
        ConnectorResponse response = message.getConnectorResponse();

        // Handle health check or missing connector response
        if (response == null) {
            if (message.isHealthCheck()) {
                return null; // Health checks don't have a response body
            }
            sneakyThrow(new ConnectorCommunicationException(
                    "Received proxy message without connector response", connector));
            return null;
        }

        // Check for proxy-level errors
        if (response.hasError()) {
            throwProxyError(response, connector);
        }

        // Check HTTP status
        int statusCode = response.getStatusCode();
        if (statusCode >= 400) {
            throwHttpError(response, connector);
        }

        // Handle void/null responses
        if (responseType == Void.class || responseType == void.class || response.getBody() == null) {
            return null;
        }

        // Deserialize the response body
        try {
            return objectMapper.convertValue(response.getBody(), responseType);
        } catch (Exception e) {
            sneakyThrow(new ConnectorCommunicationException(
                    "Failed to deserialize proxy response body to " + responseType.getSimpleName(),
                    e, connector));
            return null; // Never reached, but needed for compiler
        }
    }

    /**
     * Sneaky throw helper to throw checked exceptions without declaring them.
     * Used to throw ConnectorException from lambda contexts.
     */
    @SuppressWarnings("unchecked")
    private static <E extends Throwable> void sneakyThrow(Throwable e) throws E {
        throw (E) e;
    }

    /**
     * Map proxy error category to appropriate exception and throw it.
     * ValidationException is a RuntimeException so it's thrown directly.
     * ConnectorException subtypes are thrown using sneakyThrow for lambda compatibility.
     */
    private void throwProxyError(ConnectorResponse response, ApiClientConnectorInfo connector) {
        String errorCategory = response.getErrorCategory();
        String errorMessage = response.getError();

        if (errorCategory == null) {
            sneakyThrow(new ConnectorException(errorMessage, connector));
            return;
        }

        switch (errorCategory.toLowerCase()) {
            case "validation" -> throw new ValidationException(errorMessage);

            case "authentication" -> sneakyThrow(new ConnectorClientException(
                    errorMessage, HttpStatus.UNAUTHORIZED));

            case "authorization" -> sneakyThrow(new ConnectorClientException(
                    errorMessage, HttpStatus.FORBIDDEN));

            case "not_found" -> sneakyThrow(new ConnectorEntityNotFoundException(errorMessage));

            case "timeout", "connection" -> sneakyThrow(new ConnectorCommunicationException(
                    errorMessage, connector));

            case "server_error" -> sneakyThrow(new ConnectorServerException(
                    errorMessage,
                    response.getStatusCode() > 0 ? HttpStatus.valueOf(response.getStatusCode()) : HttpStatus.INTERNAL_SERVER_ERROR));

            default -> sneakyThrow(new ConnectorException(errorMessage, connector));
        }
    }

    /**
     * Map HTTP status codes to appropriate exception and throw it.
     * ValidationException is a RuntimeException so it's thrown directly.
     * ConnectorException subtypes are thrown using sneakyThrow for lambda compatibility.
     */
    private void throwHttpError(ConnectorResponse response, ApiClientConnectorInfo connector) {
        int statusCode = response.getStatusCode();
        HttpStatus httpStatus = HttpStatus.resolve(statusCode);

        if (httpStatus == null) {
            httpStatus = HttpStatus.INTERNAL_SERVER_ERROR;
        }

        String errorMessage = response.getError();
        if (errorMessage == null || errorMessage.isBlank()) {
            errorMessage = "HTTP " + statusCode + ": " + httpStatus.getReasonPhrase();
        }

        if (statusCode == 404) {
            sneakyThrow(new ConnectorEntityNotFoundException(errorMessage));
        } else if (statusCode == 422) {
            throw new ValidationException(errorMessage);
        } else if (httpStatus.is4xxClientError()) {
            sneakyThrow(new ConnectorClientException(errorMessage, httpStatus));
        } else if (httpStatus.is5xxServerError()) {
            sneakyThrow(new ConnectorServerException(errorMessage, httpStatus));
        } else {
            sneakyThrow(new ConnectorException(errorMessage, connector));
        }
    }

    /**
     * Resolve path variables in the URL path.
     */
    private String resolvePath(String path, Map<String, String> pathVariables) {
        if (pathVariables == null || pathVariables.isEmpty()) {
            return path;
        }
        String resolved = path;
        for (Map.Entry<String, String> entry : pathVariables.entrySet()) {
            resolved = resolved.replace("{" + entry.getKey() + "}", entry.getValue());
        }
        return resolved;
    }

    /**
     * Format timeout duration to Go duration format (e.g., "30s").
     */
    private String formatTimeout(Duration timeout) {
        long seconds = timeout.toSeconds();
        if (seconds > 0) {
            return seconds + "s";
        }
        return timeout.toMillis() + "ms";
    }

    @Override
    public void sendFireAndForget(ApiClientConnectorInfo connector, String path, String method, Object body) {
        sendFireAndForget(connector, path, method, body, null);
    }

    @Override
    public void sendFireAndForget(
            ApiClientConnectorInfo connector,
            String path,
            String method,
            Object body,
            String messageType) {

        String proxyCode = connector.getProxy() != null ? connector.getProxy().getCode() : null;

        if (proxyCode == null || proxyCode.isBlank()) {
            throw new IllegalArgumentException("Connector proxy code must be set to use ProxyClient");
        }

        // Use provided messageType or derive from method + path
        String resolvedMessageType = (messageType != null && !messageType.isBlank())
                ? messageType
                : toMessageType(method, path);

        log.debug("Sending fire-and-forget proxy request proxyCode={} method={} path={} messageType={}",
                proxyCode, method, path, resolvedMessageType);

        // Build the core message - no correlationId for fire-and-forget
        CoreMessage message = CoreMessage.builder()
                .messageType(resolvedMessageType)
                .timestamp(Instant.now())
                .connectorRequest(ConnectorRequest.builder()
                        .connectorUrl(connector.getUrl())
                        .method(method)
                        .path(path)
                        .connectorAuth(authConverter.convert(connector))
                        .body(body)
                        .build())
                .build();

        // Send without registering for response
        producer.send(message, proxyCode);

        log.debug("Sent fire-and-forget proxy request proxyCode={} messageType={}", proxyCode, resolvedMessageType);
    }

    /**
     * Convert HTTP method and path to dot-separated messageType format.
     * This format follows RabbitMQ topic exchange segment conventions.
     *
     * <p>Examples:</p>
     * <ul>
     *   <li>"GET", "/v1/certificates" → "GET.v1.certificates"</li>
     *   <li>"POST", "/v1/authorities/123/issue" → "POST.v1.authorities.123.issue"</li>
     *   <li>"GET", "" → "GET"</li>
     * </ul>
     *
     * @param method HTTP method (GET, POST, etc.)
     * @param path URL path (with or without leading slash)
     * @return Dot-separated messageType
     */
    private String toMessageType(String method, String path) {
        if (path == null || path.isEmpty()) {
            return method;
        }
        // Remove leading slash
        String normalized = path.startsWith("/") ? path.substring(1) : path;
        if (normalized.isEmpty()) {
            return method;
        }
        // Replace remaining slashes with dots
        return method + "." + normalized.replace("/", ".");
    }
}

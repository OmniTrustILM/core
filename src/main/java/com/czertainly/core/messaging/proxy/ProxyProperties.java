package com.czertainly.core.messaging.proxy;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;

/**
 * Configuration properties for the proxy client.
 * These properties control how the ProxyClient communicates with connectors
 * via the message queue proxy.
 */
@ConfigurationProperties(prefix = "proxy", ignoreInvalidFields = true, ignoreUnknownFields = true)
@Validated
public record ProxyProperties(
        /**
         * Azure Service Bus topic / RabbitMQ exchange name for proxy communication.
         * Default: czertainly-proxy
         */
        String exchange,

        /**
         * Azure Service Bus subscription / RabbitMQ queue name for receiving
         * fire-and-forget messages (health checks, connector registration).
         * Default: core
         */
        String responseQueue,

        /**
         * Unique identifier for this Core instance.
         * Used as the AMQP reply-to address and as the per-instance queue/subscription name.
         * Defaults to the local hostname (pod name in Kubernetes).
         * Must not contain dots (breaks topic routing key segmentation).
         */
        String instanceId,

        /**
         * Default request timeout duration.
         * Default: 30 seconds
         */
        Duration requestTimeout,

        /**
         * Maximum number of pending requests allowed.
         * Prevents memory issues from too many outstanding requests.
         * Default: 1000
         */
        Integer maxPendingRequests,

        /**
         * JMS listener concurrency for proxy response messages.
         * Default: 1
         */
        String concurrency
) {
    public ProxyProperties {
        if (exchange == null) {
            exchange = "czertainly-proxy";
        }
        if (responseQueue == null) {
            responseQueue = "core";
        }
        if (instanceId == null || instanceId.isBlank()) {
            try {
                instanceId = InetAddress.getLocalHost().getHostName();
            } catch (UnknownHostException e) {
                throw new IllegalStateException("Cannot resolve hostname for proxy instance ID. "
                        + "Set PROXY_INSTANCE_ID explicitly.", e);
            }
        } else {
            instanceId = instanceId.strip();
        }
        if (instanceId.contains(".")) {
            throw new IllegalArgumentException(
                    "proxy.instance-id must not contain dots (breaks topic routing): " + instanceId);
        }
        if (requestTimeout == null) {
            requestTimeout = Duration.ofSeconds(30);
        }
        if (maxPendingRequests == null) {
            maxPendingRequests = 1000;
        }
        if (concurrency == null) {
            concurrency = "1";
        }
    }

    /**
     * Get the request routing key/subject for a specific proxy instance.
     * @param proxyId The proxy instance ID
     * @return Routing key in format "coremessage.{proxyId}"
     */
    public String getRequestRoutingKey(String proxyId) {
        if (proxyId == null) {
            throw new IllegalArgumentException("proxyId must not be null");
        }
        return "coremessage." + proxyId;
    }
}

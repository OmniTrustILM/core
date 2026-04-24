package com.czertainly.core.messaging.jms.configuration;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "spring.messaging")
@Validated
public record MessagingProperties(
        @NotNull MessagingProperties.BrokerType brokerType,
        String brokerUrl,
        String host,
        Integer port,
        @NotBlank String exchange,
        String virtualHost,
        String username,      // Required for RabbitMQ and ServiceBus+SAS, optional for ServiceBus+AAD
        String password,  // Required for RabbitMQ and ServiceBus+SAS, optional for ServiceBus+AAD
        Integer amqpIdleTimeout,
        Integer closeTimeout,
        @Valid AadAuth aadAuth,
        Pool pool,
        @Valid Listener listener,
        @Valid Producer producer,
        @Valid Queue queue,
        @NotNull @Valid RoutingKey routingKey
) {

    /**
     * Compact constructor that validates authentication and connection configuration based on broker type.
     */
    public MessagingProperties {
        boolean hasUserAndPassword = StringUtils.isNotBlank(username) && StringUtils.isNotBlank(password);
        boolean hasAadAuth = aadAuth != null && aadAuth.isEnabled();
        boolean hasBrokerUrl = StringUtils.isNotBlank(brokerUrl);
        boolean hasHostAndPort = StringUtils.isNotBlank(host) && port != null;

        switch (brokerType) {
            case RABBITMQ -> {
                if (!hasBrokerUrl && !hasHostAndPort) {
                    throw new IllegalArgumentException(
                            "RabbitMQ requires either BROKER_URL or BROKER_HOST and BROKER_PORT to be configured");
                }
                if (!hasUserAndPassword) {
                    throw new IllegalArgumentException(
                            "RabbitMQ requires BROKER_USERNAME and BROKER_PASSWORD to be configured");
                }
            }
            case SERVICEBUS -> {
                if (!hasBrokerUrl) {
                    throw new IllegalArgumentException(
                            "ServiceBus requires BROKER_URL to be configured");
                }
                if (!hasUserAndPassword && !hasAadAuth) {
                    throw new IllegalArgumentException(
                            "ServiceBus requires either BROKER_USERNAME/BROKER_PASSWORD (SAS) " +
                                    "or BROKER_AZURE_TENANT_ID/BROKER_AZURE_CLIENT_ID/BROKER_AZURE_CLIENT_SECRET (AAD) to be configured");
                }
            }
        }
    }

    /**
     * Returns the effective broker URL for connection.
     * Uses brokerUrl if provided, otherwise constructs from host and port (for RabbitMQ legacy support).
     */
    public String getEffectiveBrokerUrl() {
        if (StringUtils.isNotBlank(brokerUrl)) {
            return brokerUrl;
        }
        // Construct URL from host and port (RabbitMQ legacy support)
        return "amqp://" + host + ":" + port;
    }

    private String producerDestination(String routingKey) {
        if (brokerType == BrokerType.SERVICEBUS) {
            return exchange();
        }
        return "/exchanges/" + exchange() + "/" + routingKey;
    }

    public String consumerDestination(String queueName) {
        if (brokerType == BrokerType.SERVICEBUS) {
            return exchange();
        }
        return "/queues/" + queueName;
    }

    public String produceDestinationActions() {
        return producerDestination(routingKey().actions());
    }

    public String produceDestinationAuditLogs() {
        return producerDestination(routingKey().auditLogs());
    }

    public String produceDestinationEvent() {
        return producerDestination(routingKey().event());
    }

    public String produceDestinationNotifications() {
        return producerDestination(routingKey().notification());
    }

    public String produceDestinationScheduler() {
        return producerDestination(routingKey().scheduler());
    }

    public String produceDestinationValidation() {
        return producerDestination(routingKey().validation());
    }

    public record Queue (
            @NotBlank String actions,
            @NotBlank String auditLogs,
            @NotBlank String event,
            @NotBlank String notification,
            @NotBlank String scheduler,
            @NotBlank String validation
    ) {}

    public record RoutingKey(
            @NotBlank String actions,
            @NotBlank String auditLogs,
            @NotBlank String event,
            @NotBlank String notification,
            @NotBlank String scheduler,
            @NotBlank String validation
    ) {}

    public record Listener(
            Long recoveryInterval,     // Legacy: fixed interval. Ignored when backoff fields are set.
            Long initialInterval,      // Exponential backoff initial interval in ms (default: 5000)
            Double multiplier,         // Backoff multiplier (default: 2.0)
            Long maxInterval,          // Max backoff interval cap in ms (default: 120000 = 2 min)
            Long maxElapsedTime        // Max total recovery time in ms (null = unlimited)
    ) {
        public Listener {
            if (initialInterval == null) initialInterval = 5000L;
            if (multiplier == null) multiplier = 2.0;
            if (maxInterval == null) maxInterval = 120000L;
            // maxElapsedTime null = retry forever at maxInterval
        }
    }

    public record Producer(
            @NotNull @Valid Retry retry
    ) {}

    public record Retry(
            @NotNull Boolean enabled,
            @NotNull @Positive Long initialInterval,
            @NotNull @Positive Integer maxAttempts,
            @NotNull @Positive Long maxInterval,
            @NotNull @Positive Long multiplier
    ) {
        public Retry {
            if (enabled == null) enabled = true;
            if (initialInterval == null) initialInterval = 3000L;
            if (maxAttempts == null) maxAttempts = 3;
            if (maxInterval == null) maxInterval = 10000L;
            if (multiplier == null) multiplier = 2L;
        }
    }

    /**
     * AAD (Azure Active Directory) authentication configuration for ServiceBus.
     * When enabled is true, the connection will use OAuth2 token authentication
     * instead of SAS token (user/password).
     */
    public record AadAuth(
            String tenantId,
            String clientId,
            String clientSecret,
            int tokenRefreshInterval,
            int tokenGettingTimeout
    ) {
        public boolean isEnabled() {
            return StringUtils.isNotBlank(tenantId) && StringUtils.isNotBlank(clientId) && StringUtils.isNotBlank(clientSecret);
        }
    }

    /**
     * Connection pool configuration for JmsPoolConnectionFactory.
     * Used for both ServiceBus and RabbitMQ producer connection factories.
     */
    public record Pool(
            Integer maxConnections,
            Integer connectionIdleTimeout,
            Integer connectionCheckInterval,
            Integer maxSessionsPerConnection,
            Boolean useAnonymousProducers
    ) {
        public Pool {
            if (maxConnections == null || maxConnections <= 0) maxConnections = 1;
            if (connectionIdleTimeout == null) connectionIdleTimeout = 30000;
            if (connectionCheckInterval == null) connectionCheckInterval = 60000;
            if (maxSessionsPerConnection == null || maxSessionsPerConnection <= 0) maxSessionsPerConnection = 500;
            if (useAnonymousProducers == null) useAnonymousProducers = true;
        }
    }

    public enum BrokerType {
        RABBITMQ,
        SERVICEBUS
    }
}

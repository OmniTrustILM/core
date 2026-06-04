package com.czertainly.core.messaging.jms.configuration;

import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.core.credential.TokenCredential;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.jms.ConnectionFactory;
import org.apache.qpid.jms.JmsConnectionExtensions;
import org.apache.qpid.jms.JmsConnectionFactory;
import org.slf4j.Logger;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.jms.annotation.EnableJms;
import org.springframework.jms.config.DefaultJmsListenerContainerFactory;
import org.messaginghub.pooled.jms.JmsPoolConnectionFactory;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.jms.support.converter.MappingJackson2MessageConverter;
import org.springframework.jms.support.converter.MessageConverter;
import org.springframework.jms.support.converter.MessageType;
import org.springframework.util.backoff.BackOff;
import org.springframework.util.backoff.ExponentialBackOff;
import org.springframework.util.backoff.FixedBackOff;
import org.springframework.web.util.UriComponentsBuilder;

import static org.slf4j.LoggerFactory.getLogger;

@EnableJms
@Configuration
@EnableConfigurationProperties({MessagingProperties.class, MessagingConcurrencyProperties.class})
public class JmsConfig {
    private static final Logger logger = getLogger(JmsConfig.class);

    @Bean
    public ConnectionFactory connectionFactory(MessagingProperties props) {
        if (props.brokerType() == MessagingProperties.BrokerType.SERVICEBUS) {
            return createServiceBusConnectionFactory(props);
        }
        return createRabbitMqConnectionFactory(props);
    }

    private ConnectionFactory createServiceBusConnectionFactory(MessagingProperties props) {
        // Use the broker URL as-is for ServiceBus — it may contain a failover:(...) scheme
        // that UriComponentsBuilder cannot parse.
        String brokerUrl = props.getEffectiveBrokerUrl();
        logger.info("Connecting to ServiceBus broker: {}", brokerUrl);

        JmsConnectionFactory factory = new JmsConnectionFactory(brokerUrl);
        factory.setForceSyncSend(true);

        if (props.closeTimeout() != null) {
            factory.setCloseTimeout(props.closeTimeout());
        }

        configureServiceBusAuthentication(factory, props);
        // Return raw factory for ServiceBus - listener containers manage their own connections.
        // CachingConnectionFactory interferes with DefaultMessageListenerContainer recovery
        // for durable/shared subscriptions. Producers use JmsPoolConnectionFactory (see below).
        return factory;
    }

    private ConnectionFactory createRabbitMqConnectionFactory(MessagingProperties props) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(props.getEffectiveBrokerUrl());

        // For RabbitMQ with AMQP 1.0, vhost is specified in the AMQP Open frame hostname field
        // The hostname field must be "vhost:name" format according to RabbitMQ AMQP 1.0 docs
        // We use amqp.vhost connection property to set this value
        if (props.virtualHost() != null && !props.virtualHost().isEmpty()) {
            builder.queryParam("amqp.vhost", "vhost:" + props.virtualHost());
        }

        // AMQP idle timeout: tells the remote peer how often to send heartbeat (empty) frames
        // to keep the connection alive at the transport level (default: 2 minutes).
        // See: http://docs.oasis-open.org/amqp/core/v1.0/os/amqp-core-transport-v1.0-os.html#doc-doc-idle-time-out
        int amqpIdleTimeout = props.amqpIdleTimeout() != null ? props.amqpIdleTimeout() : 120000;
        if (amqpIdleTimeout > 0) {
            builder.queryParam("amqp.idleTimeout", amqpIdleTimeout);
        }

        String brokerUrl = builder.build().toUriString();

        JmsConnectionFactory factory = new JmsConnectionFactory(brokerUrl);
        factory.setForceSyncSend(true);

        if (props.closeTimeout() != null) {
            factory.setCloseTimeout(props.closeTimeout());
        }

        // RabbitMQ - standard username/password authentication
        logger.info("Connecting to RabbitMQ broker: {} with vhost: {}", props.getEffectiveBrokerUrl(), props.virtualHost());
        factory.setUsername(props.username());
        factory.setPassword(props.password());

        return factory;
    }

    private void configureServiceBusAuthentication(JmsConnectionFactory factory, MessagingProperties props) {
        if (props.aadAuth() != null && props.aadAuth().isEnabled()) {
            // AAD (Entra ID) OAuth2 authentication
            logger.info("Connecting to ServiceBus: {} using AAD authentication", props.getEffectiveBrokerUrl());

            TokenCredential credential = new ClientSecretCredentialBuilder()
                    .tenantId(props.aadAuth().tenantId())
                    .clientId(props.aadAuth().clientId())
                    .clientSecret(props.aadAuth().clientSecret())
                    .build();

            AadTokenProvider tokenProvider = new AadTokenProvider(credential, props.aadAuth().tokenRefreshInterval(), props.aadAuth().tokenGettingTimeout());

            // ServiceBus requires "$jwt" username for OAuth2 token authentication
            factory.setUsername("$jwt");
            factory.setExtension(
                    JmsConnectionExtensions.PASSWORD_OVERRIDE.toString(),
                    tokenProvider
            );
        } else {
            // SAS (Shared Access Signature) token authentication
            logger.info("Connecting to Azure ServiceBus: {} using SAS authentication", props.getEffectiveBrokerUrl());
            factory.setUsername(props.username());
            factory.setPassword(props.password());
        }
    }

    @Bean
    public DefaultJmsListenerContainerFactory jmsListenerContainerFactory(
            ConnectionFactory connectionFactory,
            MessageConverter messageConverter,
            MessagingProperties messagingProperties) {
        DefaultJmsListenerContainerFactory factory = new DefaultJmsListenerContainerFactory();
        factory.setConnectionFactory(connectionFactory);
        factory.setMessageConverter(messageConverter);
        if (messagingProperties.brokerType() == MessagingProperties.BrokerType.SERVICEBUS) {
            factory.setPubSubDomain(true);
            factory.setSubscriptionDurable(true);
        }
        factory.setBackOff(createListenerBackOff(messagingProperties));
        return factory;
    }

    private BackOff createListenerBackOff(MessagingProperties props) {
        MessagingProperties.Listener listener = props.listener();

        // Legacy: if only recoveryInterval is explicitly set, preserve fixed-interval behavior
        if (listener != null && listener.recoveryInterval() != null) {
            logger.info("JMS listener recovery using fixed backoff: interval={}ms", listener.recoveryInterval());
            return new FixedBackOff(listener.recoveryInterval(), FixedBackOff.UNLIMITED_ATTEMPTS);
        }

        // Exponential backoff (default or explicitly configured)
        long initialInterval = listener != null ? listener.initialInterval() : 5000L;
        double multiplier = listener != null ? listener.multiplier() : 2.0;
        long maxInterval = listener != null ? listener.maxInterval() : 120000L;

        ExponentialBackOff backOff = new ExponentialBackOff(initialInterval, multiplier);
        backOff.setMaxInterval(maxInterval);

        if (listener != null && listener.maxElapsedTime() != null) {
            backOff.setMaxElapsedTime(listener.maxElapsedTime());
        }

        logger.info("JMS listener recovery using exponential backoff: initialInterval={}ms, multiplier={}, maxInterval={}ms, maxElapsedTime={}",
                initialInterval, multiplier, maxInterval,
                listener != null && listener.maxElapsedTime() != null ? listener.maxElapsedTime() + "ms" : "unlimited");
        return backOff;
    }

    @Bean
    public MessageConverter messageConverter(Jackson2ObjectMapperBuilder objectMapperBuilder) {
        ObjectMapper objectMapper = objectMapperBuilder.createXmlMapper(false)
            .featuresToDisable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .build()
            .findAndRegisterModules();

        MappingJackson2MessageConverter converter = new MappingJackson2MessageConverter();
        converter.setObjectMapper(objectMapper);
        converter.setTargetType(MessageType.TEXT);

        return converter;
    }

    @Bean(destroyMethod = "stop")
    public JmsPoolConnectionFactory producerConnectionFactory(ConnectionFactory connectionFactory,
                                                               MessagingProperties messagingProperties) {
        // JmsPoolConnectionFactory manages connection/session lifecycle independently of
        // Spring's shared-connection mechanism. On connection failure (e.g. amqp:connection:forced),
        // the pool auto-evicts the dead connection and provides a fresh one on the next borrow —
        // no manual resetConnection() needed.
        //
        // connectionIdleTimeout=30s evicts idle connections before the broker's idle thresholds.
        // useAnonymousProducers=true keeps a persistent AMQP link on the connection, preventing
        // the broker's "no active links" forced close.
        // connectionCheckInterval=60s enables a background thread to actively evict stale connections.
        MessagingProperties.Pool poolConfig = messagingProperties.pool();
        if (poolConfig == null) {
            poolConfig = new MessagingProperties.Pool(null, null, null, null, null);
        }

        JmsPoolConnectionFactory pool = new CzertainlyJmsPoolConnectionFactory();
        pool.setConnectionFactory(connectionFactory);
        pool.setMaxConnections(poolConfig.maxConnections());
        pool.setConnectionIdleTimeout(poolConfig.connectionIdleTimeout());
        pool.setConnectionCheckInterval(poolConfig.connectionCheckInterval());
        pool.setMaxSessionsPerConnection(poolConfig.maxSessionsPerConnection());
        pool.setUseAnonymousProducers(poolConfig.useAnonymousProducers());
        pool.start();
        logger.info("Started JMS producer connection pool: maxConnections={}, connectionIdleTimeout={}ms, connectionCheckInterval={}ms, maxSessionsPerConnection={}, useAnonymousProducers={}",
                poolConfig.maxConnections(), poolConfig.connectionIdleTimeout(),
                poolConfig.connectionCheckInterval(), poolConfig.maxSessionsPerConnection(),
                poolConfig.useAnonymousProducers());
        return pool;
    }

    @Bean
    public JmsTemplate jmsTemplate(JmsPoolConnectionFactory producerConnectionFactory,
                                   MessageConverter messageConverter,
                                   MessagingProperties messagingProperties) {
        JmsTemplate template = new JmsTemplate(producerConnectionFactory);
        template.setMessageConverter(messageConverter);
        if (messagingProperties.brokerType() == MessagingProperties.BrokerType.SERVICEBUS) {
            template.setPubSubDomain(true);
        }
        return template;
    }
}

package com.czertainly.core.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.RabbitMQContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Base class for integration tests that require a real RabbitMQ broker via Testcontainers.
 *
 * <p>{@code @DirtiesContext(BEFORE_CLASS)} is intentional and must stay here. The static
 * {@link RabbitMQContainer} is started/stopped per concrete subclass by the Testcontainers
 * JUnit 5 extension, so each subclass gets a new container at a new random host port.
 * Spring's context cache key does NOT include {@link DynamicPropertySource} values.</p>
 */
@SpringBootTest
@ActiveProfiles(value = {"messaging-int-test"})
@Testcontainers
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
public abstract class BaseMessagingIntTest extends BaseSpringBootTest {

    protected static final Logger logger = LoggerFactory.getLogger(BaseMessagingIntTest.class);

    @Container
    protected static final RabbitMQContainer rabbitMQContainer = RabbitMQContainerFactory.create();

    @DynamicPropertySource
    static void rabbitMQProperties(DynamicPropertyRegistry registry) throws IOException, InterruptedException {
        // Import RabbitMQ definitions after the container starts
        logger.info("Importing RabbitMQ definitions...");
        RabbitMQContainerFactory.importDefinitions(rabbitMQContainer);

        registry.add("spring.messaging.broker-url",
                () -> String.format("amqp://%s:%d", rabbitMQContainer.getHost(), rabbitMQContainer.getAmqpPort()));
        registry.add("spring.messaging.broker-type", () -> "RABBITMQ");
        registry.add("spring.messaging.username", rabbitMQContainer::getAdminUsername);
        registry.add("spring.messaging.password", rabbitMQContainer::getAdminPassword);
    }

    @Override
    @BeforeEach
    public void setupAuth() {
        // Skip truncateTables() for messaging tests - they use different database schema
        mockSuccessfulCheckResourceAccess();
        mockSuccessfulCheckObjectAccess();
        injectAuthentication();
    }

    @Test
    void containerShouldBeRunning() {
        assertThat(rabbitMQContainer.isRunning()).isTrue();
        assertThat(rabbitMQContainer.getAmqpPort()).isGreaterThan(0);
    }
}

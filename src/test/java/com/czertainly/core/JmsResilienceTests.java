package com.czertainly.core;

import com.czertainly.core.messaging.jms.listeners.EventListener;
import com.czertainly.core.messaging.jms.producers.EventProducer;
import com.czertainly.core.service.impl.AuditLogServiceImpl;
import com.czertainly.core.util.BaseSpringBootTest;
import com.czertainly.core.util.RabbitMQContainerFactory;
import eu.rekawek.toxiproxy.Proxy;
import eu.rekawek.toxiproxy.ToxiproxyClient;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.RabbitMQContainer;
import org.testcontainers.containers.ToxiproxyContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;

@Tag("chaos")
@SpringBootTest
@ActiveProfiles({"messaging-int-test"})
@Testcontainers
public abstract class JmsResilienceTests extends BaseSpringBootTest {
    protected static final Logger logger = LoggerFactory.getLogger(JmsResilienceTests.class);

    protected static final Network network = Network.newNetwork();

    @Container
    protected static final RabbitMQContainer rabbitMQContainer = RabbitMQContainerFactory.create(network);

    @Container
    protected static final ToxiproxyContainer toxiproxy = new ToxiproxyContainer("ghcr.io/shopify/toxiproxy:2.5.0")
            .withNetwork(network)
            .dependsOn(rabbitMQContainer);

    protected static Proxy proxy;

    @Autowired
    protected EventProducer eventProducer;

    @MockitoSpyBean
    protected EventListener eventListener;
    @MockitoSpyBean
    protected AuditLogServiceImpl auditLogService;

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) throws IOException, InterruptedException {
        // Import RabbitMQ definitions after the container starts
        logger.info("Importing RabbitMQ definitions...");
        RabbitMQContainerFactory.importDefinitions(rabbitMQContainer);

        ToxiproxyClient client = new ToxiproxyClient(toxiproxy.getHost(), toxiproxy.getControlPort());
        proxy = client.createProxy("amqp-proxy", "0.0.0.0:8666", "broker:5672");

        String proxyUrl = String.format("amqp://%s:%d", toxiproxy.getHost(), toxiproxy.getMappedPort(8666));
        registry.add("spring.messaging.broker-url", () -> proxyUrl);
        registry.add("spring.messaging.broker-type", () -> "RABBITMQ");
        registry.add("spring.messaging.username", rabbitMQContainer::getAdminUsername);
        registry.add("spring.messaging.password", rabbitMQContainer::getAdminPassword);
    }

    @BeforeEach
    void resetProxyToxics() throws IOException {
        if (proxy != null) {
            proxy.toxics().getAll().forEach(toxic -> {
                try {
                    toxic.remove();
                    logger.info("=== Toxic removed: {} ===", toxic.getName());
                } catch (IOException e) {
                    logger.warn("Failed to remove toxic: {}", toxic.getName(), e);
                }
            });
        }
    }

    @AfterAll
    static void cleanupResources() {
        // First stop containers explicitly to ensure they release the network
        try {
            if (toxiproxy != null && toxiproxy.isRunning()) {
                toxiproxy.stop();
                logger.info("Toxiproxy container stopped");
            }
        } catch (Exception e) {
            logger.warn("Failed to stop toxiproxy: {}", e.getMessage());
        }

        try {
            if (rabbitMQContainer != null && rabbitMQContainer.isRunning()) {
                rabbitMQContainer.stop();
                logger.info("RabbitMQ container stopped");
            }
        } catch (Exception e) {
            logger.warn("Failed to stop rabbitMQContainer: {}", e.getMessage());
        }

        // Then close the network after all containers are stopped
        try {
            if (network != null) {
                network.close();
                logger.info("Network closed");
            }
        } catch (Exception e) {
            logger.warn("Failed to close network: {}", e.getMessage());
        }
    }
}
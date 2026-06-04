package com.czertainly.core.util;

import org.testcontainers.containers.Network;
import org.testcontainers.containers.RabbitMQContainer;
import org.testcontainers.utility.MountableFile;

import java.io.IOException;

/**
 * Factory for creating RabbitMQContainer instances with unified configuration.
 * Supports both standalone and networked containers for different test scenarios.
 */
public class RabbitMQContainerFactory {

    private static final String RABBITMQ_IMAGE = "rabbitmq:4.2-management";
    private static final String DEFINITIONS_FILE = "rabbitMQ-definitions.json";
    private static final String CONTAINER_DEFINITIONS_PATH = "/etc/rabbitmq/definitions.json";
    private static final String NETWORK_ALIAS = "broker";

    private RabbitMQContainerFactory() {
        throw new UnsupportedOperationException("Utility class");
    }

    /**
     * Creates a RabbitMQContainer with standard configuration and optional network.
     * The container is configured to load queue/exchange definitions from rabbitMQ-definitions.json.
     *
     * @param network Optional Docker network for container communication (e.g., with Toxiproxy).
     *                If null, the container runs standalone.
     * @return Configured but not started RabbitMQContainer
     */
    public static RabbitMQContainer create(Network network) {
        RabbitMQContainer container = new RabbitMQContainer(RABBITMQ_IMAGE)
                .withCopyFileToContainer(MountableFile.forClasspathResource(DEFINITIONS_FILE), CONTAINER_DEFINITIONS_PATH);

        if (network != null) {
            container.withNetwork(network)
                    .withNetworkAliases(NETWORK_ALIAS);
        }

        return container;
    }

    /**
     * Creates a standalone RabbitMQContainer without a network.
     * Useful for simple integration tests that don't need inter-container communication.
     *
     * @return Configured but not started RabbitMQContainer
     */
    public static RabbitMQContainer create() {
        return create(null);
    }

    /**
     * Imports RabbitMQ definitions into a running container.
     * This must be called after the container has started.
     *
     * @param container Running a RabbitMQContainer instance
     * @throws IOException If the import command fails
     * @throws InterruptedException If the command execution is interrupted
     */
    public static void importDefinitions(RabbitMQContainer container) throws IOException, InterruptedException {
        if (!container.isRunning()) {
            throw new IllegalStateException("Container must be running before importing definitions");
        }

        var result = container.execInContainer("rabbitmqctl", "import_definitions", CONTAINER_DEFINITIONS_PATH);
        if (result.getExitCode() != 0) {
            throw new IOException("Failed to import definitions: " + result.getStderr());
        }
    }

}
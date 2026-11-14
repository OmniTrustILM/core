package com.otilm.core.util.ai;

import com.github.dockerjava.api.model.ExposedPort;
import com.github.dockerjava.api.model.PortBinding;
import com.github.dockerjava.api.model.Ports;
import com.otilm.core.util.BaseSpringBootTest;
import org.postgresql.util.URLCoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/** Shares a supported JDBC endpoint across cached AI persistence test contexts. */
public abstract class BaseAiSpringBootTest extends BaseSpringBootTest {
    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        registerDatasource(registry, Database.INSTANCE);
    }

    static void registerDatasource(DynamicPropertyRegistry registry, PostgreSQLContainer<?> database) {
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.datasource.url", () -> jdbcUrl(database));
        registry.add("spring.datasource.username", database::getUsername);
        registry.add("spring.datasource.password", database::getPassword);
    }

    static String jdbcUrl(PostgreSQLContainer<?> database) {
        if (!"localhost".equals(database.getHost()) && !"127.0.0.1".equals(database.getHost())) {
            throw new IllegalStateException("AI test database requires a local Docker endpoint");
        }
        return "jdbc:postgresql://127.0.0.1:" + database.getMappedPort(5432) + "/"
                + URLCoder.encode(database.getDatabaseName())
                + "?currentSchema=core&gssEncMode=disable&sslmode=disable";
    }

    private static final class Database {
        private static final PostgreSQLContainer<?> INSTANCE = start();

        private static PostgreSQLContainer<?> start() {
            var database = new PostgreSQLContainer<>(DockerImageName
                    .parse("postgres@sha256:09e4f20b14ddb3dfe3a0c825b206032aaf8f28300ba2070c0b60fc1c10c6abc7")
                    .asCompatibleSubstituteFor("postgres"))
                    .withDatabaseName("test")
                    .withUsername("test")
                    .withPassword("test")
                    .withCreateContainerCmdModifier(command -> command
                            .getHostConfig()
                            .withPortBindings(
                                    new PortBinding(Ports.Binding.bindIp("127.0.0.1"), new ExposedPort(5432))));
            try {
                database.start();
                ProofDatabaseLifecycle.requireLoopbackBinding(database);
                return database;
            } catch (RuntimeException failure) {
                database.stop();
                throw failure;
            }
        }
    }
}

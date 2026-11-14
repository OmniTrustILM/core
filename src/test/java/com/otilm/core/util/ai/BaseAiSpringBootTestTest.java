package com.otilm.core.util.ai;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.postgresql.Driver;
import org.postgresql.PGProperty;
import org.testcontainers.containers.PostgreSQLContainer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class BaseAiSpringBootTestTest {
    @Test
    void registersExplicitSupportedDriverEndpointAndCredentials() {
        var database = new Endpoint("localhost");
        Map<String, Object> properties = new HashMap<>();
        BaseAiSpringBootTest.registerDatasource((name, value) -> properties.put(name, value.get()), database);
        assertEquals("org.postgresql.Driver", properties.get("spring.datasource.driver-class-name"));
        assertEquals(database.getUsername(), properties.get("spring.datasource.username"));
        assertEquals(database.getPassword(), properties.get("spring.datasource.password"));
        var jdbc = Driver.parseURL((String) properties.get("spring.datasource.url"), null);
        assertEquals("127.0.0.1", PGProperty.PG_HOST.getOrDefault(jdbc));
        assertEquals("55432", PGProperty.PG_PORT.getOrDefault(jdbc));
        assertEquals(database.getDatabaseName(), PGProperty.PG_DBNAME.getOrDefault(jdbc));
        assertEquals("core", PGProperty.CURRENT_SCHEMA.getOrDefault(jdbc));
        assertEquals("disable", PGProperty.GSS_ENC_MODE.getOrDefault(jdbc));
        assertEquals("disable", PGProperty.SSL_MODE.getOrDefault(jdbc));
    }

    @Test
    void acceptsLiteralLoopbackDockerHost() {
        assertEquals(BaseAiSpringBootTest.jdbcUrl(new Endpoint("localhost")),
                BaseAiSpringBootTest.jdbcUrl(new Endpoint("127.0.0.1")));
    }

    @Test
    void rejectsRemoteDockerEndpointRatherThanRewritingIt() {
        var database = new Endpoint("192.0.2.1");
        assertThrows(IllegalStateException.class, () -> BaseAiSpringBootTest.jdbcUrl(database));
    }

    @Test
    void rejectsUnqualifiedDockerHostname() {
        var database = new Endpoint("docker.example");
        assertThrows(IllegalStateException.class, () -> BaseAiSpringBootTest.jdbcUrl(database));
    }

    private static final class Endpoint extends PostgreSQLContainer<Endpoint> {
        private final String host;

        private Endpoint(String host) {
            super("postgres:15-alpine");
            this.host = host;
        }

        @Override
        public String getHost() {
            return host;
        }

        @Override
        public Integer getMappedPort(int originalPort) {
            assertEquals(5432, originalPort);
            return 55432;
        }
    }
}

package com.otilm.core.util.ai;

import com.fasterxml.jackson.databind.json.JsonMapper;
import com.github.dockerjava.api.command.InspectContainerResponse;
import com.github.dockerjava.api.exception.NotFoundException;
import com.github.dockerjava.api.model.Container;
import com.github.dockerjava.api.model.ExposedPort;
import com.github.dockerjava.api.model.PortBinding;
import com.github.dockerjava.api.model.Ports;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.time.Duration;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProofDatabaseLifecycleTest {
    @TempDir
    Path directory;

    @Test
    void enabledStartupFailureStopsAuthorityAndRemovesAReadyDatabase() throws Exception {
        Set<String> foreign = containerIds();
        HttpServer authority = authority();
        URI endpoint = endpoint(authority);
        var database = new ObservedPostgreSQL();
        configure(database);
        database.withStartupAttempts(1).withInitScript("ai/authorization/absent-startup-schema.sql");
        try {
            assertEquals(204, request(endpoint));
            var fixtures = new ProofDatabaseLifecycle(database, () -> authority.stop(0));
            assertThrows(RuntimeException.class, fixtures::start);
            assertTrue(database.ready.get());
            assertThrows(IOException.class, () -> request(endpoint));
            var inspection = DockerClientFactory.instance().client().inspectContainerCmd(database.created.get());
            assertThrows(NotFoundException.class, inspection::exec);
        } finally {
            authority.stop(0);
            database.stop();
            assertEquals(foreign, containerIds());
        }
    }

    @Test
    void completionRecordFollowsRealAuthorityAndDatabaseStop() throws Exception {
        Set<String> foreign = containerIds();
        HttpServer authority = authority();
        URI endpoint = endpoint(authority);
        PostgreSQLContainer<?> database = configure(new PostgreSQLContainer<>(image()));
        Path completionFile = directory.resolve("completed.json");
        try {
            var fixtures = new ProofDatabaseLifecycle(database, () -> authority.stop(0));
            fixtures.start();
            String id = database.getContainerId();
            assertEquals(204, request(endpoint));
            fixtures.stopAfterContexts(completionFile);
            assertThrows(IOException.class, () -> request(endpoint));
            var inspection = DockerClientFactory.instance().client().inspectContainerCmd(id);
            assertThrows(NotFoundException.class, inspection::exec);
            assertTrue(Files.isRegularFile(completionFile));
            var observation = assertDoesNotThrow(
                    () -> JsonMapper.builder().build().readTree(Files.readString(completionFile)));
            Set<String> fields = new java.util.HashSet<>();
            observation.fieldNames().forEachRemaining(fields::add);
            assertEquals(Set.of("schema", "status", "lifecycleIdentity", "databaseIdentity"), fields);
            assertEquals(1, observation.path("schema").intValue());
            assertEquals("completed", observation.path("status").textValue());
            assertTrue(observation.path("lifecycleIdentity").textValue().matches("[0-9a-f]{1,8}"));
            assertTrue(observation.path("databaseIdentity").textValue().matches("[0-9a-f]{1,8}"));
        } finally {
            authority.stop(0);
            database.stop();
            assertEquals(foreign, containerIds());
        }
    }

    @Test
    void authorityStopFailureCannotPublishCompletion() throws IOException {
        HttpServer authority = authority();
        Path completionFile = directory.resolve("failed.json");
        var database = new PostgreSQLContainer<>(image());
        var fixtures = new ProofDatabaseLifecycle(database, () -> {
            authority.stop(0);
            throw new IllegalStateException("Intentional authority stop failure");
        });
        assertThrows(IllegalStateException.class, () -> fixtures.stopAfterContexts(completionFile));
        assertFalse(Files.exists(completionFile));
    }

    @Test
    void preexistingCompletionRecordCannotBeReplaced() throws IOException {
        Path completionFile = directory.resolve("existing.json");
        Files.writeString(completionFile, "existing observation");
        var fixtures = new ProofDatabaseLifecycle(new PostgreSQLContainer<>(image()), () -> {
        });
        assertThrows(IllegalStateException.class, () -> fixtures.stopAfterContexts(completionFile));
        assertEquals("existing observation", Files.readString(completionFile));
    }

    @Test
    void symbolicCompletionRecordCannotBeFollowed() throws IOException {
        Path target = directory.resolve("target.json");
        Files.writeString(target, "original observation");
        Path completionFile = directory.resolve("link.json");
        Files.createSymbolicLink(completionFile, target);
        var fixtures = new ProofDatabaseLifecycle(new PostgreSQLContainer<>(image()), () -> {
        });
        assertThrows(IllegalStateException.class, () -> fixtures.stopAfterContexts(completionFile));
        assertEquals("original observation", Files.readString(target));
    }

    @Test
    void relativeCompletionRecordIsRejected() {
        var fixtures = new ProofDatabaseLifecycle(new PostgreSQLContainer<>(image()), () -> {
        });
        Path relativeFile = Path.of("relative-record.json");
        assertThrows(IllegalArgumentException.class, () -> fixtures.stopAfterContexts(relativeFile));
    }

    @Test
    void absentOptionalRecordStillStopsAuthority() throws Exception {
        HttpServer authority = authority();
        URI endpoint = endpoint(authority);
        var fixtures = new ProofDatabaseLifecycle(new PostgreSQLContainer<>(image()), () -> authority.stop(0));
        assertEquals(204, request(endpoint));
        fixtures.stopAfterContexts(null);
        assertThrows(IOException.class, () -> request(endpoint));
    }

    private static final class ObservedPostgreSQL extends PostgreSQLContainer<ObservedPostgreSQL> {
        private final AtomicBoolean ready = new AtomicBoolean();
        private final AtomicReference<String> created = new AtomicReference<>();

        private ObservedPostgreSQL() {
            super(image());
        }

        @Override
        protected void containerIsStarted(InspectContainerResponse information) {
            created.set(information.getId());
            try (var connection = DriverManager.getConnection(getJdbcUrl(), getUsername(), getPassword());
                    var statement = connection.createStatement();
                    var result = statement.executeQuery("SELECT 1")) {
                ready.set(result.next() && result.getInt(1) == 1);
            } catch (Exception failure) {
                throw new IllegalStateException("Database readiness observation failed", failure);
            }
            super.containerIsStarted(information);
        }
    }

    private static HttpServer authority() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });
        server.start();
        return server;
    }

    private static URI endpoint(HttpServer server) {
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/");
    }

    private static int request(URI endpoint) throws IOException, InterruptedException {
        try (HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build()) {
            return client
                    .send(HttpRequest.newBuilder(endpoint).timeout(Duration.ofSeconds(2)).build(),
                            HttpResponse.BodyHandlers.discarding())
                    .statusCode();
        }
    }

    private static DockerImageName image() {
        return DockerImageName
                .parse("postgres@sha256:09e4f20b14ddb3dfe3a0c825b206032aaf8f28300ba2070c0b60fc1c10c6abc7")
                .asCompatibleSubstituteFor("postgres");
    }

    private static PostgreSQLContainer<?> configure(PostgreSQLContainer<?> database) {
        return database
                .withCreateContainerCmdModifier(command -> command
                        .getHostConfig()
                        .withPortBindings(new PortBinding(Ports.Binding.bindIp("127.0.0.1"), new ExposedPort(5432))))
                .withLabel("com.otilm.ai-proof.lifecycle", UUID.randomUUID().toString());
    }

    private static Set<String> containerIds() {
        return DockerClientFactory
                .instance()
                .client()
                .listContainersCmd()
                .withShowAll(true)
                .exec()
                .stream()
                .map(Container::getId)
                .collect(Collectors.toSet());
    }
}

package com.otilm.core.util.ai;

import com.github.dockerjava.api.model.Ports;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;

/** Owns the proof database and its paired authorization fixture cleanup. */
final class ProofDatabaseLifecycle {
    static final String STOP_RECORD_PROPERTY = "ilm.test.proof-fixture-stop-record";
    private final PostgreSQLContainer<?> database;
    private final Runnable stopAuthority;

    ProofDatabaseLifecycle(PostgreSQLContainer<?> database, Runnable stopAuthority) {
        this.database = database;
        this.stopAuthority = stopAuthority;
    }

    void start() {
        try {
            database.start();
            requireLoopbackBinding(database);
        } catch (RuntimeException failure) {
            stop();
            throw failure;
        }
    }

    void stop() {
        try {
            stopAuthority.run();
        } finally {
            database.stop();
        }
    }

    void stopAfterContexts(Path completionFile) {
        stop();
        if (completionFile != null) {
            if (!completionFile.isAbsolute()) {
                throw new IllegalArgumentException("Proof cleanup record requires an absolute path");
            }
            String observation = "{\"schema\":1,\"status\":\"completed\",\"lifecycleIdentity\":\"%x\",\"databaseIdentity\":\"%x\"}"
                    .formatted(System.identityHashCode(this), System.identityHashCode(database)) + "\n";
            try {
                Files
                        .writeString(completionFile, observation, StandardCharsets.US_ASCII,
                                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            } catch (IOException failure) {
                throw new IllegalStateException("Unable to record proof fixture cleanup", failure);
            }
        }
    }

    static List<Ports.Binding> actualPortBindings(GenericContainer<?> container) {
        var actual = DockerClientFactory.instance().client().inspectContainerCmd(container.getContainerId()).exec();
        return actual
                .getNetworkSettings()
                .getPorts()
                .getBindings()
                .values()
                .stream()
                .flatMap(java.util.Arrays::stream)
                .toList();
    }

    static void requireLoopbackBinding(GenericContainer<?> container) {
        List<Ports.Binding> bindings = actualPortBindings(container);
        if (bindings.isEmpty() || bindings.stream().anyMatch(binding -> !"127.0.0.1".equals(binding.getHostIp()))) {
            throw new IllegalStateException("A proof fixture published a port outside loopback.");
        }
    }
}

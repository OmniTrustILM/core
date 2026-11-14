package com.otilm.ai.controller;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ControllerConfigurationTest {
    @TempDir
    Path directory;
    private static final String VALID = """
            {"version":1,
             "core":{"origin":"https://core.test:9444/api","address":"127.0.0.1",
               "certificateFile":"/run/controller-identity/tls.crt","privateKeyFile":"/run/controller-identity/tls.key",
               "serverCaFile":"/run/core-ca/ca.pem"},
             "kubernetes":{"origin":"https://kube.test:6443","address":"127.0.0.1",
               "serverCaFile":"/run/api-ca/ca.pem","tokenFile":"/run/controller-token/token"},
             "profileFile":"/etc/ai-controller/accepted-profile.json"}
            """;

    @Test
    void administratorReferencesPreserveCoreContextAndKeepApiCredentialsSeparate() throws Exception {
        var configuration = assertDoesNotThrow(() -> ControllerConfiguration.read(file(VALID)));
        assertEquals("https://core.test:9444/api", configuration.core().origin().toString());
        assertEquals("127.0.0.1", configuration.core().address().getHostAddress());
        assertEquals(Path.of("/run/controller-identity/tls.key"), configuration.privateKeyFile());
        assertEquals(Path.of("/run/controller-token/token"), configuration.kubernetes().tokenFile());
        assertEquals(Path.of("/etc/ai-controller/accepted-profile.json"), configuration.profileFile());
    }

    @Test
    void unknownFieldsDuplicateVersionOverflowAndPathOrOriginSelectorsFailClosed() throws Exception {
        for (String invalid : new String[]{
                VALID + "{}",
                "[]",
                VALID.replace("\"version\":1", "\"version\":4294967297"),
                VALID.replace("\"version\":1", "\"version\":1,\"version\":1"),
                VALID.replace("\"version\":1", "\"version\":1,\"ready\":true"),
                VALID.replace("127.0.0.1", "selectable.test"),
                VALID.replace("/etc/ai-controller/accepted-profile.json", "relative.json"),
                VALID.replace("/run/controller-identity/tls.key", "/run/x/../tls.key"),
                VALID.replace("https://kube.test:6443", "https://kube.test:6443/api"),
                VALID.replace("https://core.test:9444/api", "https://core.test:9444/api?target=other"),
                " ".repeat(8193)}) {
            Path input = file(invalid);
            var failure = assertThrows(ObservationFailure.class, () -> ControllerConfiguration.read(input));
            assertNull(failure.getCause());
            assertEquals(0, failure.getStackTrace().length);
        }
    }

    @Test
    void absentOrWritableConfigurationCannotSupplyBootstrapReferences() throws Exception {
        assertThrows(ObservationFailure.class, () -> ControllerConfiguration.read(directory.resolve("absent")));
        Path input = file(VALID);
        Files.setPosixFilePermissions(input, PosixFilePermissions.fromString("rw-rw-rw-"));
        assertThrows(ObservationFailure.class, () -> ControllerConfiguration.read(input));
    }

    @Test
    void privateConfigurationRequiresActualRegularNonemptyFilesAndNormalizedReferences() throws Exception {
        assertThrows(ObservationFailure.class, () -> ControllerConfiguration.read(null));
        assertThrows(ObservationFailure.class, () -> ControllerConfiguration.read(Path.of("relative-private-canary")));
        assertThrows(ObservationFailure.class, () -> ControllerConfiguration.read(Path.of("/")));
        assertThrows(ObservationFailure.class, () -> ControllerConfiguration.read(directory));
        assertThrows(ObservationFailure.class, () -> ControllerConfiguration.read(file("")));
        Path groupWritable = file(VALID);
        Files.setPosixFilePermissions(groupWritable, PosixFilePermissions.fromString("rw-rw----"));
        assertThrows(ObservationFailure.class, () -> ControllerConfiguration.read(groupWritable));
        for (String value : new String[]{
                VALID.replace("\"version\":1", "\"version\":\"1\""),
                VALID.replace("/run/controller-identity/tls.key", "/run/other/tls.key"),
                VALID.replace("/run/controller-identity/tls.crt", "/"),
                VALID.replace("/run/core-ca/ca.pem", "relative-ca.pem"),
                VALID.replace("/etc/ai-controller/accepted-profile.json", "/etc/../profile.json"),
                VALID.replace("\"core\":{", "\"core\":{\"arbitraryHeader\":\"value\","),
                VALID.replace("\"kubernetes\":{", "\"kubernetes\":{\"ready\":true,")}) {
            assertThrows(ObservationFailure.class, () -> ControllerConfiguration.read(file(value)));
        }
        assertEquals("0:0:0:0:0:0:0:1",
                ControllerConfiguration
                        .read(file(VALID.replace("127.0.0.1", "::1")))
                        .core()
                        .address()
                        .getHostAddress());
    }

    @Test
    void programmaticConfigurationCannotBypassFixedIdentityPairAndEndpointReferences() throws Exception {
        var valid = ControllerConfiguration.read(file(VALID));
        assertThrows(ObservationFailure.class, () -> new ControllerConfiguration(null, valid.certificateFile(),
                valid.privateKeyFile(), valid.serverCaFile(), valid.kubernetes(), valid.profileFile()));
        assertThrows(ObservationFailure.class, () -> new ControllerConfiguration(valid.core(), valid.certificateFile(),
                valid.privateKeyFile(), valid.serverCaFile(), null, valid.profileFile()));
        assertThrows(ObservationFailure.class, () -> new ControllerConfiguration(valid.core(), null,
                valid.privateKeyFile(), valid.serverCaFile(), valid.kubernetes(), valid.profileFile()));
        assertThrows(ObservationFailure.class, () -> new ControllerConfiguration(valid.core(), valid.certificateFile(),
                null, valid.serverCaFile(), valid.kubernetes(), valid.profileFile()));
        assertThrows(ObservationFailure.class, () -> new ControllerConfiguration(valid.core(), valid.certificateFile(),
                valid.privateKeyFile(), null, valid.kubernetes(), valid.profileFile()));
        assertThrows(ObservationFailure.class, () -> new ControllerConfiguration(valid.core(), valid.certificateFile(),
                valid.privateKeyFile(), valid.serverCaFile(), valid.kubernetes(), null));
    }

    private Path file(String text) throws Exception {
        Path input = Files.createTempFile(directory, "controller-", ".json");
        Files.writeString(input, text);
        Files.setPosixFilePermissions(input, PosixFilePermissions.fromString("rw-------"));
        return input;
    }
}

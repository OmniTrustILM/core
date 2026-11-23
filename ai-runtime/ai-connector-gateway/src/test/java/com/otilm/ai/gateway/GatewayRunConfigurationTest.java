package com.otilm.ai.gateway;

import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class GatewayRunConfigurationTest {
    @TempDir
    Path directory;

    ObjectNode configuration(Path secret) throws Exception {
        var n = GatewayRunWireTest.JSON
                .createObjectNode()
                .put("protocolVersion", 1)
                .put("coreOrigin", "https://core.test:8444")
                .put("coreAddress", "127.0.0.1")
                .put("certificateFile", directory.resolve("tls.crt").toString())
                .put("privateKeyFile", directory.resolve("tls.key").toString())
                .put("serverCaFile", directory.resolve("ca.pem").toString())
                .put("providerOrigin", "https://provider.test:8443")
                .put("providerAddress", "127.0.0.1")
                .put("providerCaFile", directory.resolve("provider-ca.pem").toString())
                .put("credentialReference", "lab-key")
                .put("credentialFile", secret.toString());
        n.set("connection", GatewayRunWireTest.consumed().get("connection"));
        return n;
    }

    Path writeConfig(ObjectNode n) throws Exception {
        return Files.write(directory.resolve("config.json"), GatewayRunWireTest.JSON.writeValueAsBytes(n));
    }

    @Test
    void acceptsTheFixedPlatformServletContextWithoutReadingIdentityOrCredentialFiles() throws Exception {
        var root = configuration(directory.resolve("absent-secret"));
        root.put("coreOrigin", "https://core.test:8444/api");
        var config = assertDoesNotThrow(() -> GatewayRunConfiguration.read(writeConfig(root)));
        assertEquals("/api", config.core().origin().getRawPath());
        assertFalse(Files.exists(directory.resolve("absent-secret")));
    }

    @Test
    void deploymentParsingDoesNotReadTheCredentialAndResolutionIsOneExactVersion() throws Exception {
        Path secret = directory.resolve("private.json");
        var config = assertDoesNotThrow(() -> GatewayRunConfiguration.read(writeConfig(configuration(secret))));
        assertFalse(Files.exists(secret));
        Files
                .writeString(secret,
                        "{\"protocolVersion\":1,\"credentialReference\":\"lab-key\",\"authentication\":4,\"bearer\":\"SYNTHETIC_TRANSPORT_TOKEN\"}");
        var consumed = GatewayRunWire
                .consumed(GatewayRunWireTest.JSON.writeValueAsBytes(GatewayRunWireTest.consumed()),
                        GatewayRunWireTest.ENVELOPE, GatewayRunWireTest.CALL);
        assertEquals("SYNTHETIC_TRANSPORT_TOKEN", config.credential(consumed));
        assertThrows(GatewayFailure.class, () -> config.credential(consumed));
        assertFalse(config.toString().contains("private.json"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"reference", "authentication", "bearer", "extra", "large", "directory", "missing"})
    void rejectsAnUnboundInvalidOrUnavailablePrivateBundleWithoutFallback(String mode) throws Exception {
        Path secret = directory.resolve("private.json");
        var config = assertDoesNotThrow(() -> GatewayRunConfiguration.read(writeConfig(configuration(secret))));
        String body = "{\"protocolVersion\":1,\"credentialReference\":\"lab-key\",\"authentication\":4,\"bearer\":\"SYNTHETIC_TRANSPORT_TOKEN\"}";
        switch (mode) {
            case "reference" -> Files.writeString(secret, body.replace("lab-key", "other-key"));
            case "authentication" -> Files.writeString(secret, body.replace(":4", ":5"));
            case "bearer" -> Files.writeString(secret, body.replace("SYNTHETIC_TRANSPORT_TOKEN", "bad\\r\\nheader"));
            case "extra" -> Files.writeString(secret, body.replace("{", "{\"path\":\"PRIVATE_PATH_CANARY\","));
            case "large" -> Files.write(secret, new byte[8193]);
            case "directory" -> Files.createDirectory(secret);
        }
        var consumed = GatewayRunWire
                .consumed(GatewayRunWireTest.JSON.writeValueAsBytes(GatewayRunWireTest.consumed()),
                        GatewayRunWireTest.ENVELOPE, GatewayRunWireTest.CALL);
        var denied = assertThrows(GatewayFailure.class, () -> config.credential(consumed));
        assertNull(denied.getCause());
        assertFalse(denied.getMessage().contains("PRIVATE"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "extra",
            "version",
            "core",
            "address",
            "relative",
            "root",
            "provider",
            "reference",
            "connection",
            "oversized"})
    void rejectsUnsupportedDeploymentSelection(String mode) throws Exception {
        var n = configuration(directory.resolve("private.json"));
        switch (mode) {
            case "extra" -> n.put("executable", "/PRIVATE_EXEC_CANARY");
            case "version" -> n.put("protocolVersion", 2);
            case "core" -> n.put("coreOrigin", "https://core.test/api//arbitrary");
            case "address" -> n.put("coreAddress", "caller-selected.test");
            case "relative" -> n.put("credentialFile", "relative");
            case "root" -> n.put("credentialFile", "/");
            case "provider" -> n.put("providerAddress", "224.0.0.1");
            case "reference" -> n.put("credentialReference", "../secret");
            case "connection" -> ((ObjectNode) n.get("connection")).put("destination", 0);
            case "oversized" -> n.put("credentialFile", "/" + "x".repeat(16384));
        }
        Path config = writeConfig(n);
        assertThrows(GatewayFailure.class, () -> GatewayRunConfiguration.read(config));
    }

    @Test
    void mismatchedPositiveBindingNeverSelectsAnAlternativeCredentialFile() throws Exception {
        var c = assertDoesNotThrow(
                () -> GatewayRunConfiguration.read(writeConfig(configuration(directory.resolve("unread-secret")))));
        var n = GatewayRunWireTest.consumed();
        ((ObjectNode) n.get("connection")).put("configuration", 99);
        var reply = GatewayRunWire
                .consumed(GatewayRunWireTest.JSON.writeValueAsBytes(n), GatewayRunWireTest.ENVELOPE,
                        GatewayRunWireTest.CALL);
        assertThrows(GatewayFailure.class, () -> c.credential(reply));
    }
}

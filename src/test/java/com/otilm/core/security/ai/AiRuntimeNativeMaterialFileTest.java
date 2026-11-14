package com.otilm.core.security.ai;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AiRuntimeNativeMaterialFileTest {
    @TempDir
    Path directory;

    @Test
    void readsOnlyFixedEndpointFileAndDeploymentReferencesAndCopiesCollections() throws Exception {
        var input = valid();
        var result = AiRuntimeNativeMaterialFile.read(write(input.toString()), "/api");

        assertThat(result.cluster()).isEqualTo("lab");
        assertThat(result.contextPath()).isEqualTo("/api");
        assertThat(result.listeners())
                .extracting(AiRuntimeNativeMaterialFile.Binding::role)
                .containsExactly(RuntimePeerRole.values());
        assertThat(result.policy().namespaceName()).isEqualTo("runtime");
        assertThat(result.observation().endpoint().origin().toString()).isEqualTo("https://kubernetes.example:6443");
        assertThat(result.controller().deployment().podName()).isEqualTo("controller-a");
        assertThat(result.workloadProfiles())
                .containsOnlyKeys(RuntimePeerRole.RUNNER_PROXY, RuntimePeerRole.GATEWAY_RUN,
                        RuntimePeerRole.GATEWAY_MANAGEMENT);
        assertThatThrownBy(() -> result.listeners().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> result.workloadProfiles().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThat(result.toString()).doesNotContain(directory.toString(), "token", "kubernetes.example");
    }

    @Test
    void literalIpv6AddressesAreAcceptedWithoutAHostnameLookup() throws Exception {
        var input = valid();
        ((ObjectNode) input.withArray("listeners").get(0)).put("address", "::1");
        ((ObjectNode) input.get("observationSource")).put("address", "2001:db8::1");

        var result = AiRuntimeNativeMaterialFile.read(write(input.toString()), "/api");

        assertThat(result.listeners().getFirst().address().isLoopbackAddress()).isTrue();
        assertThat(result.observation().endpoint().address().getAddress()).hasSize(16);
    }

    @ParameterizedTest
    @MethodSource("invalidRootValues")
    void rejectsUnknownMissingAndMistypedRootAuthority(String field, String encoded) throws Exception {
        var input = valid();
        if (encoded == null) {
            input.remove(field);
        } else {
            input.set(field, ObjectMapperFactory.aiGatewayWire().readTree(encoded));
        }
        var file = write(input.toString());

        assertThatThrownBy(() -> AiRuntimeNativeMaterialFile.read(file, "/api"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Native runtime material is invalid");
    }

    static Stream<Arguments> invalidRootValues() {
        return Stream
                .of(Arguments.of("version", null), Arguments.of("version", "\"1\""), Arguments.of("version", "1.0"),
                        Arguments.of("version", "4294967297"), Arguments.of("cluster", "\"bad/name\""),
                        Arguments.of("cluster", "null"), Arguments.of("contextPath", "\"/another\""),
                        Arguments.of("listeners", "[]"), Arguments.of("serverIdentity", "{}"),
                        Arguments.of("policySource", null), Arguments.of("observationSource", "{}"),
                        Arguments.of("controllerDeployment", "{}"), Arguments.of("workloadProfiles", "{}"),
                        Arguments.of("ready", "true"), Arguments.of("apiKey", "\"SYNTHETIC_NOT_A_CREDENTIAL\""));
    }

    @Test
    void rejectsDuplicateRolesAddressesAndUnpinnedListenerAddresses() throws Exception {
        for (String field : new String[]{"role", "port", "address"}) {
            var input = valid();
            var listener = (ObjectNode) input.withArray("listeners").get(1);
            if (field.equals("address")) {
                listener.put("address", "localhost");
            } else {
                listener.set(field, input.withArray("listeners").get(0).get(field));
            }
            var file = write(input.toString());
            assertThatThrownBy(() -> AiRuntimeNativeMaterialFile.read(file, "/api"))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void rejectsAWildcardListenerOverlappingAnotherRoleOnTheSamePort() throws Exception {
        var input = valid();
        var first = (ObjectNode) input.withArray("listeners").get(0);
        first.put("address", "0.0.0.0");
        ((ObjectNode) input.withArray("listeners").get(1)).set("port", first.get("port"));
        var file = write(input.toString());

        assertThatThrownBy(() -> AiRuntimeNativeMaterialFile.read(file, "/api"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void permitsAdministrativelyBoundWildcardListenersOnDistinctRolePorts() throws Exception {
        var input = valid();
        ((ObjectNode) input.withArray("listeners").get(0)).put("address", "0.0.0.0");
        var result = AiRuntimeNativeMaterialFile.read(write(input.toString()), "/api");

        assertThat(result.listeners().getFirst().address().isAnyLocalAddress()).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"namespaceUid", "serviceAccountUid", "jobUid", "podUid", "runtimeUid"})
    void rejectsNilControllerObjectIdentitiesBeforeTheyReachLiveObservation(String field) throws Exception {
        var input = valid();
        ((ObjectNode) input.get("controllerDeployment")).put(field, new UUID(0, 0).toString());
        var file = write(input.toString());

        assertThatThrownBy(() -> AiRuntimeNativeMaterialFile.read(file, "/api"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsApiAmbientOrCallerSelectedConfiguration() throws Exception {
        for (String origin : new String[]{
                "http://kubernetes.example:6443",
                "https://user@kubernetes.example",
                "https://kubernetes.example?token=synthetic",
                "https://kubernetes.example/api"}) {
            var input = valid();
            ((ObjectNode) input.get("observationSource")).put("origin", origin);
            var file = write(input.toString());
            assertThatThrownBy(() -> AiRuntimeNativeMaterialFile.read(file, "/api"))
                    .isInstanceOf(IllegalArgumentException.class);
        }
        var input = valid();
        ((ObjectNode) input.get("observationSource")).put("tokenFile", "relative-token");
        var relative = write(input.toString());
        assertThatThrownBy(() -> AiRuntimeNativeMaterialFile.read(relative, "/api"))
                .isInstanceOf(IllegalArgumentException.class);
        input = valid();
        ((ObjectNode) input.get("observationSource")).put("headers", "synthetic");
        var headers = write(input.toString());
        assertThatThrownBy(() -> AiRuntimeNativeMaterialFile.read(headers, "/api"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsIncompletePinsAndUnsupportedProfileRoles() throws Exception {
        var input = valid();
        ((ObjectNode) input.get("controllerDeployment")).put("podUid", "not-a-uuid");
        var wrongUid = write(input.toString());
        assertThatThrownBy(() -> AiRuntimeNativeMaterialFile.read(wrongUid, "/api"))
                .isInstanceOf(IllegalArgumentException.class);
        input = valid();
        ((ObjectNode) input.get("workloadProfiles")).remove("GATEWAY_MANAGEMENT");
        ((ObjectNode) input.get("workloadProfiles")).put("CONTROLLER", directory.resolve("other.json").toString());
        var extraRole = write(input.toString());
        assertThatThrownBy(() -> AiRuntimeNativeMaterialFile.read(extraRole, "/api"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsDuplicateKeysTrailingDocumentsMalformedUtf8AndUnboundedFiles() throws Exception {
        for (String bytes : new String[]{
                "",
                valid() + "{}",
                valid().toString().replace("\"version\":1", "\"version\":1,\"version\":1"),
                " ".repeat(1_048_577)}) {
            var file = write(bytes);
            assertThatThrownBy(() -> AiRuntimeNativeMaterialFile.read(file, "/api"))
                    .isInstanceOf(IllegalArgumentException.class);
        }
        var input = valid();
        ((ObjectNode) input.get("serverIdentity")).put("certificateFile", "/runtime/malformed-marker.pem");
        String validJson = input.toString();
        var file = write(validJson);
        assertThat(AiRuntimeNativeMaterialFile.read(file, "/api")).isNotNull();
        byte[] malformed = validJson.getBytes(StandardCharsets.UTF_8);
        int marker = validJson
                .substring(0, validJson.indexOf("malformed-marker"))
                .getBytes(StandardCharsets.UTF_8).length;
        malformed[marker] = (byte) 0xff;
        Files.write(file, malformed);
        assertThatThrownBy(() -> AiRuntimeNativeMaterialFile.read(file, "/api"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsWritableSymlinkRelativeAndMissingBootstrapFiles() throws Exception {
        var file = write(valid().toString());
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-rw----"));
        assertThatThrownBy(() -> AiRuntimeNativeMaterialFile.read(file, "/api"))
                .isInstanceOf(IllegalArgumentException.class);
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        var link = directory.resolve("link.json");
        Files.createSymbolicLink(link, file);
        for (Path value : new Path[]{link, Path.of("relative.json"), directory, directory.resolve("missing")}) {
            assertThatThrownBy(() -> AiRuntimeNativeMaterialFile.read(value, "/api"))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    private Path write(String text) throws Exception {
        var file = directory.resolve(UUID.randomUUID() + ".json");
        Files.writeString(file, text);
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        return file;
    }

    private ObjectNode valid() {
        var mapper = ObjectMapperFactory.aiGatewayWire();
        var root = mapper.createObjectNode().put("version", 1).put("cluster", "lab").put("contextPath", "/api");
        root
                .putObject("serverIdentity")
                .put("certificateFile", directory.resolve("server.pem").toString())
                .put("privateKeyFile", directory.resolve("server-key.pem").toString())
                .put("serverCaFile", directory.resolve("server-ca.pem").toString());
        var listeners = root.putArray("listeners");
        int port = 8600;
        for (RuntimePeerRole role : RuntimePeerRole.values()) {
            listeners.addObject().put("role", role.name()).put("address", "127.0.0.1").put("port", ++port);
        }
        var policy = root.putObject("policySource");
        policy.set("api", api());
        policy
                .put("namespaceName", "runtime")
                .put("namespaceUid", UUID.randomUUID().toString())
                .put("configMapName", "runtime-policy")
                .put("configMapUid", UUID.randomUUID().toString());
        root.set("observationSource", api());
        var deployment = root.putObject("controllerDeployment");
        deployment
                .put("namespaceName", "runtime")
                .put("namespaceUid", UUID.randomUUID().toString())
                .put("serviceAccountName", "controller")
                .put("serviceAccountUid", UUID.randomUUID().toString())
                .put("jobName", "controller")
                .put("jobUid", UUID.randomUUID().toString())
                .put("podName", "controller-a")
                .put("podUid", UUID.randomUUID().toString())
                .put("runtimeClass", "sandbox")
                .put("runtimeUid", UUID.randomUUID().toString())
                .put("runtimeHandler", "sandbox")
                .put("schedulingGate", "ilm.example/ready")
                .put("podSpecJson", "{}")
                .put("jobSpecJson", "{}")
                .put("runtimeConfigurationJson", "{}")
                .put("podMetadataJson", "{}");
        deployment.putObject("imageIds").put("controller", "docker-pullable://controller@sha256:" + "a".repeat(64));
        var profiles = root.putObject("workloadProfiles");
        for (RuntimePeerRole role : new RuntimePeerRole[]{
                RuntimePeerRole.RUNNER_PROXY,
                RuntimePeerRole.GATEWAY_RUN,
                RuntimePeerRole.GATEWAY_MANAGEMENT}) {
            profiles.put(role.name(), directory.resolve(role.name() + ".json").toString());
        }
        return root;
    }

    private ObjectNode api() {
        return ObjectMapperFactory
                .aiGatewayWire()
                .createObjectNode()
                .put("origin", "https://kubernetes.example:6443")
                .put("address", "127.0.0.1")
                .put("serverCaFile", directory.resolve("api-ca.pem").toString())
                .put("tokenFile", directory.resolve("api-token").toString());
    }
}

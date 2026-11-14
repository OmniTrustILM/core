package com.otilm.core.security.ai;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.ai.controller.KubernetesConfiguration;
import com.otilm.ai.controller.KubernetesSnapshotVerifier;
import com.otilm.ai.proxy.CoreEndpoint;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Fixed administrative file references; parsing grants no workload or business authority. */
record AiRuntimeNativeMaterialFile(String cluster, String contextPath, Path certificateFile, Path privateKeyFile,
        Path serverCaFile, List<Binding> listeners, AiRuntimeNativeMaterialPublisher.Source policy,
        KubernetesConfiguration observation, AiRuntimeControllerAuthority.Source controller,
        Map<RuntimePeerRole, Path> workloadProfiles) {
    private static final int MAXIMUM = 1_048_576;
    private static final ObjectMapper JSON = ObjectMapperFactory.aiGatewayWire();
    private static final Set<String> ROOT_FIELDS = Set
            .of("version", "cluster", "contextPath", "serverIdentity", "listeners", "policySource", "observationSource",
                    "controllerDeployment", "workloadProfiles");
    private static final Set<String> API_FIELDS = Set.of("origin", "address", "serverCaFile", "tokenFile");
    private static final Set<String> PIN_FIELDS = Set
            .of("namespaceName", "namespaceUid", "serviceAccountName", "serviceAccountUid", "jobName", "jobUid",
                    "podName", "podUid", "runtimeClass", "runtimeUid", "runtimeHandler", "schedulingGate",
                    "podSpecJson", "jobSpecJson", "runtimeConfigurationJson", "podMetadataJson", "imageIds");
    private static final Set<RuntimePeerRole> PROFILE_ROLES = Set
            .of(RuntimePeerRole.RUNNER_PROXY, RuntimePeerRole.GATEWAY_RUN, RuntimePeerRole.GATEWAY_MANAGEMENT);

    AiRuntimeNativeMaterialFile {
        listeners = List.copyOf(listeners);
        workloadProfiles = Map.copyOf(workloadProfiles);
    }

    record Binding(RuntimePeerRole role, InetAddress address, int port) {
    }

    static AiRuntimeNativeMaterialFile read(Path file, String expectedContext) {
        try {
            require(file != null && file.isAbsolute() && file.equals(file.normalize()));
            var before = attributes(file);
            var permissions = Files.getPosixFilePermissions(file, LinkOption.NOFOLLOW_LINKS);
            require(!permissions.contains(PosixFilePermission.GROUP_WRITE)
                    && !permissions.contains(PosixFilePermission.OTHERS_WRITE));
            byte[] bytes;
            try (var input = Files.newInputStream(file, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
                bytes = input.readNBytes(MAXIMUM + 1);
            }
            require(bytes.length == before.size() && bytes.length <= MAXIMUM);
            var result = parse(JSON.readTree(bytes), expectedContext);
            var after = attributes(file);
            require(Objects.equals(before.fileKey(), after.fileKey()) && before.size() == after.size()
                    && before.lastModifiedTime().equals(after.lastModifiedTime())
                    && permissions.equals(Files.getPosixFilePermissions(file, LinkOption.NOFOLLOW_LINKS)));
            return result;
        } catch (IOException | RuntimeException invalid) {
            throw new IllegalArgumentException("Native runtime material is invalid");
        }
    }

    private static BasicFileAttributes attributes(Path file) throws IOException {
        var value = Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        require(value.isRegularFile() && value.fileKey() != null && value.size() > 0 && value.size() <= MAXIMUM);
        return value;
    }

    private static AiRuntimeNativeMaterialFile parse(JsonNode root, String expectedContext) throws IOException {
        fields(root, ROOT_FIELDS);
        JsonNode version = root.get("version");
        require(version.isIntegralNumber() && version.canConvertToInt() && version.intValue() == 1);
        String cluster = text(root.get("cluster"), 63);
        require(cluster.matches("[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"));
        String context = text(root.get("contextPath"), 128);
        require(context.equals(expectedContext) && context.matches("(?:/[A-Za-z0-9_-]++)*+"));
        JsonNode server = root.get("serverIdentity");
        fields(server, Set.of("certificateFile", "privateKeyFile", "serverCaFile"));
        var observation = api(root.get("observationSource"));
        return new AiRuntimeNativeMaterialFile(cluster, context, path(server.get("certificateFile")),
                path(server.get("privateKeyFile")), path(server.get("serverCaFile")), bindings(root.get("listeners")),
                policy(root.get("policySource")), observation,
                new AiRuntimeControllerAuthority.Source(cluster, observation, pins(root.get("controllerDeployment"))),
                profiles(root.get("workloadProfiles")));
    }

    private static List<Binding> bindings(JsonNode array) throws UnknownHostException {
        require(array != null && array.isArray() && array.size() == RuntimePeerRole.values().length);
        var result = new ArrayList<Binding>();
        var roles = new HashSet<RuntimePeerRole>();
        var ports = new HashSet<Integer>();
        for (JsonNode entry : array) {
            fields(entry, Set.of("role", "address", "port"));
            var role = RuntimePeerRole.valueOf(text(entry.get("role"), 32));
            JsonNode number = entry.get("port");
            require(number.isIntegralNumber() && number.canConvertToInt());
            int port = number.intValue();
            require(port > 0 && port <= 65535);
            InetAddress address = address(entry.get("address"));
            require(roles.add(role) && ports.add(port));
            result.add(new Binding(role, address, port));
        }
        return result;
    }

    private static AiRuntimeNativeMaterialPublisher.Source policy(JsonNode value) {
        fields(value, Set.of("api", "namespaceName", "namespaceUid", "configMapName", "configMapUid"));
        return new AiRuntimeNativeMaterialPublisher.Source(api(value.get("api")), text(value.get("namespaceName"), 63),
                uid(value.get("namespaceUid")), text(value.get("configMapName"), 253), uid(value.get("configMapUid")));
    }

    private static KubernetesConfiguration api(JsonNode value) {
        fields(value, API_FIELDS);
        try {
            return new KubernetesConfiguration(
                    new CoreEndpoint(URI.create(text(value.get("origin"), 1024)), address(value.get("address"))),
                    path(value.get("serverCaFile")), path(value.get("tokenFile")));
        } catch (UnknownHostException | RuntimeException invalid) {
            throw new IllegalArgumentException("Native runtime endpoint is invalid");
        }
    }

    private static KubernetesSnapshotVerifier.Pins pins(JsonNode value) throws JsonProcessingException {
        fields(value, PIN_FIELDS);
        for (String field : PIN_FIELDS) {
            if (!field.equals("imageIds")) {
                text(value.get(field), 65_536);
            }
        }
        for (String field : Set.of("namespaceUid", "serviceAccountUid", "jobUid", "podUid", "runtimeUid")) {
            uid(value.get(field));
        }
        JsonNode images = value.get("imageIds");
        require(images.isObject() && !images.isEmpty() && images.size() <= 16);
        for (JsonNode image : images) {
            text(image, 1024);
        }
        return JSON.treeToValue(value, KubernetesSnapshotVerifier.Pins.class);
    }

    private static Map<RuntimePeerRole, Path> profiles(JsonNode value) {
        require(value != null && value.isObject() && value.size() == PROFILE_ROLES.size());
        var result = new EnumMap<RuntimePeerRole, Path>(RuntimePeerRole.class);
        var names = value.fieldNames();
        while (names.hasNext()) {
            var name = names.next();
            var role = RuntimePeerRole.valueOf(name);
            require(PROFILE_ROLES.contains(role));
            result.put(role, path(value.get(name)));
        }
        return result;
    }

    private static InetAddress address(JsonNode value) throws UnknownHostException {
        String literal = text(value, 64);
        InetAddress result;
        if (literal.contains(":")) {
            require(literal.matches("[0-9a-fA-F:]+"));
            result = InetAddress.getByName(literal);
        } else {
            require(literal.matches("[0-9]{1,3}(?:\\.[0-9]{1,3}){3}"));
            String[] parts = literal.split("\\.");
            byte[] bytes = new byte[4];
            for (int index = 0; index < bytes.length; index++) {
                int number = Integer.parseInt(parts[index]);
                require(number <= 255);
                bytes[index] = (byte) number;
            }
            result = InetAddress.getByAddress(bytes);
        }
        require(!result.isMulticastAddress());
        return result;
    }

    private static UUID uid(JsonNode value) {
        String text = text(value, 36);
        UUID result = UUID.fromString(text);
        require(result.toString().equals(text) && !result.equals(new UUID(0, 0)));
        return result;
    }

    private static Path path(JsonNode value) {
        Path result = Path.of(text(value, 4096));
        require(result.isAbsolute() && result.getParent() != null && result.normalize().equals(result));
        return result;
    }

    private static String text(JsonNode value, int maximum) {
        require(value != null && value.isTextual());
        String result = value.textValue();
        require(!result.isEmpty() && result.length() <= maximum);
        return result;
    }

    private static void fields(JsonNode value, Set<String> expected) {
        require(value != null && value.isObject() && value.size() == expected.size());
        var actual = new HashSet<String>();
        value.fieldNames().forEachRemaining(actual::add);
        require(actual.equals(expected));
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new IllegalArgumentException("Native runtime material is invalid");
        }
    }

    @Override
    public String toString() {
        return "NativeRuntimeMaterial";
    }
}

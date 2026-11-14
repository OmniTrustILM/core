package com.otilm.ai.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.otilm.ai.proxy.CoreEndpoint;
import java.net.InetAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import org.apache.hc.core5.net.InetAddressUtils;

/** Fixed administrator references; the controller receives no URL, key or executable from a workload. */
public record ControllerConfiguration(CoreEndpoint core, Path certificateFile, Path privateKeyFile, Path serverCaFile,
        KubernetesConfiguration kubernetes, Path profileFile) {
    public ControllerConfiguration {
        if (core == null || kubernetes == null || !absolute(certificateFile) || !absolute(privateKeyFile)
                || !absolute(serverCaFile) || !absolute(profileFile)
                || !certificateFile.getParent().equals(privateKeyFile.getParent())) {
            throw new ObservationFailure();
        }
    }

    public static ControllerConfiguration read(Path file) {
        try {
            var root = fields(document(file, 8192), Set.of("version", "core", "kubernetes", "profileFile"));
            if (!root.path("version").isIntegralNumber() || !root.path("version").canConvertToInt()
                    || root.path("version").intValue() != 1) {
                throw new ObservationFailure();
            }
            var core = fields(root.get("core"),
                    Set.of("origin", "address", "certificateFile", "privateKeyFile", "serverCaFile"));
            var api = fields(root.get("kubernetes"), Set.of("origin", "address", "serverCaFile", "tokenFile"));
            return new ControllerConfiguration(endpoint(core), path(core, "certificateFile"),
                    path(core, "privateKeyFile"), path(core, "serverCaFile"),
                    new KubernetesConfiguration(endpoint(api), path(api, "serverCaFile"), path(api, "tokenFile")),
                    path(root, "profileFile"));
        } catch (Throwable unavailable) {
            throw new ObservationFailure();
        }
    }

    static ObjectNode document(Path file, int maximum) {
        try {
            if (!absolute(file) || maximum < 1 || maximum > 1_048_576) {
                throw new ObservationFailure();
            }
            Path resolved = file.toRealPath();
            var before = state(resolved, maximum);
            byte[] bytes;
            try (var input = Files.newInputStream(resolved)) {
                bytes = input.readNBytes(maximum + 1);
            }
            if (bytes.length == 0 || bytes.length > maximum || bytes.length != before.size()) {
                throw new ObservationFailure();
            }
            var root = KubernetesSnapshotVerifier.parse(bytes);
            var after = state(resolved, maximum);
            if (!resolved.equals(file.toRealPath()) || !Objects.equals(before.fileKey(), after.fileKey())
                    || before.size() != after.size() || !before.lastModifiedTime().equals(after.lastModifiedTime())) {
                throw new ObservationFailure();
            }
            return root;
        } catch (Throwable unavailable) {
            throw new ObservationFailure();
        }
    }

    private static BasicFileAttributes state(Path path, int maximum) throws Exception {
        var value = Files.readAttributes(path, BasicFileAttributes.class);
        var mode = Files.getPosixFilePermissions(path);
        if (!value.isRegularFile() || value.fileKey() == null || value.size() <= 0 || value.size() > maximum
                || mode.contains(PosixFilePermission.OTHERS_WRITE) || mode.contains(PosixFilePermission.GROUP_WRITE)) {
            throw new ObservationFailure();
        }
        return value;
    }

    static ObjectNode fields(JsonNode node, Set<String> expected) {
        if (!(node instanceof ObjectNode object)) {
            throw new ObservationFailure();
        }
        var actual = new HashSet<String>();
        object.fieldNames().forEachRemaining(actual::add);
        if (!actual.equals(expected)) {
            throw new ObservationFailure();
        }
        return object;
    }

    private static CoreEndpoint endpoint(JsonNode node) throws Exception {
        String address = KubernetesSnapshotVerifier.text(node, "address");
        if (!InetAddressUtils.isIPv4(address) && !InetAddressUtils.isIPv6(address)) {
            throw new ObservationFailure();
        }
        return new CoreEndpoint(URI.create(KubernetesSnapshotVerifier.text(node, "origin")),
                InetAddress.getByName(address));
    }

    private static Path path(JsonNode node, String field) {
        Path value = Path.of(KubernetesSnapshotVerifier.text(node, field));
        if (!absolute(value)) {
            throw new ObservationFailure();
        }
        return value;
    }

    private static boolean absolute(Path path) {
        return path != null && path.isAbsolute() && path.getParent() != null && path.equals(path.normalize());
    }
}

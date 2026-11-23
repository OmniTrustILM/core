package com.otilm.core.service.ai;

import com.fasterxml.jackson.databind.JsonNode;
import com.otilm.ai.controller.ControllerProfile;
import com.otilm.core.model.ai.AiRuntimeState.ControlPins;
import com.otilm.core.model.ai.AiRuntimeState.LaunchSpec;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Arrays;
import java.util.Objects;

/** Captures administrator recipe bytes; current API and independent native proof remain separate requirements. */
final class AiRuntimeWorkloadProfile {
    private static final int MAXIMUM = 1_048_576;
    private final Path file;
    private final byte[] original;
    private final ControllerProfile profile;
    private final ControlPins pins;
    private final String jobName;

    private AiRuntimeWorkloadProfile(Path file, byte[] original, ControllerProfile profile, ControlPins pins,
            String jobName) {
        this.file = file;
        this.original = original;
        this.profile = profile;
        this.pins = pins;
        this.jobName = jobName;
    }

    static AiRuntimeWorkloadProfile read(Path file, AiRuntimeOperationBudget budget) throws Exception {
        byte[] before = snapshot(file, budget);
        var profile = ControllerProfile.read(file);
        if (!Arrays.equals(before, snapshot(file, budget))) {
            throw invalid();
        }
        JsonNode root = ObjectMapperFactory
                .aiKubernetesWire()
                .readTree(StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(before)).toString());
        var value = root.path("pins");
        var launch = new LaunchSpec(value.path("cluster").textValue(), value.path("namespaceName").textValue(),
                value.path("namespaceUid").textValue(), value.path("serviceAccountName").textValue(),
                value.path("serviceAccountUid").textValue(), value.path("templateDigest").textValue(),
                value.path("runtimeClass").textValue());
        var pins = new ControlPins(value.path("imageDigest").textValue(), value.path("profileRevision").longValue(),
                value.path("securityRevision").longValue(), value.path("trustRevision").longValue(),
                value.path("protocol").textValue(), launch);
        budget.remaining();
        return new AiRuntimeWorkloadProfile(file, before, profile, pins,
                root.path("job").path("metadata").path("name").textValue());
    }

    ControllerProfile profile() {
        return profile;
    }

    ControlPins pins() {
        return pins;
    }

    String jobName() {
        return jobName;
    }

    void requireUnchanged(AiRuntimeOperationBudget budget) throws Exception {
        if (!Arrays.equals(original, snapshot(file, budget))) {
            throw invalid();
        }
    }

    private static byte[] snapshot(Path file, AiRuntimeOperationBudget budget) throws Exception {
        budget.remaining();
        if (file == null || !file.isAbsolute() || !file.equals(file.normalize())) {
            throw invalid();
        }
        var before = Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        var permissions = Files.getPosixFilePermissions(file, LinkOption.NOFOLLOW_LINKS);
        if (!before.isRegularFile() || before.fileKey() == null || before.size() < 1 || before.size() > MAXIMUM
                || permissions.contains(PosixFilePermission.GROUP_WRITE)
                || permissions.contains(PosixFilePermission.OTHERS_WRITE)) {
            throw invalid();
        }
        byte[] bytes;
        try (var input = Files.newInputStream(file, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            bytes = input.readNBytes(MAXIMUM + 1);
        }
        var after = Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!Objects.equals(before.fileKey(), after.fileKey()) || before.size() != bytes.length
                || before.size() != after.size() || !before.lastModifiedTime().equals(after.lastModifiedTime())
                || !permissions.equals(Files.getPosixFilePermissions(file, LinkOption.NOFOLLOW_LINKS))) {
            throw invalid();
        }
        budget.remaining();
        return bytes;
    }

    private static IllegalStateException invalid() {
        return new IllegalStateException("Current workload profile unavailable");
    }
}

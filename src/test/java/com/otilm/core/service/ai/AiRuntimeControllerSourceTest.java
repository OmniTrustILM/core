package com.otilm.core.service.ai;

import com.otilm.ai.controller.KubernetesConfiguration;
import com.otilm.ai.proxy.CoreEndpoint;
import com.otilm.core.security.ai.RuntimePeerRole;
import java.net.InetAddress;
import java.net.URI;
import java.nio.file.Path;
import java.util.EnumMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AiRuntimeControllerSourceTest {
    @Test
    void administratorReferencesAreCapturedWithoutAcceptingControllerAsATargetRole() throws Exception {
        var profiles = profiles();
        var source = new AiRuntimeControllerServiceImpl.Source(api(), profiles);
        profiles.clear();
        assertEquals(
                Set.of(RuntimePeerRole.RUNNER_PROXY, RuntimePeerRole.GATEWAY_RUN, RuntimePeerRole.GATEWAY_MANAGEMENT),
                source.workloadProfiles().keySet());
        assertThrows(UnsupportedOperationException.class, () -> source.workloadProfiles().clear());
        assertEquals("Source[redacted]", source.toString());
        var extra = profiles();
        extra.put(RuntimePeerRole.CONTROLLER, Path.of("/private/controller-profile-canary"));
        assertThrows(IllegalArgumentException.class, () -> new AiRuntimeControllerServiceImpl.Source(api(), extra));
    }

    @Test
    void missingOrAmbiguousProfileReferencesCannotBecomeCurrentObservationInputs() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> new AiRuntimeControllerServiceImpl.Source(api(), Map.of()));
        for (Path bad : new Path[]{
                Path.of("relative-private-canary"),
                Path.of("/private/../profile-canary"),
                Path.of("/")}) {
            var profiles = profiles();
            profiles.put(RuntimePeerRole.RUNNER_PROXY, bad);
            assertThrows(IllegalArgumentException.class,
                    () -> new AiRuntimeControllerServiceImpl.Source(api(), profiles));
        }
    }

    private static EnumMap<RuntimePeerRole, Path> profiles() {
        var result = new EnumMap<RuntimePeerRole, Path>(RuntimePeerRole.class);
        result.put(RuntimePeerRole.RUNNER_PROXY, Path.of("/private/runner-profile-canary"));
        result.put(RuntimePeerRole.GATEWAY_RUN, Path.of("/private/run-profile-canary"));
        result.put(RuntimePeerRole.GATEWAY_MANAGEMENT, Path.of("/private/management-profile-canary"));
        return result;
    }

    private static KubernetesConfiguration api() throws Exception {
        return new KubernetesConfiguration(
                new CoreEndpoint(URI.create("https://kubernetes.example.test:6443"),
                        InetAddress.getByName("127.0.0.1")),
                Path.of("/private/api-ca-canary"), Path.of("/private/api-token-canary"));
    }
}

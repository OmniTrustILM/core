package com.otilm.core.security.ai;

import com.otilm.ai.controller.KubernetesApi;
import com.otilm.ai.controller.KubernetesConfiguration;
import com.otilm.ai.controller.KubernetesObserver;
import com.otilm.ai.controller.KubernetesSnapshotVerifier;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import org.springframework.security.access.AccessDeniedException;

/** Requires current independently observed administrator-pinned controller deployment, in addition to native TLS. */
public final class AiRuntimeControllerAuthority {
    private final Source source;
    private final RuntimeProxyCertificateClaims expected;
    private final AtomicBoolean observing = new AtomicBoolean();
    private volatile KubernetesApi quarantined;

    public record Source(String cluster, KubernetesConfiguration api, KubernetesSnapshotVerifier.Pins deployment) {
        public Source {
            Objects.requireNonNull(cluster);
            Objects.requireNonNull(api);
            Objects.requireNonNull(deployment);
        }
    }

    public AiRuntimeControllerAuthority(Source source) {
        this.source = Objects.requireNonNull(source);
        var deployment = source.deployment();
        expected = new RuntimeProxyCertificateClaims(source.cluster(), deployment.namespaceName(),
                deployment.serviceAccountName(), deployment.podName(), UUID.fromString(deployment.podUid()));
    }

    public KubernetesObserver.Evidence requireCurrent(RuntimePeer peer, AiRuntimeOperationBudget budget) {
        if (peer == null || peer.role() != RuntimePeerRole.CONTROLLER || !expected.equals(peer.subject())
                || budget == null || quarantined != null || !observing.compareAndSet(false, true)) {
            throw denied();
        }
        KubernetesApi api = null;
        try {
            api = source.api().open(budget.remaining());
            var evidence = KubernetesObserver
                    .observe(api, source.deployment(), KubernetesSnapshotVerifier.Stage.RUNNING);
            if (api.cleanupUncertain()) {
                throw denied();
            }
            budget.remaining();
            return evidence;
        } catch (Throwable unavailable) {
            throw denied();
        } finally {
            if (api != null && api.cleanupUncertain()) {
                quarantined = api;
            } else {
                observing.set(false);
            }
        }
    }

    private static AccessDeniedException denied() {
        return new AccessDeniedException("Current controller deployment required");
    }
}

package com.otilm.core.security.ai;

import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.model.ai.AiRuntimeGatewayState.Registration;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import com.otilm.core.service.writer.ai.AiRuntimeGatewayRegistrationWriter;
import java.util.Objects;
import java.util.Optional;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;

/** Requires current registered run-gateway identity in addition to the native transport certificate. */
@Component
@TraceMetadataOnly
public class AiRuntimeGatewayAuthority {
    private final AiRuntimeGatewayRegistrationWriter registrations;

    public AiRuntimeGatewayAuthority(AiRuntimeGatewayRegistrationWriter registrations) {
        this.registrations = Objects.requireNonNull(registrations);
    }

    public Registration requireCurrent(RuntimePeer peer, AiRuntimeOperationBudget budget) {
        if (peer == null || peer.role() != RuntimePeerRole.GATEWAY_RUN) {
            throw denied();
        }
        return current(peer, budget).orElseThrow(AiRuntimeGatewayAuthority::denied);
    }

    public Optional<Registration> current(RuntimePeer peer, AiRuntimeOperationBudget budget) {
        if (peer == null || peer.role() != RuntimePeerRole.GATEWAY_RUN) {
            throw denied();
        }
        return registrations.current(peer, budget);
    }

    private static AccessDeniedException denied() {
        return new AccessDeniedException("Current gateway registration required");
    }
}

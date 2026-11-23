package com.otilm.core.security.ai;

import com.otilm.core.aop.TraceMetadataOnly;
import com.otilm.core.model.ai.AiRuntimeManagementGatewayState.Registration;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import com.otilm.core.service.writer.ai.AiRuntimeManagementGatewayWriter;
import java.util.Objects;
import java.util.Optional;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;

/** Native transport membership only; the separate stored-session CONNECT check remains mandatory. */
@Component
@TraceMetadataOnly
public class AiRuntimeManagementGatewayAuthority {
    private final AiRuntimeManagementGatewayWriter registrations;

    public AiRuntimeManagementGatewayAuthority(AiRuntimeManagementGatewayWriter registrations) {
        this.registrations = Objects.requireNonNull(registrations);
    }

    public Registration requireCurrent(RuntimePeer peer, AiRuntimeOperationBudget budget) {
        if (peer == null || peer.role() != RuntimePeerRole.GATEWAY_MANAGEMENT) {
            throw denied();
        }
        return current(peer, budget).orElseThrow(AiRuntimeManagementGatewayAuthority::denied);
    }

    public Optional<Registration> current(RuntimePeer peer, AiRuntimeOperationBudget budget) {
        if (peer == null || peer.role() != RuntimePeerRole.GATEWAY_MANAGEMENT) {
            throw denied();
        }
        return registrations.current(peer, budget);
    }

    private static AccessDeniedException denied() {
        return new AccessDeniedException("Current management gateway required");
    }
}

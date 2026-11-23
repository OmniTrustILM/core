package com.otilm.core.security.ai;

import com.otilm.core.model.ai.AiRuntimeManagementGatewayState.Registration;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import com.otilm.core.service.writer.ai.AiRuntimeManagementGatewayWriter;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.security.access.AccessDeniedException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

/** Native transport registration boundary only; no model CONNECT or real workload attestation is mocked as accepted. */
class AiRuntimeManagementGatewayAuthorityTest {
    private final AiRuntimeManagementGatewayWriter writer = mock(AiRuntimeManagementGatewayWriter.class);
    private final AiRuntimeManagementGatewayAuthority authority = new AiRuntimeManagementGatewayAuthority(writer);
    private final RuntimeProxyCertificateClaims subject = new RuntimeProxyCertificateClaims("cluster-one", "ai-proof",
            "gateway-account", "management-gateway", UUID.randomUUID());

    @Test
    void exactManagementRoleStillRequiresActualCurrentPersistenceLookup() {
        var peer = new RuntimePeer(RuntimePeerRole.GATEWAY_MANAGEMENT, subject);
        var budget = AiRuntimeOperationBudget.start();
        var row = new Registration(subject, 1, 1, UUID.randomUUID(), Instant.parse("2030-01-01T00:00:00Z"));
        when(writer.current(peer, budget)).thenReturn(Optional.of(row));
        assertThat(authority.requireCurrent(peer, budget)).isSameAs(row);
        verify(writer).current(peer, budget);
        verifyNoMoreInteractions(writer);
    }

    @ParameterizedTest
    @EnumSource(value = RuntimePeerRole.class, names = "GATEWAY_MANAGEMENT", mode = EnumSource.Mode.EXCLUDE)
    void otherValidNativeRolesCannotBorrowManagementRegistration(RuntimePeerRole role) {
        var peer = new RuntimePeer(role, subject);
        var budget = AiRuntimeOperationBudget.start();
        assertThatThrownBy(() -> authority.requireCurrent(peer, budget))
                .isInstanceOf(AccessDeniedException.class)
                .hasNoCause();
        verifyNoInteractions(writer);
    }

    @Test
    void absentCurrentOrAbsentPeerFailsClosed() {
        var peer = new RuntimePeer(RuntimePeerRole.GATEWAY_MANAGEMENT, subject);
        var budget = AiRuntimeOperationBudget.start();
        when(writer.current(peer, budget)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> authority.requireCurrent(peer, budget))
                .isInstanceOf(AccessDeniedException.class)
                .hasNoCause();
        assertThatThrownBy(() -> authority.requireCurrent(null, budget))
                .isInstanceOf(AccessDeniedException.class)
                .hasNoCause();
        verify(writer).current(peer, budget);
        verifyNoMoreInteractions(writer);
    }
}

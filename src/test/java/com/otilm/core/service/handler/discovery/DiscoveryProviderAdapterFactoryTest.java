package com.otilm.core.service.handler.discovery;

import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.exception.UnsupportedDiscoveryVersionException;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Pins the factory's routing table: no association → v1, {@code "v2"} → v2, anything else refuses. */
class DiscoveryProviderAdapterFactoryTest {

    private DiscoveryProviderV1Adapter v1Adapter;
    private DiscoveryProviderV2Adapter v2Adapter;
    private ConnectorInterfaceRepository interfaceRepository;
    private DiscoveryProviderAdapterFactory factory;

    @BeforeEach
    void setUp() {
        v1Adapter = mock(DiscoveryProviderV1Adapter.class);
        v2Adapter = mock(DiscoveryProviderV2Adapter.class);
        interfaceRepository = mock(ConnectorInterfaceRepository.class);
        factory = new DiscoveryProviderAdapterFactory(v1Adapter, v2Adapter, interfaceRepository);
    }

    @Test
    void runWithoutInterfaceAssociationRoutesToV1() {
        Discovery run = new Discovery();

        assertThat(factory.forDiscovery(run)).isSameAs(v1Adapter);
    }

    @Test
    void unloadableRunRoutesToV1() {
        assertThat(factory.forDiscovery(null)).isSameAs(v1Adapter);
    }

    @Test
    void v2InterfaceRoutesToV2() {
        Discovery run = runWithInterfaceVersion("v2");

        assertThat(factory.forDiscovery(run)).isSameAs(v2Adapter);
    }

    @Test
    void routingOnTheAssociationAloneMatchesRoutingOnTheRun() {
        Discovery run = runWithInterfaceVersion("v2");

        // Dispatch takes this route so it never loads the run; it has to reach the same adapter as the entity one,
        // or the generation a run is driven by would depend on how it was dispatched.
        assertThat(factory.forConnectorInterface(run.getConnectorInterfaceUuid(), run.getUuid()))
                .isSameAs(factory.forDiscovery(run));
    }

    @Test
    void noAssociationRoutesToV1WithoutTouchingTheRepository() {
        assertThat(factory.forConnectorInterface(null, UUID.randomUUID())).isSameAs(v1Adapter);
        verifyNoInteractions(interfaceRepository);
    }

    @Test
    void unknownVersionRefuses() {
        Discovery run = runWithInterfaceVersion("v3");

        assertThatThrownBy(() -> factory.forDiscovery(run))
                .isInstanceOf(UnsupportedDiscoveryVersionException.class)
                .hasMessageContaining("v3");
    }

    @Test
    void nullInterfaceVersionRefusesWithTheDedicatedMessage() {
        Discovery run = runWithInterfaceVersion(null);

        assertThatThrownBy(() -> factory.forDiscovery(run))
                .isInstanceOf(UnsupportedDiscoveryVersionException.class)
                .hasMessageContaining("has no version");
    }

    @Test
    void missingInterfaceRowRefuses() {
        Discovery run = new Discovery();
        run.setConnectorInterfaceUuid(UUID.randomUUID());
        when(interfaceRepository.findById(any())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> factory.forDiscovery(run))
                .isInstanceOf(UnsupportedDiscoveryVersionException.class)
                .hasMessageContaining("not found");
    }

    private Discovery runWithInterfaceVersion(String version) {
        Discovery run = new Discovery();
        run.setConnectorInterfaceUuid(UUID.randomUUID());
        ConnectorInterfaceEntity iface = new ConnectorInterfaceEntity();
        iface.setVersion(version);
        when(interfaceRepository.findById(run.getConnectorInterfaceUuid())).thenReturn(Optional.of(iface));
        return run;
    }
}

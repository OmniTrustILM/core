package com.otilm.core.service.impl;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.authority.AuthorityInstanceRequestDto;
import com.otilm.api.model.client.authority.AuthorityInstanceUpdateRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.core.authority.AuthorityInstanceDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.connector.ConnectorDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.ConnectorService;
import com.otilm.core.service.CredentialInternalService;
import com.otilm.core.service.RaProfileService;
import com.otilm.core.service.ResourceInternalService;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapter;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapterFactory;
import com.otilm.core.client.ConnectorApiFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the v3-specific branch in
 * {@link AuthorityInstanceServiceImpl#createAuthorityInstance}.
 *
 * <p>The v3 path skips the legacy {@code createAuthorityInstance} connector call and instead
 * validates connectivity via {@link AuthorityProviderAdapter#checkAuthorityConnection}. These
 * tests verify the branch logic without a Spring application context.</p>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AuthorityInstanceServiceImplV3Test {

    @Mock private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Mock private ConnectorService connectorService;
    @Mock private CredentialInternalService credentialService;
    @Mock private ConnectorApiFactory connectorApiFactory;
    @Mock private RaProfileService raProfileService;
    @Mock private AttributeEngine attributeEngine;
    @Mock private ResourceInternalService resourceService;
    @Mock private ConnectorRepository connectorRepository;
    @Mock private AuthorityProviderAdapterFactory adapterFactory;
    @Mock private AuthorityProviderAdapter v3Adapter;

    @InjectMocks
    private AuthorityInstanceServiceImpl service;

    private UUID connectorUuid;
    private Connector connectorEntity;
    private ConnectorInterfaceEntity v3Iface;
    private ConnectorDto connectorDto;

    @BeforeEach
    void setUp() throws Exception {
        connectorUuid = UUID.randomUUID();

        v3Iface = new ConnectorInterfaceEntity();
        v3Iface.setInterfaceCode(ConnectorInterface.AUTHORITY);
        v3Iface.setVersion("v3");
        v3Iface.setConnectorUuid(connectorUuid);

        connectorEntity = new Connector();
        connectorEntity.setName("v3-connector");
        connectorEntity.getInterfaces().add(v3Iface);

        connectorDto = new ConnectorDto();
        connectorDto.setName("v3-connector");
        connectorDto.setUuid(connectorUuid.toString());
        connectorDto.setFunctionGroups(List.of());

        when(authorityInstanceReferenceRepository.findByName(any())).thenReturn(Optional.empty());
        when(connectorService.getConnector(any())).thenReturn(connectorDto);
        when(attributeEngine.getDataAttributesByContent(any(), any())).thenReturn(List.of());
        when(connectorRepository.findByUuid(connectorUuid)).thenReturn(Optional.of(connectorEntity));
        when(adapterFactory.forAuthority(any())).thenReturn(v3Adapter);

        // save returns the passed entity after assigning a UUID (simulates @PrePersist)
        when(authorityInstanceReferenceRepository.save(any())).thenAnswer(inv -> {
            com.otilm.core.dao.entity.AuthorityInstanceReference ref = inv.getArgument(0);
            if (ref.uuid == null) ref.uuid = UUID.randomUUID();
            return ref;
        });
        when(attributeEngine.updateObjectCustomAttributesContent(any(), any(), any())).thenReturn(List.of());
        when(attributeEngine.updateObjectDataAttributesContent(any(ObjectAttributeContentInfo.class), any())).thenReturn(List.of());
    }

    @Test
    void createV3AuthoritySkipsConnectorCreateCall() throws Exception {
        AuthorityInstanceRequestDto request = buildRequest();

        service.createAuthorityInstance(request);

        verify(connectorApiFactory, never()).getAuthorityInstanceApiClient(any());
    }

    @Test
    void createV3AuthorityCallsCheckAuthorityConnection() throws Exception {
        AuthorityInstanceRequestDto request = buildRequest();

        service.createAuthorityInstance(request);

        verify(v3Adapter).checkAuthorityConnection(any(), any());
    }

    @Test
    void createV3AuthoritySavesWithConnectorInterfaceUuid() throws Exception {
        UUID ifaceUuid = UUID.randomUUID();
        // Set UUID on the interface entity via reflection (UniquelyIdentified has a protected uuid field)
        java.lang.reflect.Field uuidField = findUuidField(ConnectorInterfaceEntity.class);
        uuidField.setAccessible(true);
        uuidField.set(v3Iface, ifaceUuid);

        AuthorityInstanceRequestDto request = buildRequest();

        service.createAuthorityInstance(request);

        ArgumentCaptor<com.otilm.core.dao.entity.AuthorityInstanceReference> captor =
                ArgumentCaptor.forClass(com.otilm.core.dao.entity.AuthorityInstanceReference.class);
        verify(authorityInstanceReferenceRepository).save(captor.capture());

        com.otilm.core.dao.entity.AuthorityInstanceReference saved = captor.getValue();
        assertThat(saved.getConnectorInterfaceUuid()).isEqualTo(ifaceUuid);
    }

    @Test
    void createV3AuthorityReturnsDto() throws Exception {
        AuthorityInstanceRequestDto request = buildRequest();

        AuthorityInstanceDto result = service.createAuthorityInstance(request);

        assertThat(result).isNotNull();
        assertThat(result.getName()).isEqualTo(request.getName());
    }

    @Test
    void createV3AuthorityReturnsDtoWithConnectorAndInterface() throws Exception {
        AuthorityInstanceDto result = service.createAuthorityInstance(buildRequest());

        assertThat(result.getConnector()).isNotNull();
        assertThat(result.getConnector().getName()).isEqualTo("v3-connector");
        assertThat(result.getConnectorInterface()).isNotNull();
        assertThat(result.getConnectorInterface().getVersion()).isEqualTo("v3");
    }

    @Test
    void createV3AuthorityValidatesAttributesAgainstV3Definitions() throws Exception {
        List<BaseAttribute> definitions = List.of(mock(BaseAttribute.class));
        when(v3Adapter.listAuthorityInstanceAttributes(any())).thenReturn(definitions);

        service.createAuthorityInstance(buildRequest());

        // v3 has no connector-side /validate: Core validates locally against the definitions
        // the adapter lists from the v3 attributes endpoint.
        verify(attributeEngine).validateUpdateDataAttributes(eq(connectorUuid), any(), eq(definitions), any());
    }

    @Test
    void editV3AuthorityReprobesAndSkipsConnectorUpdateCall() throws Exception {
        com.otilm.core.dao.entity.AuthorityInstanceReference existing =
                new com.otilm.core.dao.entity.AuthorityInstanceReference();
        existing.uuid = UUID.randomUUID();
        existing.setName("v3-authority");
        existing.setKind("ApiKey");
        existing.setConnectorUuid(connectorUuid);
        existing.setConnectorInterface(v3Iface);
        when(authorityInstanceReferenceRepository.findByUuid(any(SecuredUUID.class)))
                .thenReturn(Optional.of(existing));

        AuthorityInstanceUpdateRequestDto request = new AuthorityInstanceUpdateRequestDto();
        request.setAttributes(List.of());
        request.setCustomAttributes(List.of());

        service.editAuthorityInstance(SecuredUUID.fromUUID(existing.uuid), request);

        verify(connectorApiFactory, never()).getAuthorityInstanceApiClient(any()); // no connector update endpoint
        verify(v3Adapter).checkAuthorityConnection(any(), any());                  // re-probe instead
        verify(authorityInstanceReferenceRepository).save(existing);
    }

    @Test
    void createV3AuthorityWithExplicitInterfaceUuidSelectsThatInterface() throws Exception {
        UUID ifaceUuid = UUID.randomUUID();
        java.lang.reflect.Field uuidField = findUuidField(ConnectorInterfaceEntity.class);
        uuidField.setAccessible(true);
        uuidField.set(v3Iface, ifaceUuid);

        AuthorityInstanceRequestDto request = buildRequest();
        request.setInterfaceUuid(ifaceUuid);

        AuthorityInstanceDto result = service.createAuthorityInstance(request);

        assertThat(result).isNotNull();
        verify(v3Adapter).checkAuthorityConnection(any(), any());
    }

    @Test
    void createRejectsUnknownInterfaceUuid() throws Exception {
        AuthorityInstanceRequestDto request = buildRequest();
        request.setInterfaceUuid(UUID.randomUUID()); // not present on the connector

        assertThatThrownBy(() -> service.createAuthorityInstance(request))
                .isInstanceOf(ValidationException.class);
    }

    @Test
    void createRejectsMultipleAuthorityInterfacesWithoutInterfaceUuid() throws Exception {
        ConnectorInterfaceEntity secondIface = new ConnectorInterfaceEntity();
        secondIface.setInterfaceCode(ConnectorInterface.AUTHORITY);
        secondIface.setVersion("v2");
        secondIface.setConnectorUuid(connectorUuid);
        connectorEntity.getInterfaces().add(secondIface);

        AuthorityInstanceRequestDto request = buildRequest(); // no interfaceUuid → ambiguous

        assertThatThrownBy(() -> service.createAuthorityInstance(request))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("multiple AUTHORITY interfaces");
    }

    // ---- helpers ----

    private AuthorityInstanceRequestDto buildRequest() throws Exception {
        AuthorityInstanceRequestDto req = new AuthorityInstanceRequestDto();
        req.setName("v3-authority");
        req.setConnectorUuid(connectorUuid.toString());
        req.setKind("ApiKey");
        req.setAttributes(List.of());
        req.setCustomAttributes(List.of());
        return req;
    }

    /**
     * Finds the {@code uuid} field by walking the class hierarchy. The field lives in
     * {@code UniquelyIdentified} which is a grandparent of {@code ConnectorInterfaceEntity}.
     */
    private java.lang.reflect.Field findUuidField(Class<?> clazz) {
        Class<?> current = clazz;
        while (current != null) {
            try {
                return current.getDeclaredField("uuid");
            } catch (NoSuchFieldException e) {
                current = current.getSuperclass();
            }
        }
        throw new IllegalStateException("Could not find 'uuid' field in hierarchy of " + clazz.getName());
    }
}

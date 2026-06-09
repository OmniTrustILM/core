package com.czertainly.core.service.impl;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.authority.AuthorityInstanceRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.core.authority.AuthorityInstanceDto;
import com.otilm.api.model.core.connector.ConnectorDto;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.api.model.core.connector.FunctionGroupDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.ConnectorInterfaceEntity;
import com.czertainly.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.czertainly.core.dao.repository.ConnectorRepository;
import com.czertainly.core.service.ConnectorService;
import com.czertainly.core.service.CredentialService;
import com.czertainly.core.service.RaProfileService;
import com.czertainly.core.service.ResourceInternalService;
import com.czertainly.core.service.handler.authority.AuthorityProviderAdapter;
import com.czertainly.core.service.handler.authority.AuthorityProviderAdapterFactory;
import com.czertainly.core.client.ConnectorApiFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
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
class AuthorityInstanceServiceImplV3Test {

    @Mock private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Mock private ConnectorService connectorService;
    @Mock private CredentialService credentialService;
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

        Set<ConnectorInterfaceEntity> interfaces = new HashSet<>();
        interfaces.add(v3Iface);

        connectorEntity = new Connector();
        connectorEntity.setName("v3-connector");

        // Use reflection to set interfaces (field is populated via Hibernate in prod, not a setter)
        java.lang.reflect.Field ifacesField = Connector.class.getDeclaredField("interfaces");
        ifacesField.setAccessible(true);
        ifacesField.set(connectorEntity, interfaces);

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
            com.czertainly.core.dao.entity.AuthorityInstanceReference ref = inv.getArgument(0);
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

        ArgumentCaptor<com.czertainly.core.dao.entity.AuthorityInstanceReference> captor =
                ArgumentCaptor.forClass(com.czertainly.core.dao.entity.AuthorityInstanceReference.class);
        verify(authorityInstanceReferenceRepository).save(captor.capture());

        com.czertainly.core.dao.entity.AuthorityInstanceReference saved = captor.getValue();
        assertThat(saved.getConnectorInterfaceUuid()).isEqualTo(ifaceUuid);
    }

    @Test
    void createV3AuthorityReturnsDto() throws Exception {
        AuthorityInstanceRequestDto request = buildRequest();

        AuthorityInstanceDto result = service.createAuthorityInstance(request);

        assertThat(result).isNotNull();
        assertThat(result.getName()).isEqualTo(request.getName());
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

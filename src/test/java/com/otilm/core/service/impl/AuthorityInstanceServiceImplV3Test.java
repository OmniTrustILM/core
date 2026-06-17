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
import com.otilm.core.dao.entity.AuthorityInstanceReference;
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
import static org.mockito.Mockito.doThrow;
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
            AuthorityInstanceReference ref = inv.getArgument(0);
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
        v3Iface.setUuid(ifaceUuid);

        AuthorityInstanceRequestDto request = buildRequest();

        service.createAuthorityInstance(request);

        ArgumentCaptor<AuthorityInstanceReference> captor =
                ArgumentCaptor.forClass(AuthorityInstanceReference.class);
        verify(authorityInstanceReferenceRepository).save(captor.capture());

        AuthorityInstanceReference saved = captor.getValue();
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
        AuthorityInstanceReference existing =
                new AuthorityInstanceReference();
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
        v3Iface.setUuid(ifaceUuid);

        AuthorityInstanceRequestDto request = buildRequest();
        request.setInterfaceUuid(ifaceUuid);

        AuthorityInstanceDto result = service.createAuthorityInstance(request);

        assertThat(result).isNotNull();
        verify(v3Adapter).checkAuthorityConnection(any(), any());
    }

    @Test
    void createV3AuthorityFallsBackToSoleAuthorityInterfaceWhenNoInterfaceUuid() throws Exception {
        // exactly one AUTHORITY interface + no interfaceUuid → the sole interface is selected
        ArgumentCaptor<AuthorityInstanceReference> captor =
                ArgumentCaptor.forClass(AuthorityInstanceReference.class);

        service.createAuthorityInstance(buildRequest());

        verify(authorityInstanceReferenceRepository).save(captor.capture());
        assertThat(captor.getValue().getConnectorInterface()).isSameAs(v3Iface);
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

    @Test
    void getV3AuthorityReturnsLocalWithoutConnectorCall() throws Exception {
        AuthorityInstanceReference existing = v3AuthorityEntity();
        existing.setConnector(connectorEntity); // non-null connector → not the "deleted" branch
        when(authorityInstanceReferenceRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(existing));
        when(attributeEngine.getObjectDataAttributesContent(any(ObjectAttributeContentInfo.class))).thenReturn(List.of());
        when(attributeEngine.getObjectCustomAttributesContent(any(), any())).thenReturn(List.of());

        AuthorityInstanceDto result = service.getAuthorityInstance(SecuredUUID.fromUUID(existing.uuid));

        assertThat(result).isNotNull();
        verify(connectorApiFactory, never()).getAuthorityInstanceApiClient(any()); // v3 stateless — no connector detail fetch
    }

    @Test
    void deleteV3AuthoritySkipsConnectorRemoveCall() throws Exception {
        AuthorityInstanceReference existing = v3AuthorityEntity();
        existing.setConnector(connectorEntity);
        when(authorityInstanceReferenceRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(existing));

        service.deleteAuthorityInstance(SecuredUUID.fromUUID(existing.uuid));

        verify(connectorApiFactory, never()).getAuthorityInstanceApiClient(any()); // v3 stateless — no connector delete
        verify(authorityInstanceReferenceRepository).delete(existing);
    }

    @Test
    void listProfilesReturnEmptyForV3() throws Exception {
        AuthorityInstanceReference existing = v3AuthorityEntity();
        when(authorityInstanceReferenceRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(existing));
        SecuredUUID id = SecuredUUID.fromUUID(existing.uuid);

        assertThat(service.listEndEntityProfiles(id)).isEmpty();
        assertThat(service.listCertificateProfiles(id, 1)).isEmpty();
        assertThat(service.listCAsInProfile(id, 1)).isEmpty();
        verify(connectorApiFactory, never()).getEndEntityProfileApiClient(any());
    }

    @Test
    void listRAProfileAttributesRoutesThroughAdapterForV3() throws Exception {
        AuthorityInstanceReference existing = v3AuthorityEntity();
        when(authorityInstanceReferenceRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(existing));
        List<BaseAttribute> definitions = List.of(mock(BaseAttribute.class));
        when(v3Adapter.listRaProfileAttributes(existing)).thenReturn(definitions);

        assertThat(service.listRAProfileAttributes(SecuredUUID.fromUUID(existing.uuid))).isSameAs(definitions);
    }

    @Test
    void validateRAProfileAttributesValidatesLocallyForV3() throws Exception {
        AuthorityInstanceReference existing = v3AuthorityEntity();
        when(authorityInstanceReferenceRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(existing));
        when(v3Adapter.listRaProfileAttributes(existing)).thenReturn(List.of());

        Boolean valid = service.validateRAProfileAttributes(SecuredUUID.fromUUID(existing.uuid), List.of());

        assertThat(valid).isTrue();
        verify(attributeEngine).validateUpdateDataAttributes(eq(connectorUuid), any(), any(), any());
    }

    @Test
    void validateRAProfileAttributesPropagatesInvalidContentForV3() throws Exception {
        AuthorityInstanceReference existing = v3AuthorityEntity();
        when(authorityInstanceReferenceRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(existing));
        when(v3Adapter.listRaProfileAttributes(existing)).thenReturn(List.of());
        doThrow(new ValidationException("invalid")).when(attributeEngine)
                .validateUpdateDataAttributes(any(), any(), any(), any());

        assertThatThrownBy(() -> service.validateRAProfileAttributes(SecuredUUID.fromUUID(existing.uuid), List.of()))
                .isInstanceOf(ValidationException.class);
    }

    @Test
    void validateRAProfileAttributesToleratesNullAttributesForV3() throws Exception {
        AuthorityInstanceReference existing = v3AuthorityEntity();
        when(authorityInstanceReferenceRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(existing));
        when(v3Adapter.listRaProfileAttributes(existing)).thenReturn(List.of());

        assertThat(service.validateRAProfileAttributes(SecuredUUID.fromUUID(existing.uuid), null)).isTrue();
    }

    // ---- helpers ----

    private AuthorityInstanceRequestDto buildRequest() {
        AuthorityInstanceRequestDto req = new AuthorityInstanceRequestDto();
        req.setName("v3-authority");
        req.setConnectorUuid(connectorUuid.toString());
        req.setKind("ApiKey");
        req.setAttributes(List.of());
        req.setCustomAttributes(List.of());
        return req;
    }

    private AuthorityInstanceReference v3AuthorityEntity() {
        AuthorityInstanceReference ref = new AuthorityInstanceReference();
        ref.uuid = UUID.randomUUID();
        ref.setName("v3-authority");
        ref.setKind("ApiKey");
        ref.setConnectorUuid(connectorUuid);
        ref.setConnectorInterface(v3Iface);
        return ref;
    }
}

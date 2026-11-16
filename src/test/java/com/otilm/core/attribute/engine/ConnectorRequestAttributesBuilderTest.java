package com.otilm.core.attribute.engine;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.ResponseAttributeV3;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.AttributeVersion;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.ResourceObjectContent;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSecretContentData;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSimpleContentData;
import com.otilm.api.model.core.auth.AttributeResource;
import com.otilm.core.service.CredentialInternalService;
import com.otilm.core.service.ResourceInternalService;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ConnectorRequestAttributesBuilderTest {

    @Mock
    private AttributeEngine attributeEngine;
    @Mock
    private ResourceInternalService resourceService;
    @Mock
    private CredentialInternalService credentialService;

    private ConnectorRequestAttributesBuilder builder;

    @BeforeEach
    void setUp() {
        builder = new ConnectorRequestAttributesBuilder();
        builder.setAttributeEngine(attributeEngine);
        builder.setResourceService(resourceService);
        builder.setCredentialService(credentialService);
    }

    @Test
    void dereferenceForConnectorRequestResolvesReferencesWithoutRevalidating() throws Exception {
        // The operation path re-reads already-stored, already-validated attributes for a connector request. It must
        // dereference CREDENTIAL + RESOURCE (incl. SECRET) content in place — the same system-mode load the callback
        // path performs — but must NOT re-run validateUpdateDataAttributes (no definitions, no drift re-check).
        UUID connectorUuid = UUID.randomUUID();
        List<RequestAttribute> stored = List.of();
        List<DataAttribute> resolved = List.of(credentialAttribute());
        when(attributeEngine.getDataAttributesByContent(connectorUuid, stored)).thenReturn(resolved);

        List<RequestAttribute> result = builder.dereferenceForConnectorRequest(connectorUuid, stored);

        InOrder order = inOrder(attributeEngine, credentialService, resourceService);
        order.verify(attributeEngine).getDataAttributesByContent(connectorUuid, stored);
        order.verify(credentialService).loadFullCredentialData(resolved);
        order.verify(resourceService).loadResourceObjectContentData(resolved);
        verify(attributeEngine, never()).validateUpdateDataAttributes(any(), any(), any(), any());
        // getClientAttributes maps to fresh instances without value equality, so compare what identifies them.
        assertEquals(resolved.stream().map(DataAttribute::getName).toList(),
                result.stream().map(RequestAttribute::getName).toList());
    }

    @Test
    void aRequestNamingNoCredentialDoesNotReachTheCredentialLoader() throws Exception {
        // That loader authorizes CREDENTIAL:DETAIL at method entry and would then walk past every attribute here,
        // so calling it would charge the caller a permission for work that never happens.
        UUID connectorUuid = UUID.randomUUID();
        List<RequestAttribute> stored = List.of();
        List<DataAttribute> resolved = List.of(secretAttribute());
        when(attributeEngine.getDataAttributesByContent(connectorUuid, stored)).thenReturn(resolved);

        builder.dereferenceForConnectorRequest(connectorUuid, stored);

        verify(credentialService, never()).loadFullCredentialData(any());
        verify(resourceService).loadResourceObjectContentData(resolved);
    }

    @Test
    void resolvesTheSecretOfAReferencedAuthority_whenTheAuthorityBelongsToTheConnector() throws Exception {
        // given
        UUID connectorUuid = UUID.randomUUID();
        UUID authorityUuid = UUID.randomUUID();
        UUID secretUuid = UUID.randomUUID();
        List<RequestAttribute> stored = List.of();
        when(attributeEngine.getDataAttributesByContent(connectorUuid, stored))
                .thenReturn(List.of(loadedAuthorityHolding(authorityUuid, secretUuid)));
        when(resourceService.findOwningConnector(AttributeResource.AUTHORITY, authorityUuid))
                .thenReturn(Optional.of(connectorUuid));
        ResourceSecretContentData secretContent = new ResourceSecretContentData();
        when(resourceService.loadReferencedObjectContent(AttributeResource.SECRET, secretUuid))
                .thenReturn(secretContent);

        // when
        List<RequestAttribute> sent = builder.dereferenceWithNestedReferencesForConnectorRequest(connectorUuid, stored);

        // then
        List<?> authorityContent = sent.getFirst().getContent();
        ResourceSimpleContentData authority = (ResourceSimpleContentData) ((ResourceObjectContent) authorityContent
                .getFirst()).getData();
        List<?> oauthClient = authority.getAttributes().getFirst().getContent();
        assertThat(((ResourceObjectContent) oauthClient.getFirst()).getData()).isSameAs(secretContent);
    }

    @Test
    void refusesBeforeLoading_whenADiscoveryRefersToAnAuthorityOfAnotherConnector() throws Exception {
        // given
        UUID connectorUuid = UUID.randomUUID();
        UUID authorityUuid = UUID.randomUUID();
        List<RequestAttribute> stored = List.of();
        when(attributeEngine.getDataAttributesByContent(connectorUuid, stored))
                .thenReturn(List.of(loadedAuthorityHolding(authorityUuid, UUID.randomUUID())));
        var anotherConnector = UUID.randomUUID();
        when(resourceService.findOwningConnector(AttributeResource.AUTHORITY, authorityUuid))
                .thenReturn(Optional.of(anotherConnector));

        // when
        ThrowingCallable dereference = () -> builder
                .dereferenceWithNestedReferencesForConnectorRequest(connectorUuid, stored);

        // then
        assertThatThrownBy(dereference)
                .isInstanceOf(ForeignReferenceException.class)
                .hasMessageContaining(
                        "Attribute 'authority' refers to Authority 'otpki', which belongs to another " + "connector");
        verify(resourceService, never()).loadResourceObjectContentData(any());
        verify(resourceService, never()).loadReferencedObjectContent(any(), any());
    }

    @Test
    void refusesBeforeLoading_whenTheValueIsLabelledAsAnotherKindThanTheAttributeDeclares() throws Exception {
        // given
        UUID connectorUuid = UUID.randomUUID();
        UUID authorityUuid = UUID.randomUUID();
        List<RequestAttribute> stored = List.of();
        DataAttribute authorityLabelledAsCertificate = loadedObjectHolding(AttributeResource.CERTIFICATE, authorityUuid,
                UUID.randomUUID());
        when(attributeEngine.getDataAttributesByContent(connectorUuid, stored))
                .thenReturn(List.of(authorityLabelledAsCertificate));
        when(resourceService.findOwningConnector(AttributeResource.AUTHORITY, authorityUuid))
                .thenReturn(Optional.of(UUID.randomUUID()));

        // when
        ThrowingCallable dereference = () -> builder.dereferenceForConnectorRequest(connectorUuid, stored);

        // then
        assertThatThrownBy(dereference).isInstanceOf(ForeignReferenceException.class);
        verify(resourceService, never()).loadResourceObjectContentData(any());
    }

    @Test
    void refusesBeforeLoading_whenAnOperationRefersToAnAuthorityOfAnotherConnector() throws Exception {
        // given
        UUID connectorUuid = UUID.randomUUID();
        UUID authorityUuid = UUID.randomUUID();
        List<RequestAttribute> stored = List.of();
        when(attributeEngine.getDataAttributesByContent(connectorUuid, stored))
                .thenReturn(List.of(loadedAuthorityHolding(authorityUuid, UUID.randomUUID())));
        when(resourceService.findOwningConnector(AttributeResource.AUTHORITY, authorityUuid))
                .thenReturn(Optional.of(UUID.randomUUID()));

        // when
        ThrowingCallable dereference = () -> builder.dereferenceForConnectorRequest(connectorUuid, stored);

        // then
        assertThatThrownBy(dereference).isInstanceOf(ForeignReferenceException.class);
        verify(resourceService, never()).loadResourceObjectContentData(any());
    }

    @Test
    void leavesNestedReferencesAlone_whenDereferencingOneLevel() throws Exception {
        // given
        UUID connectorUuid = UUID.randomUUID();
        List<RequestAttribute> stored = List.of();
        when(attributeEngine.getDataAttributesByContent(connectorUuid, stored))
                .thenReturn(List.of(loadedAuthorityHolding(UUID.randomUUID(), UUID.randomUUID())));

        // when
        builder.dereferenceForConnectorRequest(connectorUuid, stored);

        // then
        verify(resourceService, never()).loadReferencedObjectContent(any(), any());
    }

    @Test
    void leavesNestedReferencesAlone_whenPreparingARequestAsTheCaller() throws Exception {
        // given
        UUID connectorUuid = UUID.randomUUID();
        List<RequestAttribute> submitted = List.of();
        when(attributeEngine.getDataAttributesByContent(connectorUuid, submitted))
                .thenReturn(List.of(loadedAuthorityHolding(UUID.randomUUID(), UUID.randomUUID())));

        // when
        builder.prepareRequestAttributesForConnectorRequest(connectorUuid, List.of(), submitted);

        // then
        verify(resourceService, never()).loadReferencedObjectContent(any(), any());
    }

    private static DataAttribute credentialAttribute() {
        return attributeOfType(AttributeContentType.CREDENTIAL);
    }

    private static DataAttribute secretAttribute() {
        return attributeOfType(AttributeContentType.RESOURCE);
    }

    /** A request's authority reference as the depth-0 loader leaves it: loaded, its OAuth client still bare. */
    private static DataAttribute loadedAuthorityHolding(UUID authorityUuid, UUID secretUuid) {
        return loadedObjectHolding(AttributeResource.AUTHORITY, authorityUuid, secretUuid);
    }

    /** As {@link #loadedAuthorityHolding}, with the value labelled as the given kind. */
    private static DataAttribute loadedObjectHolding(AttributeResource labelledKind, UUID authorityUuid,
            UUID secretUuid) {
        List<BaseAttributeContentV3<?>> oauthClient = new ArrayList<>();
        oauthClient
                .add(new ResourceObjectContent("oauth-client",
                        new ResourceSecretContentData(secretUuid.toString(), "oauth-client", null)));
        ResourceSimpleContentData authority = new ResourceSimpleContentData(labelledKind, authorityUuid.toString(),
                "otpki",
                new ArrayList<>(List
                        .of(new ResponseAttributeV3(oauthClient, UUID.randomUUID(), "oauthClient", "OAuth client",
                                AttributeType.DATA, AttributeContentType.RESOURCE, AttributeVersion.V3))));
        List<BaseAttributeContentV3<?>> content = new ArrayList<>();
        content.add(new ResourceObjectContent("otpki", authority));
        DataAttributeV3 attribute = new DataAttributeV3();
        attribute.setUuid(UUID.randomUUID().toString());
        attribute.setName("authority");
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.RESOURCE);
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setResource(AttributeResource.AUTHORITY);
        attribute.setProperties(properties);
        attribute.setContent(content);
        return attribute;
    }

    private static DataAttribute attributeOfType(AttributeContentType contentType) {
        DataAttributeV2 attribute = new DataAttributeV2();
        attribute.setUuid(UUID.randomUUID().toString());
        attribute.setName("reference");
        attribute.setContentType(contentType);
        return attribute;
    }
}

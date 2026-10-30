package com.otilm.core.attribute.engine;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.core.service.CredentialInternalService;
import com.otilm.core.service.ResourceInternalService;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

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

    private static DataAttribute credentialAttribute() {
        return attributeOfType(AttributeContentType.CREDENTIAL);
    }

    private static DataAttribute secretAttribute() {
        return attributeOfType(AttributeContentType.RESOURCE);
    }

    private static DataAttribute attributeOfType(AttributeContentType contentType) {
        DataAttributeV2 attribute = new DataAttributeV2();
        attribute.setUuid(UUID.randomUUID().toString());
        attribute.setName("reference");
        attribute.setContentType(contentType);
        return attribute;
    }
}

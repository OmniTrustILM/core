package com.otilm.core.attribute.engine;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.core.service.CredentialInternalService;
import com.otilm.core.service.ResourceInternalService;
import com.otilm.core.util.AttributeDefinitionUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.UUID;

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
        List<DataAttribute> resolved = List.of();
        when(attributeEngine.getDataAttributesByContent(connectorUuid, stored)).thenReturn(resolved);

        List<RequestAttribute> result = builder.dereferenceForConnectorRequest(connectorUuid, stored);

        InOrder order = inOrder(attributeEngine, credentialService, resourceService);
        order.verify(attributeEngine).getDataAttributesByContent(connectorUuid, stored);
        order.verify(credentialService).loadFullCredentialData(resolved);
        order.verify(resourceService).loadResourceObjectContentData(resolved);
        verify(attributeEngine, never()).validateUpdateDataAttributes(any(), any(), any(), any());
        assertEquals(AttributeDefinitionUtils.getClientAttributes(resolved), result);
    }
}

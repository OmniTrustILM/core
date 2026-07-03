package com.otilm.core.service.handler;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.core.attribute.engine.ConnectorRequestAttributesBuilder;
import com.otilm.core.util.AuthHelper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OperationAttributeResolverTest {

    @Mock
    private AuthHelper authHelper;
    @Mock
    private ConnectorRequestAttributesBuilder connectorRequestAttributesBuilder;

    @InjectMocks
    private OperationAttributeResolver resolver;

    @BeforeEach
    void runElevationInline() {
        // runAsSystem executes the supplier inline here, so these tests exercise the resolver's composition and
        // exception mapping without the real elevation (that is covered by AuthHelperTest).
        doAnswer(inv -> {
            AuthHelper.ThrowingSupplier<?, ?> supplier = inv.getArgument(1);
            return supplier.get();
        }).when(authHelper).runAsSystem(anyString(), any());
    }

    @Test
    void resolvesUnderTheAttributeResolverIdentity() throws Exception {
        UUID connectorUuid = UUID.randomUUID();
        List<RequestAttribute> stored = List.of();
        List<RequestAttribute> resolved = List.of(mock(RequestAttribute.class));
        when(connectorRequestAttributesBuilder.dereferenceForConnectorRequest(connectorUuid, stored)).thenReturn(resolved);

        List<RequestAttribute> out = resolver.resolveForConnectorRequestAsSystem(connectorUuid, stored);

        assertSame(resolved, out, "the resolver must return the dereferenced attributes");
        verify(authHelper).runAsSystem(eq(AuthHelper.ATTRIBUTE_RESOLVER_USERNAME), any());
    }

    @Test
    void wrapsUnresolvableReferenceValidationAsConnectorException() throws Exception {
        UUID connectorUuid = UUID.randomUUID();
        List<RequestAttribute> stored = List.of();
        // a disabled/invalid-state secret or vault profile throws an unchecked ValidationException from the deref
        when(connectorRequestAttributesBuilder.dereferenceForConnectorRequest(connectorUuid, stored))
                .thenThrow(new ValidationException("Secret is not enabled"));

        assertThrows(ConnectorException.class,
                () -> resolver.resolveForConnectorRequestAsSystem(connectorUuid, stored));
    }

    @Test
    void wrapsCheckedResolutionFailureAsConnectorException() throws Exception {
        UUID connectorUuid = UUID.randomUUID();
        List<RequestAttribute> stored = List.of();
        when(connectorRequestAttributesBuilder.dereferenceForConnectorRequest(connectorUuid, stored))
                .thenThrow(new AttributeException("bad reference"));

        assertThrows(ConnectorException.class,
                () -> resolver.resolveForConnectorRequestAsSystem(connectorUuid, stored));
    }
}

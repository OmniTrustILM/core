package com.otilm.core.service.handler;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.core.attribute.engine.ConnectorRequestAttributesBuilder;
import com.otilm.core.util.AuthHelper;
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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OperationAttributeResolverTest {

    @Mock
    private AuthHelper authHelper;
    @Mock
    private ConnectorRequestAttributesBuilder connectorRequestAttributesBuilder;

    @InjectMocks
    private OperationAttributeResolver resolver;

    // runAsSystem executes the supplier inline, so the elevation-path tests exercise the resolver's composition and
    // exception mapping without the real elevation (that is covered by AuthHelperTest). Called only by the tests that
    // actually elevate — the short-circuit test must not reach runAsSystem, and stubbing it there would trip
    // strict-stubbing detection.
    private void runElevationInline() {
        doAnswer(inv -> {
            AuthHelper.ThrowingSupplier<?, ?> supplier = inv.getArgument(1);
            return supplier.get();
        }).when(authHelper).runAsSystem(anyString(), any());
    }

    private static RequestAttribute referenceAttribute() {
        RequestAttribute attribute = mock(RequestAttribute.class);
        when(attribute.getContentType()).thenReturn(AttributeContentType.RESOURCE);
        return attribute;
    }

    @Test
    void resolvesUnderTheContentResolverIdentityWhenAReferenceIsPresent() throws Exception {
        runElevationInline();
        UUID connectorUuid = UUID.randomUUID();
        List<RequestAttribute> stored = List.of(referenceAttribute());
        List<RequestAttribute> resolved = List.of(mock(RequestAttribute.class));
        when(connectorRequestAttributesBuilder.dereferenceForConnectorRequest(connectorUuid, stored)).thenReturn(resolved);

        List<RequestAttribute> out = resolver.resolveForConnectorRequestAsSystem(connectorUuid, stored);

        assertSame(resolved, out, "the resolver must return the dereferenced attributes");
        verify(authHelper).runAsSystem(eq(AuthHelper.ATTRIBUTE_CONTENT_RESOLVER_USERNAME), any());
    }

    @Test
    void returnsStoredUnchangedWithoutElevatingWhenNoReferencePresent() throws Exception {
        UUID connectorUuid = UUID.randomUUID();
        RequestAttribute plain = mock(RequestAttribute.class);
        when(plain.getContentType()).thenReturn(AttributeContentType.STRING);
        List<RequestAttribute> stored = List.of(plain);

        List<RequestAttribute> out = resolver.resolveForConnectorRequestAsSystem(connectorUuid, stored);

        assertSame(stored, out, "reference-free attributes must pass through unchanged");
        verify(authHelper, never()).runAsSystem(anyString(), any());
        verifyNoInteractions(connectorRequestAttributesBuilder);
    }

    @Test
    void propagatesConnectorExceptionFromDerefUnwrapped() throws Exception {
        // ConnectorException is the one checked type deliberately NOT caught in the lambda, so a ConnectorException
        // from the deref must pass through as the same instance, not be re-wrapped in another ConnectorException.
        runElevationInline();
        UUID connectorUuid = UUID.randomUUID();
        List<RequestAttribute> stored = List.of(referenceAttribute());
        ConnectorException original = new ConnectorException("connector unreachable");
        when(connectorRequestAttributesBuilder.dereferenceForConnectorRequest(connectorUuid, stored))
                .thenThrow(original);

        ConnectorException thrown = assertThrows(ConnectorException.class,
                () -> resolver.resolveForConnectorRequestAsSystem(connectorUuid, stored));
        assertSame(original, thrown, "a ConnectorException from the deref must propagate unwrapped, not double-wrapped");
    }

    @Test
    void wrapsUnresolvableReferenceValidationAsConnectorException() throws Exception {
        runElevationInline();
        UUID connectorUuid = UUID.randomUUID();
        List<RequestAttribute> stored = List.of(referenceAttribute());
        // a disabled/invalid-state secret or vault profile throws an unchecked ValidationException from the deref
        when(connectorRequestAttributesBuilder.dereferenceForConnectorRequest(connectorUuid, stored))
                .thenThrow(new ValidationException("Secret is not enabled"));

        assertThrows(ConnectorException.class,
                () -> resolver.resolveForConnectorRequestAsSystem(connectorUuid, stored));
    }

    @Test
    void wrapsCheckedResolutionFailureAsConnectorException() throws Exception {
        runElevationInline();
        UUID connectorUuid = UUID.randomUUID();
        List<RequestAttribute> stored = List.of(referenceAttribute());
        when(connectorRequestAttributesBuilder.dereferenceForConnectorRequest(connectorUuid, stored))
                .thenThrow(new AttributeException("bad reference"));

        assertThrows(ConnectorException.class,
                () -> resolver.resolveForConnectorRequestAsSystem(connectorUuid, stored));
    }
}

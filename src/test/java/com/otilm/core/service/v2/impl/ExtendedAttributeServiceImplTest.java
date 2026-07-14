package com.otilm.core.service.v2.impl;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeOperation;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Connector2FunctionGroup;
import com.otilm.core.dao.entity.FunctionGroup;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapter;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapterFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ExtendedAttributeServiceImplTest {

    @Mock
    ConnectorRepository connectorRepository;
    @Mock
    AuthorityProviderAdapterFactory adapterFactory;
    @Mock
    AuthorityProviderAdapter adapter;
    @Mock
    AttributeEngine attributeEngine;

    @InjectMocks
    ExtendedAttributeServiceImpl service;

    private Connector connector;
    private AuthorityInstanceReference authority;
    private RaProfile raProfile;

    @BeforeEach
    void setUp() {
        connector = new Connector();
        connector.setUuid(UUID.randomUUID());

        authority = new AuthorityInstanceReference();
        authority.setUuid(UUID.randomUUID());
        authority.setConnector(connector);

        raProfile = new RaProfile();
        raProfile.setUuid(UUID.randomUUID());
        raProfile.setAuthorityInstanceReference(authority);

        // Lenient: the connector-missing and legacy-rejection tests never reach the factory.
        lenient().when(adapterFactory.forAuthority(authority)).thenReturn(adapter);
    }

    // --- listIssueCertificateAttributes ---

    @Test
    void listIssueCertificateAttributes_delegatesToAdapter() throws Exception {
        List<BaseAttribute> expected = List.of(mock(BaseAttribute.class));
        when(adapter.listIssueAttributes(authority, raProfile)).thenReturn(expected);

        assertSame(expected, service.listIssueCertificateAttributes(raProfile));
    }

    @Test
    void listIssueCertificateAttributes_throwsWhenConnectorMissing() {
        authority.setConnector(null);

        assertThrows(NotFoundException.class, () -> service.listIssueCertificateAttributes(raProfile));
        verifyNoInteractions(adapterFactory);
    }

    @Test
    void listIssueCertificateAttributes_rejectsLegacyConnector() {
        FunctionGroup functionGroup = new FunctionGroup();
        Connector2FunctionGroup c2fg = new Connector2FunctionGroup();
        c2fg.setFunctionGroup(functionGroup);
        connector.getFunctionGroups().add(c2fg);
        when(connectorRepository.findConnectedByFunctionGroupAndKind(functionGroup, "LegacyEjbca"))
                .thenReturn(List.of(new Connector()));

        assertThrows(NotFoundException.class, () -> service.listIssueCertificateAttributes(raProfile));
        verifyNoInteractions(adapterFactory);
    }

    // --- validateIssueCertificateAttributes / validateRevokeCertificateAttributes ---

    @Test
    void validateIssueCertificateAttributes_delegatesToAdapter() throws Exception {
        List<RequestAttribute> attrs = List.of(mock(RequestAttribute.class));

        service.validateIssueCertificateAttributes(raProfile, attrs);

        verify(adapter).validateIssueAttributes(authority, attrs);
    }

    @Test
    void validateRevokeCertificateAttributes_delegatesToAdapter() throws Exception {
        List<RequestAttribute> attrs = List.of(mock(RequestAttribute.class));

        service.validateRevokeCertificateAttributes(raProfile, attrs);

        verify(adapter).validateRevokeAttributes(authority, attrs);
    }

    // --- mergeAndValidateIssueAttributes ---

    @Test
    void mergeAndValidateIssueAttributes_validatesThenListsThenUpdatesEngine() throws Exception {
        List<RequestAttribute> attrs = List.of(mock(RequestAttribute.class));
        List<BaseAttribute> definitions = List.of(mock(BaseAttribute.class));
        when(adapter.listIssueAttributes(authority, raProfile)).thenReturn(definitions);

        service.mergeAndValidateIssueAttributes(raProfile, attrs);

        InOrder order = inOrder(adapter, attributeEngine);
        order.verify(adapter).validateIssueAttributes(authority, attrs);
        order.verify(adapter).listIssueAttributes(authority, raProfile);
        order.verify(attributeEngine).validateUpdateDataAttributes(
                connector.getUuid(), AttributeOperation.CERTIFICATE_ISSUE, definitions, attrs);
    }

    @Test
    void mergeAndValidateIssueAttributes_normalizesNullAttributesToEmptyList() throws Exception {
        when(adapter.listIssueAttributes(authority, raProfile)).thenReturn(List.of());

        service.mergeAndValidateIssueAttributes(raProfile, null);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<RequestAttribute>> captor = ArgumentCaptor.forClass(List.class);
        verify(adapter).validateIssueAttributes(eq(authority), captor.capture());
        assertNotNull(captor.getValue());
        assertTrue(captor.getValue().isEmpty());
        verify(attributeEngine).validateUpdateDataAttributes(
                connector.getUuid(), AttributeOperation.CERTIFICATE_ISSUE, List.of(), captor.getValue());
    }

    @Test
    void mergeAndValidateIssueAttributes_throwsWhenConnectorMissing() {
        authority.setConnector(null);

        assertThrows(ValidationException.class, () -> service.mergeAndValidateIssueAttributes(raProfile, List.of()));
        verifyNoInteractions(adapterFactory, attributeEngine);
    }

    @Test
    void mergeAndValidateIssueAttributes_connectorRejectionShortCircuits() throws Exception {
        List<RequestAttribute> attrs = List.of(mock(RequestAttribute.class));
        doThrow(new ValidationException("rejected")).when(adapter).validateIssueAttributes(authority, attrs);

        assertThrows(ValidationException.class, () -> service.mergeAndValidateIssueAttributes(raProfile, attrs));

        verify(adapter, never()).listIssueAttributes(any(), any());
        verifyNoInteractions(attributeEngine);
    }

    @Test
    void mergeAndValidateIssueAttributes_propagatesConnectorException() throws Exception {
        List<RequestAttribute> attrs = List.of(mock(RequestAttribute.class));
        doThrow(new ConnectorException("connector down")).when(adapter).validateIssueAttributes(authority, attrs);

        assertThrows(ConnectorException.class, () -> service.mergeAndValidateIssueAttributes(raProfile, attrs));
        verifyNoInteractions(attributeEngine);
    }

    // --- listRevokeCertificateAttributes / mergeAndValidateRevokeAttributes ---

    @Test
    void listRevokeCertificateAttributes_delegatesToAdapter() throws Exception {
        List<BaseAttribute> expected = List.of(mock(BaseAttribute.class));
        when(adapter.listRevokeAttributes(authority, raProfile)).thenReturn(expected);

        assertSame(expected, service.listRevokeCertificateAttributes(raProfile));
    }

    @Test
    void mergeAndValidateRevokeAttributes_usesRevokeOperationAndDefinitions() throws Exception {
        List<RequestAttribute> attrs = List.of(mock(RequestAttribute.class));
        List<BaseAttribute> definitions = List.of(mock(BaseAttribute.class));
        when(adapter.listRevokeAttributes(authority, raProfile)).thenReturn(definitions);

        service.mergeAndValidateRevokeAttributes(raProfile, attrs);

        InOrder order = inOrder(adapter, attributeEngine);
        order.verify(adapter).validateRevokeAttributes(authority, attrs);
        order.verify(adapter).listRevokeAttributes(authority, raProfile);
        order.verify(attributeEngine).validateUpdateDataAttributes(
                connector.getUuid(), AttributeOperation.CERTIFICATE_REVOKE, definitions, attrs);
    }
}

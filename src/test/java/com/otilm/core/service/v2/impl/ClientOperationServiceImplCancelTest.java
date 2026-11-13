package com.otilm.core.service.v2.impl;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorEntityNotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.CancelPendingCertificateRequestDto;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.OutboundSecretContainment;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.CertificateRelationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.handler.ConnectorCapabilityService;
import com.otilm.core.service.handler.OperationAttributeResolver;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapterFactory;
import com.otilm.core.service.handler.authority.AuthorityProviderV3Adapter;
import com.otilm.core.service.handler.authority.lifecycle.CertificateStateMachine;
import com.otilm.core.service.v2.CancelConfirmation;
import com.otilm.core.service.v2.ConnectorInternalService;
import java.util.Optional;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The operator cancel of a pending issue on a v3 authority whose cancel request cannot be prepared: the real adapter
 * resolves the request's stored references before anything is sent, so its failures reach the shared cancel core.
 */
@ExtendWith(MockitoExtension.class)
class ClientOperationServiceImplCancelTest {

    @Mock
    private CertificateRepository certificateRepository;
    @Mock
    private CertificateRelationRepository certificateRelationRepository;
    @Mock
    private AuthorityProviderAdapterFactory adapterFactory;
    @Mock
    private CertificateInternalService certificateService;
    @Mock
    private PlatformTransactionManager transactionManager;
    @Mock
    private CertificateStateMachine stateMachine;
    @Mock
    private CertificateEventHistoryInternalService certificateEventHistoryService;
    @Mock
    private EventProducer eventProducer;
    @Mock
    private ConnectorInternalService connectorService;
    @Mock
    private ConnectorApiFactory connectorApiFactory;
    @Mock
    private AttributeEngine attributeEngine;
    @Mock
    private OperationAttributeResolver operationAttributeResolver;
    @Mock
    private OutboundSecretContainment outboundContainment;
    @Mock
    private ConnectorCapabilityService capabilityService;

    private ClientOperationServiceImpl service;
    private Certificate certificate;
    private SecuredParentUUID authorityUuid;

    @BeforeEach
    void createServiceWithAPendingIssueOnAV3Authority() throws Exception {
        service = new ClientOperationServiceImpl();
        service.setCertificateRepository(certificateRepository);
        service.setCertificateRelationRepository(certificateRelationRepository);
        service.setAdapterFactory(adapterFactory);
        service.setCertificateService(certificateService);
        service.setTransactionManager(transactionManager);
        service.setStateMachine(stateMachine);
        service.setCertificateEventHistoryService(certificateEventHistoryService);
        service.setEventProducer(eventProducer);

        AuthorityInstanceReference authority = new AuthorityInstanceReference();
        authority.setUuid(UUID.randomUUID());
        authority.setConnectorUuid(UUID.randomUUID());
        authorityUuid = SecuredParentUUID.fromUUID(authority.getUuid());
        RaProfile raProfile = new RaProfile();
        raProfile.setUuid(UUID.randomUUID());
        raProfile.setAuthorityInstanceReference(authority);
        certificate = aCertificate().build();
        certificate.setUuid(UUID.randomUUID());
        certificate.setState(CertificateState.PENDING_ISSUE);
        certificate.setRaProfile(raProfile);

        var adapter = new AuthorityProviderV3Adapter(connectorService, connectorApiFactory, attributeEngine,
                operationAttributeResolver, outboundContainment, capabilityService);
        when(adapterFactory.forAuthority(authority)).thenReturn(adapter);
        when(connectorService.getConnectorForApiClient(authority.getConnectorUuid()))
                .thenReturn(mock(ApiClientConnectorInfo.class));
        when(certificateRepository.findWithAssociationsByUuid(certificate.getUuid()))
                .thenReturn(Optional.of(certificate));
        when(certificateRepository.findForPollingByUuid(certificate.getUuid())).thenReturn(Optional.of(certificate));
        lenient()
                .when(certificateRepository.findAndLockWithAssociationsByUuid(certificate.getUuid()))
                .thenReturn(Optional.of(certificate));
        lenient().when(transactionManager.getTransaction(any())).thenReturn(mock(TransactionStatus.class));
    }

    @Test
    void returnsUnconfirmedAndFailsTheCertificateWithoutSendingTheCancel_whenASecretOfTheRequestIsNotFound()
            throws Exception {
        // given
        var secretNotFound = new ConnectorEntityNotFoundException("Secret content not found");
        when(operationAttributeResolver.resolveForConnectorRequestAsSystem(any(), any())).thenThrow(secretNotFound);

        // when
        CancelConfirmation confirmation = service
                .cancelPendingCertificateOperationWithConfirmation(authorityUuid,
                        certificate.getRaProfile().getSecuredUuid(), certificate.getUuid().toString(),
                        new CancelPendingCertificateRequestDto());

        // then
        assertThat(confirmation).isEqualTo(CancelConfirmation.UNCONFIRMED);
        verify(connectorApiFactory, never()).getCertificateApiClientV3(any());
        verify(stateMachine)
                .transition(eq(certificate), eq(CertificateState.FAILED), eq(CertificateEvent.ISSUE), anyString());
    }

    @Test
    void throwsValidationAndKeepsTheCertificatePendingWithoutSendingTheCancel_whenAReferenceOfTheRequestIsInvalid()
            throws Exception {
        // given
        var disabledSecret = new ValidationException("Secret is disabled");
        when(operationAttributeResolver.resolveForConnectorRequestAsSystem(any(), any())).thenThrow(disabledSecret);
        String certificateUuid = certificate.getUuid().toString();
        var request = new CancelPendingCertificateRequestDto();

        // when
        ThrowingCallable cancel = () -> service
                .cancelPendingCertificateOperationWithConfirmation(authorityUuid,
                        certificate.getRaProfile().getSecuredUuid(), certificateUuid, request);

        // then
        assertThatThrownBy(cancel)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("could not be prepared");
        verify(connectorApiFactory, never()).getCertificateApiClientV3(any());
        verify(stateMachine, never()).transition(any(), any(), any(), any());
    }
}

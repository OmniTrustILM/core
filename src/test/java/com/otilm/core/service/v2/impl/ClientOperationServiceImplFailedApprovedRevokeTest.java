package com.otilm.core.service.v2.impl;

import com.otilm.api.exception.CertificateOperationException;
import com.otilm.api.exception.ConnectorClientException;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.v2.ClientCertificateRevocationDto;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapter;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapterFactory;
import com.otilm.core.service.handler.authority.lifecycle.CertificateStateMachine;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.CannotCreateTransactionException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.TransactionSystemException;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * An approved revoke that the authority fails returns the certificate to Issued in a transaction of its own. When that
 * transaction cannot be opened or rolled back, the caller must still see the revoke's own, Core-authored failure: the
 * database's message would otherwise reach the requester's notification.
 */
class ClientOperationServiceImplFailedApprovedRevokeTest {

    private static final String FAILURE = "Failed to revoke certificate: the authority rejected the revocation";

    private ClientOperationServiceImpl service;
    private CertificateRepository certificateRepository;
    private PlatformTransactionManager transactionManager;
    private UUID certificateUuid;

    @BeforeEach
    void setUp() throws Exception {
        certificateRepository = mock(CertificateRepository.class);
        transactionManager = mock(PlatformTransactionManager.class);
        AuthorityProviderAdapterFactory adapterFactory = mock(AuthorityProviderAdapterFactory.class);
        AuthorityProviderAdapter adapter = mock(AuthorityProviderAdapter.class);

        service = new ClientOperationServiceImpl();
        service.setCertificateRepository(certificateRepository);
        service.setTransactionManager(transactionManager);
        service.setAdapterFactory(adapterFactory);
        service.setStateMachine(mock(CertificateStateMachine.class));
        service.setCertificateEventHistoryService(mock(CertificateEventHistoryInternalService.class));

        AuthorityInstanceReference authority = new AuthorityInstanceReference();
        authority.setUuid(UUID.randomUUID());
        RaProfile raProfile = new RaProfile();
        raProfile.setUuid(UUID.randomUUID());
        raProfile.setAuthorityInstanceReference(authority);

        certificateUuid = UUID.randomUUID();
        Certificate certificate = new Certificate();
        certificate.setUuid(certificateUuid);
        certificate.setState(CertificateState.PENDING_APPROVAL);
        certificate.setRaProfile(raProfile);
        when(certificateRepository.findWithAssociationsByUuid(certificateUuid)).thenReturn(Optional.of(certificate));

        when(adapterFactory.forAuthority(ArgumentMatchers.any())).thenReturn(adapter);
        when(adapter.revoke(ArgumentMatchers.any(), ArgumentMatchers.any()))
                .thenThrow(new ConnectorClientException("refused", HttpStatus.BAD_REQUEST));
    }

    @Test
    void keepsTheRevokeFailureWhenTheRestoreCannotOpenItsTransaction() {
        when(transactionManager.getTransaction(ArgumentMatchers.any()))
                .thenThrow(new CannotCreateTransactionException("Connection to db:5432 refused"));

        assertRevokeFailsWithItsOwnMessage();
    }

    @Test
    void keepsTheRevokeFailureWhenTheRestoreCannotRollBack() {
        TransactionStatus tx = mock(TransactionStatus.class);
        when(transactionManager.getTransaction(ArgumentMatchers.any())).thenReturn(tx);
        when(certificateRepository.findAndLockWithAssociationsByUuid(certificateUuid))
                .thenThrow(new IllegalStateException("lock wait timeout"));
        doThrow(new TransactionSystemException("Could not roll back JPA transaction"))
                .when(transactionManager)
                .rollback(tx);

        assertRevokeFailsWithItsOwnMessage();
    }

    private void assertRevokeFailsWithItsOwnMessage() {
        ClientCertificateRevocationDto request = new ClientCertificateRevocationDto();
        request.setAttributes(List.of());

        CertificateOperationException failure = Assertions
                .assertThrows(CertificateOperationException.class,
                        () -> service.revokeCertificateAction(certificateUuid, request, true));

        Assertions.assertEquals(FAILURE, failure.getMessage());
    }
}

package com.otilm.core.service.renewal.auto;

import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateLocation;
import com.otilm.core.dao.entity.CertificateRelation;
import com.otilm.core.dao.entity.CertificateRelationId;
import com.otilm.core.dao.entity.CertificateRenewalInfo;
import com.otilm.core.dao.entity.workflows.TriggerAssociation;
import com.otilm.core.dao.entity.workflows.TriggerHistory;
import com.otilm.core.dao.repository.CertificateLocationRepository;
import com.otilm.core.dao.repository.CertificateRenewalInfoRepository;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.util.AuthHelper;
import jakarta.persistence.EntityManager;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.PlatformTransactionManager;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AsyncRenewalLocationReplacerTest {

    private static final UUID RENEWED_UUID = UUID.randomUUID();
    private static final UUID SUCCESSOR_UUID = UUID.randomUUID();

    @Mock
    private ClientOperationInternalService clientOperationService;
    @Mock
    private CertificateRenewalInfoRepository renewalInfoRepository;
    @Mock
    private CertificateLocationRepository certificateLocationRepository;
    @Mock
    private LocationReplacementFailureRecorder failureRecorder;
    @Mock
    private AuthHelper authHelper;
    @Mock
    private EntityManager entityManager;
    @Mock
    private PlatformTransactionManager transactionManager;

    private AsyncRenewalLocationReplacer replacer;

    @BeforeEach
    void createReplacer() {
        replacer = new AsyncRenewalLocationReplacer(clientOperationService, renewalInfoRepository,
                certificateLocationRepository, failureRecorder, authHelper, entityManager, transactionManager);
    }

    @Test
    void replacesNothing_whenNoAutomaticRenewalTracksTheCertificate() {
        // given
        stubSuccessorOf(RENEWED_UUID);
        when(renewalInfoRepository.findByCertificateUuid(RENEWED_UUID)).thenReturn(Optional.empty());

        // when
        replacer.replaceInLocations(SUCCESSOR_UUID);

        // then
        verifyNoInteractions(authHelper, clientOperationService, failureRecorder);
    }

    @Test
    void recordsTheFailure_whenTheRenewalHasNoTriggerOwner() {
        // given
        stubTrackedRenewalInALocation(null);

        // when
        replacer.replaceInLocations(SUCCESSOR_UUID);

        // then
        verify(failureRecorder)
                .recordFailure(RENEWED_UUID, SUCCESSOR_UUID,
                        "the trigger that renewed the certificate has no owner to act as");
        verifyNoInteractions(authHelper, clientOperationService);
    }

    @Test
    void recordsTheFailure_whenTheReplacementFailsUnexpectedly() throws Exception {
        // given
        var ownerUuid = UUID.randomUUID();
        stubTrackedRenewalInALocation(ownerUuid);
        when(authHelper.runAsUser(eq(ownerUuid), any())).thenThrow(new IllegalStateException("connection reset"));

        // when
        replacer.replaceInLocations(SUCCESSOR_UUID);

        // then
        verify(failureRecorder).recordFailure(RENEWED_UUID, SUCCESSOR_UUID, "unexpected error");
    }

    @Test
    void replacesNothing_whenTheLookupFails() {
        // given
        when(entityManager.find(Certificate.class, SUCCESSOR_UUID)).thenThrow(new IllegalStateException("db down"));

        // when
        replacer.replaceInLocations(SUCCESSOR_UUID);

        // then
        verifyNoInteractions(authHelper, clientOperationService, failureRecorder);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void stubSuccessorOf(UUID renewedUuid) {
        CertificateRelation relation = new CertificateRelation();
        relation.setId(new CertificateRelationId(SUCCESSOR_UUID, renewedUuid));
        Certificate successor = aCertificate().withUuid(SUCCESSOR_UUID).build();
        successor.setPredecessorRelations(Set.of(relation));
        when(entityManager.find(Certificate.class, SUCCESSOR_UUID)).thenReturn(successor);
    }

    /**
     * The renewed certificate is still in a location, and its renewal row tracks the successor, started by a firing of
     * a trigger the given user owns, or by no recorded firing when the owner is null.
     */
    private void stubTrackedRenewalInALocation(UUID ownerUuid) {
        stubSuccessorOf(RENEWED_UUID);
        CertificateRenewalInfo row = new CertificateRenewalInfo();
        row.setRenewSuccessorUuid(SUCCESSOR_UUID);
        if (ownerUuid != null) {
            UUID firingUuid = UUID.randomUUID();
            row.setRenewTriggerHistoryUuid(firingUuid);
            TriggerAssociation association = mock(TriggerAssociation.class);
            when(association.getTriggeredBy()).thenReturn(ownerUuid);
            TriggerHistory firing = mock(TriggerHistory.class);
            when(firing.getTriggerAssociation()).thenReturn(association);
            when(entityManager.find(TriggerHistory.class, firingUuid)).thenReturn(firing);
        }
        when(renewalInfoRepository.findByCertificateUuid(RENEWED_UUID)).thenReturn(Optional.of(row));
        when(certificateLocationRepository.findByCertificateUuid(RENEWED_UUID))
                .thenReturn(List.of(mock(CertificateLocation.class)));
    }
}

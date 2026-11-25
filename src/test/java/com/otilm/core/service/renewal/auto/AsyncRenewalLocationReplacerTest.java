package com.otilm.core.service.renewal.auto;

import com.otilm.api.exception.LocationException;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateLocation;
import com.otilm.core.dao.entity.CertificateLocationId;
import com.otilm.core.dao.entity.CertificateRelation;
import com.otilm.core.dao.entity.CertificateRelationId;
import com.otilm.core.dao.entity.CertificateRenewalInfo;
import com.otilm.core.dao.entity.CertificateRenewalLocation;
import com.otilm.core.dao.repository.CertificateLocationRepository;
import com.otilm.core.dao.repository.CertificateRenewalInfoRepository;
import com.otilm.core.dao.repository.CertificateRenewalLocationRepository;
import com.otilm.core.service.LocationInternalService;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.AuthHelper.ThrowingSupplier;
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
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AsyncRenewalLocationReplacerTest {

    private static final UUID RENEWED_UUID = UUID.randomUUID();
    private static final UUID SUCCESSOR_UUID = UUID.randomUUID();
    private static final UUID LOCATION_UUID = UUID.randomUUID();

    @Mock
    private ClientOperationInternalService clientOperationService;
    @Mock
    private LocationInternalService locationService;
    @Mock
    private CertificateRenewalInfoRepository renewalInfoRepository;
    @Mock
    private CertificateRenewalLocationRepository renewalLocationRepository;
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
        replacer = new AsyncRenewalLocationReplacer(clientOperationService, locationService, renewalInfoRepository,
                renewalLocationRepository, certificateLocationRepository, failureRecorder, authHelper, entityManager,
                transactionManager);
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

    @Test
    void pushesToTheLocationAsTheStoredOwnerInPlaceOfTheRenewedCertificate_whenALocationRenewalRequestedIt()
            throws Exception {
        // given
        var ownerUuid = UUID.randomUUID();
        CertificateRenewalLocation row = stubTrackedLocationRenewal(ownerUuid);
        stubRunningAsUser(ownerUuid);
        var renewedEntry = new CertificateLocation();
        when(certificateLocationRepository.findById(new CertificateLocationId(LOCATION_UUID, RENEWED_UUID)))
                .thenReturn(Optional.of(renewedEntry));
        when(renewalLocationRepository.findAndLock(RENEWED_UUID, LOCATION_UUID)).thenReturn(Optional.of(row));

        // when
        replacer.replaceInLocations(SUCCESSOR_UUID);

        // then
        verify(locationService)
                .pushRequestedCertificateToLocationAction(new CertificateLocationId(LOCATION_UUID, SUCCESSOR_UUID),
                        false);
        verify(certificateLocationRepository).delete(renewedEntry);
        assertThat(row.getCompletedAt()).isNotNull();
        verifyNoInteractions(failureRecorder);
    }

    @Test
    void recordsTheFailureWithoutCompletingTheLocation_whenThePushFails() throws Exception {
        // given
        var ownerUuid = UUID.randomUUID();
        stubTrackedLocationRenewal(ownerUuid);
        stubRunningAsUser(ownerUuid);
        var pushRefused = new LocationException("location is offline");
        doThrow(pushRefused)
                .when(locationService)
                .pushRequestedCertificateToLocationAction(new CertificateLocationId(LOCATION_UUID, SUCCESSOR_UUID),
                        false);

        // when
        replacer.replaceInLocations(SUCCESSOR_UUID);

        // then
        verify(failureRecorder)
                .recordLocationFailure(RENEWED_UUID, SUCCESSOR_UUID, LOCATION_UUID, pushRefused.getMessage());
        verify(renewalLocationRepository, never()).findAndLock(any(), any());
    }

    @Test
    void recordsTheLocationFailure_whenTheLocationRenewalHasNoOwner() {
        // given
        stubTrackedLocationRenewal(null);

        // when
        replacer.replaceInLocations(SUCCESSOR_UUID);

        // then
        verify(failureRecorder)
                .recordLocationFailure(RENEWED_UUID, SUCCESSOR_UUID, LOCATION_UUID,
                        "the trigger that renewed the certificate has no owner to act as");
        verifyNoInteractions(authHelper, locationService);
    }

    @Test
    void pushesNothing_whenTheOldCertificateIsNoLongerInTheLocation() {
        // given
        stubSuccessorOf(RENEWED_UUID);
        CertificateRenewalLocation row = locationRenewalRow(UUID.randomUUID());
        when(renewalLocationRepository.findBySuccessorUuid(SUCCESSOR_UUID)).thenReturn(List.of(row));
        when(certificateLocationRepository.existsById(new CertificateLocationId(LOCATION_UUID, SUCCESSOR_UUID)))
                .thenReturn(true);
        when(certificateLocationRepository.existsById(new CertificateLocationId(LOCATION_UUID, RENEWED_UUID)))
                .thenReturn(false);

        // when
        replacer.replaceInLocations(SUCCESSOR_UUID);

        // then
        verifyNoInteractions(authHelper, locationService, failureRecorder);
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
     * The renewed certificate is still in a location, and its renewal row tracks the successor, started by a firing
     * that acted as the given user, or as no user when the owner is null.
     */
    private void stubTrackedRenewalInALocation(UUID ownerUuid) {
        stubSuccessorOf(RENEWED_UUID);
        CertificateRenewalInfo row = new CertificateRenewalInfo();
        row.setRenewSuccessorUuid(SUCCESSOR_UUID);
        row.setRenewOwnerUuid(ownerUuid);
        when(renewalInfoRepository.findByCertificateUuid(RENEWED_UUID)).thenReturn(Optional.of(row));
        when(certificateLocationRepository.findByCertificateUuid(RENEWED_UUID))
                .thenReturn(List.of(mock(CertificateLocation.class)));
    }

    /**
     * A location renewal of the renewed certificate requested the successor, which is linked to the location while the
     * renewed certificate is still there, started by a firing that acted as the given user.
     */
    private CertificateRenewalLocation stubTrackedLocationRenewal(UUID ownerUuid) {
        stubSuccessorOf(RENEWED_UUID);
        CertificateRenewalLocation row = locationRenewalRow(ownerUuid);
        when(renewalLocationRepository.findBySuccessorUuid(SUCCESSOR_UUID)).thenReturn(List.of(row));
        when(certificateLocationRepository.existsById(any(CertificateLocationId.class))).thenReturn(true);
        return row;
    }

    private void stubRunningAsUser(UUID ownerUuid) throws Exception {
        when(authHelper.runAsUser(eq(ownerUuid), any()))
                .thenAnswer(invocation -> invocation.<ThrowingSupplier<?, ?>>getArgument(1).get());
    }

    private static CertificateRenewalLocation locationRenewalRow(UUID ownerUuid) {
        CertificateRenewalLocation row = new CertificateRenewalLocation();
        row.setCertificateUuid(RENEWED_UUID);
        row.setLocationUuid(LOCATION_UUID);
        row.setSuccessorUuid(SUCCESSOR_UUID);
        row.setOwnerUuid(ownerUuid);
        return row;
    }
}

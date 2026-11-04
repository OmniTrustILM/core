package com.otilm.core.service.impl;

import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.config.cache.CacheEvictor;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.entity.signing.TspProfile;
import com.otilm.core.dao.repository.signing.SigningProfileRepository;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.TspProfileInternalService;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A profile writer must hold the lock a profile update holds before it reads the profile, or it decides on state a
 * concurrent update is replacing, commits a link the update has just cleared, or evicts the cache entry of a name the
 * update has already changed.
 */
@ExtendWith(MockitoExtension.class)
class SigningProfileWriterLockTest {

    private static final UUID PROFILE = UUID.fromString("00000000-0000-0000-0000-0000000000c1");
    private static final UUID TSP_PROFILE = UUID.fromString("00000000-0000-0000-0000-0000000000c2");

    @Mock
    ClusterOperationSynchronizer clusterSynchronizer;
    @Mock
    SigningProfileRepository signingProfileRepository;
    @Mock
    CacheEvictor cacheEvictor;
    @Mock
    TspProfileInternalService tspProfileService;

    private final SigningProfile profile = new SigningProfile();
    private final SigningProfileServiceImpl service = new SigningProfileServiceImpl();

    @BeforeEach
    void wireServiceToStoredProfile() {
        service.setClusterSynchronizer(clusterSynchronizer);
        service.setSigningProfileRepository(signingProfileRepository);
        service.setCacheEvictor(cacheEvictor);
        service.setTspProfileService(tspProfileService);

        profile.setUuid(PROFILE);
        profile.setName("invoices");
        profile.setWorkflowType(SigningWorkflowType.RAW_SIGNING);
        profile.setSigningScheme(SigningScheme.MANAGED);
        when(signingProfileRepository.findByUuid(any())).thenReturn(Optional.of(profile));
    }

    @Test
    void locksProfileBeforeReadingIt_whenActivatingIlmNative() throws Exception {
        // given — a stored managed raw-signing profile

        // when
        service.activateIlmNative(SecuredUUID.fromUUID(PROFILE));

        // then
        InOrder order = inOrder(clusterSynchronizer, signingProfileRepository);
        order.verify(clusterSynchronizer).lock("signing-profile:" + PROFILE);
        order.verify(signingProfileRepository).findByUuid(any());
    }

    @Test
    void locksProfileBeforeReadingIt_whenDeactivatingIlmNative() throws Exception {
        // given — a stored managed raw-signing profile

        // when
        service.deactivateIlmNative(SecuredUUID.fromUUID(PROFILE));

        // then
        InOrder order = inOrder(clusterSynchronizer, signingProfileRepository);
        order.verify(clusterSynchronizer).lock("signing-profile:" + PROFILE);
        order.verify(signingProfileRepository).findByUuid(any());
    }

    @Test
    void locksProfileBeforeReadingIt_whenActivatingTsp() throws Exception {
        // given — a stored timestamping profile and the TSP profile to link
        profile.setWorkflowType(SigningWorkflowType.TIMESTAMPING);
        var tspProfile = new TspProfile();
        tspProfile.setUuid(TSP_PROFILE);
        when(tspProfileService.getTspProfileEntity(any())).thenReturn(tspProfile);

        // when
        service.activateTsp(SecuredUUID.fromUUID(PROFILE), SecuredUUID.fromUUID(TSP_PROFILE), "https://ilm.example");

        // then
        InOrder order = inOrder(clusterSynchronizer, signingProfileRepository);
        order.verify(clusterSynchronizer).lock("signing-profile:" + PROFILE);
        order.verify(signingProfileRepository).findByUuid(any());
    }

    @Test
    void locksProfileBeforeReadingIt_whenDeactivatingTsp() throws Exception {
        // given — a stored profile

        // when
        service.deactivateTsp(SecuredUUID.fromUUID(PROFILE));

        // then
        InOrder order = inOrder(clusterSynchronizer, signingProfileRepository);
        order.verify(clusterSynchronizer).lock("signing-profile:" + PROFILE);
        order.verify(signingProfileRepository).findByUuid(any());
    }

    @Test
    void locksProfileBeforeReadingIt_whenEnabling() throws Exception {
        // given — a stored profile

        // when
        service.enableSigningProfile(SecuredUUID.fromUUID(PROFILE));

        // then
        verifyLockedBeforeRead();
    }

    @Test
    void locksProfileBeforeReadingIt_whenDisabling() throws Exception {
        // given — a stored profile

        // when
        service.disableSigningProfile(SecuredUUID.fromUUID(PROFILE));

        // then
        verifyLockedBeforeRead();
    }

    @Test
    void locksProfileBeforeReadingIt_whenEnablingInOwnTransaction() throws Exception {
        // given — a stored profile

        // when
        service.enableInOwnTransaction(SecuredUUID.fromUUID(PROFILE));

        // then
        verifyLockedBeforeRead();
    }

    @Test
    void locksProfileBeforeReadingIt_whenDisablingInOwnTransaction() throws Exception {
        // given — a stored profile

        // when
        service.disableInOwnTransaction(SecuredUUID.fromUUID(PROFILE));

        // then
        verifyLockedBeforeRead();
    }

    @Test
    void readsProfileOnlyUnderLock_whenBulkEnabling() {
        // given — a stored profile, with the service standing in for its own proxy
        service.setSelf(service);

        // when
        service.bulkEnableSigningProfiles(List.of(SecuredUUID.fromUUID(PROFILE)));

        // then
        verifyReadOnlyUnderLock();
    }

    @Test
    void readsProfileOnlyUnderLock_whenBulkDisabling() {
        // given — a stored profile, with the service standing in for its own proxy
        service.setSelf(service);

        // when
        service.bulkDisableSigningProfiles(List.of(SecuredUUID.fromUUID(PROFILE)));

        // then
        verifyReadOnlyUnderLock();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void verifyLockedBeforeRead() {
        InOrder order = inOrder(clusterSynchronizer, signingProfileRepository);
        order.verify(clusterSynchronizer).lock("signing-profile:" + PROFILE);
        order.verify(signingProfileRepository).findByUuid(any());
    }

    /**
     * Under open-in-view a profile read before the lock stays managed in the request's EntityManager, which the
     * per-profile transaction reuses, so the read under the lock would hand back that copy.
     */
    private void verifyReadOnlyUnderLock() {
        verifyLockedBeforeRead();
        verify(signingProfileRepository).findByUuid(any());
    }
}

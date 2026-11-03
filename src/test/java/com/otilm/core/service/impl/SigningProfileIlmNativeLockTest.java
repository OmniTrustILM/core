package com.otilm.core.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.config.cache.CacheEvictor;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.repository.signing.SigningProfileRepository;
import com.otilm.core.security.authz.SecuredUUID;
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
import static org.mockito.Mockito.when;

/**
 * Switching ILM_NATIVE must hold the lock a profile update holds, or the switch is decided on a workflow and scheme a
 * concurrent update is replacing.
 */
@ExtendWith(MockitoExtension.class)
class SigningProfileIlmNativeLockTest {

    private static final UUID PROFILE = UUID.fromString("00000000-0000-0000-0000-0000000000c1");

    @Mock
    ClusterOperationSynchronizer clusterSynchronizer;
    @Mock
    SigningProfileRepository signingProfileRepository;
    @Mock
    CacheEvictor cacheEvictor;

    private final SigningProfileServiceImpl service = new SigningProfileServiceImpl();

    @BeforeEach
    void wireService() {
        service.setClusterSynchronizer(clusterSynchronizer);
        service.setSigningProfileRepository(signingProfileRepository);
        service.setCacheEvictor(cacheEvictor);

        SigningProfile profile = new SigningProfile();
        profile.setUuid(PROFILE);
        profile.setName("invoices");
        profile.setWorkflowType(SigningWorkflowType.RAW_SIGNING);
        profile.setSigningScheme(SigningScheme.MANAGED);
        when(signingProfileRepository.findByUuid(any())).thenReturn(Optional.of(profile));
    }

    @Test
    void activationLocksTheProfileBeforeReadingIt() throws NotFoundException {
        // when
        service.activateIlmNative(SecuredUUID.fromUUID(PROFILE));

        // then
        InOrder order = inOrder(clusterSynchronizer, signingProfileRepository);
        order.verify(clusterSynchronizer).lock("signing-profile:" + PROFILE);
        order.verify(signingProfileRepository).findByUuid(any());
    }

    @Test
    void deactivationLocksTheProfileBeforeReadingIt() throws NotFoundException {
        // when
        service.deactivateIlmNative(SecuredUUID.fromUUID(PROFILE));

        // then
        InOrder order = inOrder(clusterSynchronizer, signingProfileRepository);
        order.verify(clusterSynchronizer).lock("signing-profile:" + PROFILE);
        order.verify(signingProfileRepository).findByUuid(any());
    }
}

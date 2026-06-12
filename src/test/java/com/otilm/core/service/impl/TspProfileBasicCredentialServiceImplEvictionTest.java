package com.otilm.core.service.impl;

import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.config.cache.CacheEvictor;
import com.otilm.core.dao.entity.signing.TspProfile;
import com.otilm.core.dao.entity.signing.TspProfileBasicCredential;
import com.otilm.core.dao.repository.signing.TspProfileBasicCredentialRepository;
import com.otilm.core.security.authn.client.CredentialVerificationCache;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.UUID;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TspProfileBasicCredentialServiceImplEvictionTest {

    @Mock
    private TspProfileBasicCredentialRepository credentialRepository;

    @Mock
    private CacheEvictor cacheEvictor;

    @Mock
    private CredentialVerificationCache credentialVerificationCache;

    private TspProfileBasicCredentialServiceImpl service;

    private UUID secretUuid;

    @BeforeEach
    void wireService() {
        service = new TspProfileBasicCredentialServiceImpl();
        service.setCredentialRepository(credentialRepository);
        service.setCacheEvictor(cacheEvictor);
        service.setCredentialVerificationCache(credentialVerificationCache);
        secretUuid = UUID.randomUUID();
    }

    @Test
    void evictsProfileAndVerificationCaches_whenCredentialFound() {
        // given
        var profileName = "p1";
        var profile = new TspProfile();
        profile.setName(profileName);
        var credential = new TspProfileBasicCredential();
        credential.setTspProfile(profile);
        when(credentialRepository.findBySecretUuid(secretUuid)).thenReturn(Optional.of(credential));

        // when
        service.evictCachesForSecret(secretUuid);

        // then
        verify(cacheEvictor).evict(CacheConfig.TSP_PROFILE_CACHE, profileName);
        verify(credentialVerificationCache).evictBySecretUuid(secretUuid);
    }

    @Test
    void evictsVerificationCacheOnly_whenSecretIsNotTspBasicCredential() {
        // given — no TSP basic credential references this secret
        when(credentialRepository.findBySecretUuid(secretUuid)).thenReturn(Optional.empty());

        // when
        service.evictCachesForSecret(secretUuid);

        // then — verification cache eviction is keyed by secretUuid and stays idempotent even after the row is gone
        verifyNoInteractions(cacheEvictor);
        verify(credentialVerificationCache).evictBySecretUuid(secretUuid);
    }
}

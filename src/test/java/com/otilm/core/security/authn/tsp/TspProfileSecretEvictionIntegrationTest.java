package com.otilm.core.security.authn.tsp;

import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.dao.entity.signing.TspProfile;
import com.otilm.core.dao.entity.signing.TspProfileBasicCredential;
import com.otilm.core.dao.repository.signing.TspProfileBasicCredentialRepository;
import com.otilm.core.dao.repository.signing.TspProfileRepository;
import com.otilm.core.events.SecretContentUpdatedEvent;
import com.otilm.core.security.authn.client.CredentialVerificationCache;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end proof of the rotation-invalidation wiring that the unit tests can only cover link-by-link:
 * a committed {@link SecretContentUpdatedEvent} must flow through {@link TspProfileSecretEvictionListener}
 * (AFTER_COMMIT) into {@code TspProfileBasicCredentialService.evictCachesForSecret} and clear the real
 * caches. This is the path a password rotation relies on, since {@code update()} intentionally does not
 * evict the verification cache eagerly on rotation.
 */
class TspProfileSecretEvictionIntegrationTest extends BaseSpringBootTest {

    @Autowired
    private CredentialVerificationCache credentialVerificationCache;
    @Autowired
    private ApplicationEventPublisher eventPublisher;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @Autowired
    private CacheManager cacheManager;
    @Autowired
    private TspProfileRepository tspProfileRepository;
    @Autowired
    private TspProfileBasicCredentialRepository credentialRepository;

    @Test
    void evictsVerificationCacheAfterCommit_whenSecretContentUpdatedEventIsPublished() {
        // given — a successfully verified credential cached against its secret
        UUID secretUuid = UUID.randomUUID();
        UUID mappedUserUuid = UUID.randomUUID();
        String password = "s3cr3t";
        credentialVerificationCache.putSuccess(secretUuid, password, mappedUserUuid);
        assertThat(credentialVerificationCache.getMappedUser(secretUuid, password)).contains(mappedUserUuid);

        // when — the secret's content is updated and the event is published inside a transaction
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            eventPublisher.publishEvent(new SecretContentUpdatedEvent(secretUuid));

            // then — the AFTER_COMMIT listener has NOT fired yet, so the entry is still live mid-transaction
            assertThat(credentialVerificationCache.getMappedUser(secretUuid, password)).contains(mappedUserUuid);
        });

        // then — once the transaction commits, the listener evicts the entry
        assertThat(credentialVerificationCache.getMappedUser(secretUuid, password)).isEmpty();
    }

    @Test
    void evictsBothCachesAfterCommit_whenSecretBelongsToTspBasicCredential() {
        // given — a persisted TSP Basic credential, its profile model cached, and a cached verification
        TspProfile profile = new TspProfile();
        profile.setName("tsp-evict-end-to-end");
        profile = tspProfileRepository.save(profile);

        UUID secretUuid = UUID.randomUUID();
        UUID mappedUserUuid = UUID.randomUUID();
        String password = "s3cr3t";

        TspProfileBasicCredential credential = new TspProfileBasicCredential();
        credential.setTspProfile(profile);
        credential.setUsername("svc");
        credential.setSecretUuid(secretUuid);
        credential.setMappedUserUuid(mappedUserUuid);
        credentialRepository.save(credential);

        Cache modelCache = cacheManager.getCache(CacheConfig.TSP_PROFILE_CACHE);
        modelCache.put(profile.getName(), "cached-tsp-profile-model");
        credentialVerificationCache.putSuccess(secretUuid, password, mappedUserUuid);

        assertThat(modelCache.get(profile.getName())).isNotNull();
        assertThat(credentialVerificationCache.getMappedUser(secretUuid, password)).contains(mappedUserUuid);

        // when — the secret's content is updated and the event is published inside a transaction
        String profileName = profile.getName();
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            eventPublisher.publishEvent(new SecretContentUpdatedEvent(secretUuid));

            // then — nothing is evicted mid-transaction; both caches are still populated
            assertThat(modelCache.get(profileName)).isNotNull();
            assertThat(credentialVerificationCache.getMappedUser(secretUuid, password)).contains(mappedUserUuid);
        });

        // then — after commit the listener resolves the credential and clears BOTH caches
        assertThat(modelCache.get(profileName)).isNull();
        assertThat(credentialVerificationCache.getMappedUser(secretUuid, password)).isEmpty();
    }
}

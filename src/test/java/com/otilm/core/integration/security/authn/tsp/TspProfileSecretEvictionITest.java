package com.otilm.core.integration.security.authn.tsp;

import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.dao.entity.signing.TspProfile;
import com.otilm.core.dao.entity.signing.TspProfileBasicCredential;
import com.otilm.core.dao.repository.signing.TspProfileBasicCredentialRepository;
import com.otilm.core.dao.repository.signing.TspProfileRepository;
import com.otilm.core.events.SecretContentUpdatedEvent;
import com.otilm.core.security.authn.tsp.TspProfileSecretEvictionListener;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end proof of the rotation-invalidation wiring that the unit tests can only cover link-by-link: a committed
 * {@link SecretContentUpdatedEvent} must flow through {@link TspProfileSecretEvictionListener} (AFTER_COMMIT) into
 * {@code TspProfileBasicCredentialInternalService.evictProfileModelForSecret} and evict the cached profile model. A
 * password rotation relies on this path.
 */
class TspProfileSecretEvictionITest extends BaseSpringBootTest {

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
    void evictsTheProfileModelAfterCommit_whenSecretBelongsToTspBasicCredential() {
        // given — a persisted TSP Basic credential with its profile model cached
        TspProfile profile = new TspProfile();
        profile.setName("tsp-evict-end-to-end");
        profile = tspProfileRepository.save(profile);

        UUID secretUuid = UUID.randomUUID();
        UUID mappedUserUuid = UUID.randomUUID();

        TspProfileBasicCredential credential = new TspProfileBasicCredential();
        credential.setTspProfile(profile);
        credential.setUsername("svc");
        credential.setSecretUuid(secretUuid);
        credential.setMappedUserUuid(mappedUserUuid);
        credentialRepository.save(credential);

        Cache modelCache = cacheManager.getCache(CacheConfig.TSP_PROFILE_CACHE);
        modelCache.get(profile.getName(), () -> "cached-tsp-profile-model");
        assertThat(modelCache.get(profile.getName())).isNotNull();

        // when — the secret's content is updated and the event is published inside a transaction
        String profileName = profile.getName();
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            eventPublisher.publishEvent(new SecretContentUpdatedEvent(secretUuid));

            // then — the profile model stays cached until the commit
            assertThat(modelCache.get(profileName)).isNotNull();
        });

        // then — the listener evicts the profile model after the commit
        assertThat(modelCache.get(profileName)).isNull();
    }
}

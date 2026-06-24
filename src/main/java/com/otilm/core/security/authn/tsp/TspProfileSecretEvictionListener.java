package com.otilm.core.security.authn.tsp;

import com.otilm.core.events.SecretContentUpdatedEvent;
import com.otilm.core.service.TspProfileBasicCredentialInternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * TSP-side adapter for {@link SecretContentUpdatedEvent}. Keeps the Secret subsystem decoupled from TSP:
 * when a secret's latest-version fingerprint flips (async rotation), this bridges the committed event to
 * {@link TspProfileBasicCredentialInternalService#evictCachesForSecret}, which refreshes the TSP profile model
 * cache and the credential-verification cache against the new fingerprint.
 *
 * <p>Runs AFTER_COMMIT so the eventual model reload reads the committed new fingerprint, not the stale one.
 * A no-op for secrets that are not TSP Basic credentials.</p>
 */
@Component
public class TspProfileSecretEvictionListener {

    private TspProfileBasicCredentialInternalService credentialService;

    @Autowired
    public void setCredentialService(TspProfileBasicCredentialInternalService credentialService) {
        this.credentialService = credentialService;
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    @Transactional(propagation = Propagation.REQUIRES_NEW, readOnly = true)
    public void onSecretContentUpdated(SecretContentUpdatedEvent event) {
        credentialService.evictCachesForSecret(event.secretUuid());
    }
}

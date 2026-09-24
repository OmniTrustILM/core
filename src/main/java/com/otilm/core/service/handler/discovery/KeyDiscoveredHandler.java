package com.otilm.core.service.handler.discovery;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryItem;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.ExternalAuthorizationProgrammatic;
import com.otilm.core.service.writer.discovery.DiscoveredKeyWriter;
import java.security.PublicKey;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Turns staged key items into key records, one per key whichever run or connector reported it. Only a key with a public
 * part Core can read is onboarded (see {@link DiscoveredKeyIdentity}); any other is listed with a reason on its item,
 * and one key's failure never costs the batch its other keys.
 */
@Service
public class KeyDiscoveredHandler {

    private static final Logger logger = LoggerFactory.getLogger(KeyDiscoveredHandler.class);

    private final DiscoveredKeyWriter keyWriter;
    private final AuthorizationEnforcer authorizationEnforcer;
    private final ObjectMapper objectMapper;
    private final TransactionHandler transactionHandler;
    private final AttributeEngine attributeEngine;

    public KeyDiscoveredHandler(DiscoveredKeyWriter keyWriter, AuthorizationEnforcer authorizationEnforcer,
            ObjectMapper objectMapper, TransactionHandler transactionHandler, AttributeEngine attributeEngine) {
        this.keyWriter = keyWriter;
        this.authorizationEnforcer = authorizationEnforcer;
        this.objectMapper = objectMapper;
        this.transactionHandler = transactionHandler;
        this.attributeEngine = attributeEngine;
    }

    /**
     * Imports one batch of staged key items.
     *
     * @return how the batch went, for the caller to report on the run
     */
    @ExternalAuthorizationProgrammatic(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.CREATE)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public KeyImportOutcome importBatch(Discovery run, List<DiscoveryItem> items) {
        if (items.isEmpty()) {
            return new KeyImportOutcome(0, 0, 0);
        }
        // Once per page, not per key, and before anything is written: enforcement is a blocking call, and a page
        // that may not be imported must leave no half-filled inventory behind. Creating a discovery run is not
        // permission to create keys -- the certificate half enforces CERTIFICATE:CREATE for the same reason.
        authorizationEnforcer.enforce(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.CREATE);
        int imported = 0;
        int failed = 0;
        int deferred = 0;
        for (DiscoveryItem item : items) {
            try {
                if (importOne(run, item)) {
                    imported++;
                } else {
                    failed++;
                }
            } catch (RuntimeException e) {
                // This attempt failed, not this key: its row stays pending for a later tick, and the keys after it
                // still get their turn -- one key that fails every time must not hold back the rest of the backlog.
                logger
                        .error("Discovery {} could not import key item {} on this attempt: {}", run.getUuid(),
                                item.getUniqueRef(), e.getMessage(), e);
                deferred++;
            }
        }
        return new KeyImportOutcome(imported, failed, deferred);
    }

    /**
     * Gives the keys a run never reached a reason, once it has stopped trying, for the item listing to show.
     */
    public void markUnreached(UUID discoveryUuid) {
        transactionHandler
                .runInNewTransaction(() -> keyWriter
                        .markUnreachedKeys(discoveryUuid,
                                "Not imported: processing stopped before this key could be imported."));
    }

    /**
     * Imports one key, or records why it never will. A reason is final, so only the key itself earns one; a failure of
     * the attempt leaves the row pending for a later tick.
     */
    private boolean importOne(Discovery run, DiscoveryItem item) {
        PublicKey publicKey;
        String fingerprint;
        try {
            DiscoveredKeyDto key = objectMapper.convertValue(item.getPayload(), DiscoveredKeyDto.class);
            publicKey = DiscoveredKeyIdentity.publicKeyOf(key);
            fingerprint = DiscoveredKeyIdentity.fingerprintOf(publicKey);
        } catch (UnusableDiscoveredKeyException e) {
            return refuse(run, item, e.getMessage(), e);
        } catch (IllegalArgumentException e) {
            return refuse(run, item, "The key's payload could not be read.", e);
        }
        // One transaction per key, opened here rather than in the writer: a key that commits is never revisited,
        // and a refusal further down the page must not take it back out.
        transactionHandler
                .runInNewTransaction(() -> keyWriter
                        .importKey(item, publicKey, fingerprint)
                        .ifPresent(keyItemUuid -> recordWhereFound(run, keyItemUuid, item.getMeta())));
        return true;
    }

    /**
     * Keeps where the provider found the key as metadata from this run, on the key item, which is where the key APIs
     * read metadata. Not in {@code key_meta}: that is a token's reference to the key.
     */
    private void recordWhereFound(Discovery run, UUID keyItemUuid, List<MetadataAttribute> meta) {
        if (meta == null || meta.isEmpty()) {
            return;
        }
        try {
            attributeEngine
                    .updateMetadataAttributes(meta,
                            ObjectAttributeContentInfo
                                    .builder(Resource.CRYPTOGRAPHIC_KEY, keyItemUuid)
                                    .connector(run.getConnectorUuid())
                                    .source(Resource.DISCOVERY, run.getUuid())
                                    .sourceName(run.getName())
                                    .build());
        } catch (AttributeException e) {
            // As for a certificate: a lost location does not cost the key.
            logger
                    .warn("Discovery {} could not record where key {} was found: {}", run.getUuid(), keyItemUuid,
                            e.getMessage());
        }
    }

    /** Records the reason on the item. The connector's own words and the stack stay in the log. */
    private boolean refuse(Discovery run, DiscoveryItem item, String reason, RuntimeException cause) {
        if (cause instanceof DiscoveredKeyNotOnboardedException) {
            logger
                    .debug("Discovery {} listed key item {} without onboarding it: {}", run.getUuid(),
                            item.getUniqueRef(), reason);
        } else {
            logger
                    .warn("Discovery {} could not import key item {}: {}", run.getUuid(), item.getUniqueRef(),
                            cause.getMessage(), cause);
        }
        // Committed on its own, so the reason outlives the caller.
        transactionHandler.runInNewTransaction(() -> keyWriter.markFailed(item.getUuid(), reason));
        return false;
    }

    /**
     * What one batch produced.
     *
     * @param deferred keys left pending because the attempt failed rather than the key; a later tick tries them again
     */
    public record KeyImportOutcome(int imported, int failed, int deferred) {
    }
}

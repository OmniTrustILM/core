package com.otilm.core.service.handler;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.crypto.ImportedKeyRegistration;
import com.otilm.core.model.crypto.KeyImportAttempt;
import com.otilm.core.model.crypto.KeyImportCheck;
import com.otilm.core.model.crypto.KeyImportMetadata;
import com.otilm.core.model.crypto.KeyMaterial;
import com.otilm.core.model.crypto.ProviderKeyItem;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.service.handler.key.ImportAnswer;
import com.otilm.core.service.handler.key.KeyProviderAdapter;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import com.otilm.core.service.writer.CryptographicKeyWriter;
import com.otilm.core.service.writer.KeyImportWriter;
import com.otilm.core.util.CryptographyUtil;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Component;

/**
 * Settles a claimed import attempt from what the connector recorded of it. An import the connector never accepted, or
 * one that ended without a key, is closed; one still running is left for the next look. The key of an import whose
 * requester was never answered is destroyed through the connector's handles for it, once the attempt is taken so that
 * no retry registers the key meanwhile; a key the connector refuses to destroy is registered deactivated.
 */
@Component
public class KeyImportReconciler {

    public static final String NEVER_ACCEPTED = "The connector never accepted the key import.";
    public static final String UNRESOLVED = "The outcome of the key import could not be learned in time.";
    public static final String NOT_REGISTERED = "The connector refused to destroy the imported key, and the platform could not register it.";

    private static final Logger logger = LoggerFactory.getLogger(KeyImportReconciler.class);

    private final TokenProfileRepository tokenProfileRepository;
    private final KeyProviderAdapterFactory keyProviderAdapterFactory;
    private final KeyImportWriter keyImportWriter;
    private final KeyImportGates keyImportGates;

    public KeyImportReconciler(TokenProfileRepository tokenProfileRepository,
            KeyProviderAdapterFactory keyProviderAdapterFactory, KeyImportWriter keyImportWriter,
            KeyImportGates keyImportGates) {
        this.tokenProfileRepository = tokenProfileRepository;
        this.keyProviderAdapterFactory = keyProviderAdapterFactory;
        this.keyImportWriter = keyImportWriter;
        this.keyImportGates = keyImportGates;
    }

    /**
     * Settles the attempt; one whose token profile is gone or whose connector cannot say is left for its next look, or
     * ends unresolved on its last look. On its last look a connector that no longer knows the attempt proves nothing,
     * but one that still holds its key has it undone.
     *
     * @return whether the connector answered, so that it can be asked about other attempts now
     */
    public boolean reconcile(KeyImportCheck check) {
        UUID attemptUuid = check.attempt().uuid();
        Optional<TokenProfileFullModel> profile = tokenProfileRepository
                .findFullModelByUuidAndTokenInstanceReferenceUuid(check.tokenProfileUuid(), check.tokenInstanceUuid());
        if (profile.isEmpty()) {
            unsettled(check, "its token profile no longer exists");
            return true;
        }
        KeyProviderAdapter adapter;
        ImportAnswer answer;
        try {
            adapter = keyProviderAdapterFactory.forToken(profile.get().tokenInstance());
            answer = adapter.importKeyResult(profile.get(), attemptUuid, check.attempt().secretDigests(), check.name());
        } catch (ConnectorException | NotFoundException | RuntimeException e) {
            unsettled(check, "the connector could not report on it (" + e.getClass().getSimpleName() + ")");
            return false;
        }
        if (answer instanceof ImportAnswer.NotAccepted) {
            if (check.lastLook()) {
                unsettled(check, "the connector no longer knows it");
            } else {
                keyImportWriter.failUntaken(check.attempt(), NEVER_ACCEPTED);
            }
        } else if (answer instanceof ImportAnswer.NotImported) {
            keyImportWriter.failUntaken(check.attempt(), KeyImportSaga.NOT_IMPORTED);
        } else if (answer instanceof ImportAnswer.Imported imported && keyImportWriter.compensating(check.attempt())) {
            return compensate(check, profile.get(), adapter, imported);
        } else if (answer instanceof ImportAnswer.Running) {
            unsettled(check, "it is still running");
        }
        return true;
    }

    /** Leaves the attempt for its next look, or on its last look closes it as unresolved, with its key reference. */
    private void unsettled(KeyImportCheck check, String reason) {
        UUID attemptUuid = check.attempt().uuid();
        if (!check.lastLook()) {
            logger.info("Key import {} is left for its next look: {}", attemptUuid, reason);
            return;
        }
        if (keyImportWriter.unresolved(check.attempt(), UNRESOLVED)) {
            logger
                    .warn("Key import {} is unresolved: {}; key reference {} identifies its key in token instance {}",
                            attemptUuid, reason, check.attempt().keyReference(), check.tokenInstanceUuid());
        } else {
            logger
                    .info("Key import {} is left to the request that took it since its last look was claimed",
                            attemptUuid);
        }
    }

    /**
     * Destroys the imported key, private key first. The attempt is compensated once the connector has destroyed the
     * private key, even when the public key stays in the token, which exposes nothing. It is recorded so before the
     * public key is destroyed, as a later look can no longer learn of a destroy left unrecorded.
     *
     * @return whether the connector answered about the private key
     */
    private boolean compensate(KeyImportCheck check, TokenProfileFullModel profile, KeyProviderAdapter adapter,
            ImportAnswer.Imported imported) {
        UUID attemptUuid = check.attempt().uuid();
        try {
            for (ProviderKeyItem item : imported.items()) {
                if (item.type() != KeyType.PUBLIC_KEY) {
                    adapter.destroyImportedKeyItem(profile, handleOf(item));
                }
            }
        } catch (ValidationException refused) {
            quarantine(check, profile, imported);
            return true;
        } catch (ConnectorException | RuntimeException e) {
            unsettled(check, "the connector did not destroy its key (" + e.getClass().getSimpleName() + ")");
            return false;
        }
        keyImportWriter.compensated(attemptUuid);
        logger
                .info("Key import {} is undone: the connector destroyed the key its requester never received",
                        attemptUuid);
        imported
                .items()
                .stream()
                .filter(item -> item.type() == KeyType.PUBLIC_KEY)
                .forEach(publicKey -> destroyPublicKey(attemptUuid, profile, adapter, publicKey));
        return true;
    }

    private static void destroyPublicKey(UUID attemptUuid, TokenProfileFullModel profile, KeyProviderAdapter adapter,
            ProviderKeyItem publicKey) {
        try {
            adapter.destroyImportedKeyItem(profile, handleOf(publicKey));
        } catch (ConnectorException | RuntimeException e) {
            logger
                    .info("The public key of key import {} stays in the token: the connector did not destroy it ({})",
                            attemptUuid, e.getClass().getSimpleName());
        }
    }

    /**
     * Registers the key the connector refused to destroy, deactivated, with what the attempt keeps: as a key of its
     * own, or into the public-key-only record that holds its public key, which it takes only once the requester is
     * shown to be allowed to update it. When the platform cannot register it the attempt is unresolved, and the key
     * reference is logged to find the key in the token.
     */
    private void quarantine(KeyImportCheck check, TokenProfileFullModel profile, ImportAnswer.Imported imported) {
        KeyImportAttempt attempt = check.attempt();
        String fingerprint = CryptographyUtil
                .calculateKeyFingerprint(new KeyMaterial(KeyFormat.SPKI, imported.publicKey()));
        ImportedKeyRegistration registration = new ImportedKeyRegistration(profile, imported.items(),
                attempt.keyReference(), fingerprint, check.exportable(),
                new KeyImportMetadata(check.name(), null, Set.of(), null), check.requester(), true, null);
        try {
            UUID adoptable = keyImportGates.adoptableBy(check.requester(), fingerprint).orElse(null);
            keyImportWriter
                    .quarantine(attempt.uuid(), registration.adopting(adoptable))
                    .ifPresent(keyUuid -> logger
                            .warn("Key import {} could not be undone: the connector refused to destroy its key, registered deactivated as key {}",
                                    attempt.uuid(), keyUuid));
        } catch (ValidationException | DataIntegrityViolationException | CryptographicKeyWriter.UncheckedRecordException
                | AttributeException | NotFoundException e) {
            if (keyImportWriter.unresolved(attempt, NOT_REGISTERED)) {
                logger
                        .warn("Key import {} is unresolved: the connector refused to destroy its key and the platform could not register it ({}); key reference {} identifies the key in token instance {}",
                                attempt.uuid(), e.getClass().getSimpleName(), attempt.keyReference(),
                                check.tokenInstanceUuid());
            }
        }
    }

    private static List<MetadataAttribute> handleOf(ProviderKeyItem item) {
        return item.reference() instanceof RemoteKeyReference.MetadataReference(List<MetadataAttribute> keyMeta)
                ? keyMeta
                : List.of();
    }
}

package com.otilm.core.service.handler.discovery;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryItem;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.service.writer.discovery.DiscoveredKeyWriter;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.dao.CannotAcquireLockException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Which failures belong to the item and which to the attempt. A reason on a staged row is final, so only the key itself
 * earns one; a database that was briefly unavailable leaves the row for the next tick.
 */
class KeyDiscoveredHandlerTest {

    private static final String SPKI = Base64.getEncoder().encodeToString(rsaPublicKey().getEncoded());

    private final DiscoveredKeyWriter writer = Mockito.mock(DiscoveredKeyWriter.class);
    private final AuthorizationEnforcer enforcer = Mockito.mock(AuthorizationEnforcer.class);
    private KeyDiscoveredHandler handler;
    private Discovery run;

    @BeforeEach
    void setUp() {
        handler = new KeyDiscoveredHandler(writer, enforcer, new ObjectMapper(), new TransactionHandler(),
                Mockito.mock(AttributeEngine.class));
        run = new Discovery();
        run.setUuid(UUID.randomUUID());
    }

    @Test
    void keyWithNoPublicPart_isTheItemsOwnReasonAndNeverReachesTheWriter() {
        DiscoveryItem item = keyItem(null);

        KeyDiscoveredHandler.KeyImportOutcome outcome = handler.importBatch(run, List.of(item));

        assertThat(outcome.failed()).isEqualTo(1);
        verify(writer).markFailed(Mockito.eq(item.getUuid()), Mockito.startsWith("Listed, not added to the inventory"));
        verify(writer, never()).importKey(any(), any(), any());
    }

    @Test
    void databaseThatCouldNotBeReached_leavesTheItemForTheNextTick() {
        doThrow(new CannotAcquireLockException("lock timeout")).when(writer).importKey(any(), any(), any());
        DiscoveryItem item = keyItem(SPKI);

        KeyDiscoveredHandler.KeyImportOutcome outcome = handler.importBatch(run, List.of(item));

        assertThat(outcome.deferred()).isEqualTo(1);
        assertThat(outcome.failed()).isZero();
        verify(writer, never()).markFailed(any(), any());
    }

    @Test
    void keyThatFailsTheAttempt_doesNotHoldBackTheKeysAfterIt() {
        DiscoveryItem unreachable = keyItem(SPKI);
        DiscoveryItem next = keyItem(SPKI);
        doThrow(new CannotAcquireLockException("lock timeout"))
                .when(writer)
                .importKey(Mockito.eq(unreachable), any(), any());

        KeyDiscoveredHandler.KeyImportOutcome outcome = handler.importBatch(run, List.of(unreachable, next));

        // Stopping at the first failure would leave one key that always fails in front of the whole backlog.
        assertThat(outcome.deferred()).isEqualTo(1);
        assertThat(outcome.imported()).isEqualTo(1);
        verify(writer).importKey(Mockito.eq(next), any(), any());
    }

    @Test
    void refusalAheadOfATransientFailure_isStillCountedForTheRunToReport() {
        DiscoveryItem refused = keyItem(null);
        DiscoveryItem unreachable = keyItem(SPKI);
        doThrow(new CannotAcquireLockException("lock timeout"))
                .when(writer)
                .importKey(Mockito.eq(unreachable), any(), any());

        KeyDiscoveredHandler.KeyImportOutcome outcome = handler.importBatch(run, List.of(refused, unreachable));

        assertThat(outcome.failed()).isEqualTo(1);
        assertThat(outcome.deferred()).isEqualTo(1);
        verify(writer).markFailed(Mockito.eq(refused.getUuid()), any());
    }

    private DiscoveryItem keyItem(String publicKey) {
        DiscoveryItem item = new DiscoveryItem();
        item.setUuid(UUID.randomUUID());
        item.setDiscoveryUuid(run.getUuid());
        item.setUniqueRef("ssh://host-a:22");
        DiscoveredKeyDto key = new DiscoveredKeyDto();
        key.setType(publicKey == null ? KeyType.SECRET_KEY : KeyType.PUBLIC_KEY);
        key.setAlgorithm(KeyAlgorithm.RSA);
        key.setPublicKey(publicKey);
        key.setPublicKeyFormat(publicKey == null ? null : KeyFormat.SPKI);
        key.setFingerprint("whatever-the-connector-computed");
        item.setPayload(new ObjectMapper().convertValue(key, new TypeReference<Map<String, Object>>() {
        }));
        return item;
    }

    private static PublicKey rsaPublicKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair().getPublic();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}

package com.otilm.core.service.handler.discovery;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryItem;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.service.writer.discovery.DiscoveredKeyWriter;
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
 * Which failures belong to the item and which belong to the attempt.
 *
 * <p>
 * A reason stamped on a staged row is final — the backlog never offers that row again — so only a payload nothing can
 * make sense of earns one. A database that was briefly unavailable is the agenda's problem, and the row has to stay
 * where the next tick can find it.
 */
class KeyDiscoveredHandlerTest {

    private final DiscoveredKeyWriter writer = Mockito.mock(DiscoveredKeyWriter.class);
    private final AuthorizationEnforcer enforcer = Mockito.mock(AuthorizationEnforcer.class);
    private KeyDiscoveredHandler handler;
    private Discovery run;

    @BeforeEach
    void setUp() {
        handler = new KeyDiscoveredHandler(writer, enforcer, new ObjectMapper(), new TransactionHandler());
        run = new Discovery();
        run.setUuid(UUID.randomUUID());
    }

    @Test
    void payloadNothingCanIdentify_isTheItemsOwnFailure() {
        doThrow(new UnusableDiscoveredKeyException("The key was reported without anything to identify it."))
                .when(writer)
                .importKey(any(), any());
        DiscoveryItem item = keyItem();

        KeyDiscoveredHandler.KeyImportOutcome outcome = handler.importBatch(run, List.of(item));

        assertThat(outcome.failed()).isEqualTo(1);
        verify(writer).markFailed(item.getUuid(), "The key was reported without anything to identify it.");
    }

    @Test
    void databaseThatCouldNotBeReached_leavesTheItemForTheNextTick() {
        doThrow(new CannotAcquireLockException("lock timeout")).when(writer).importKey(any(), any());
        DiscoveryItem item = keyItem();

        // Stamped, the row would be lost for good: a lock this tick could not take is the agenda's business, and
        // the caller leaves the backlog alone so the ladder brings the row back.
        KeyDiscoveredHandler.KeyImportOutcome outcome = handler.importBatch(run, List.of(item));

        assertThat(outcome.aborted()).isTrue();
        assertThat(outcome.failed()).isZero();
        verify(writer, never()).markFailed(any(), any());
    }

    @Test
    void refusalAheadOfATransientFailure_isStillCountedForTheRunToReport() {
        DiscoveryItem refused = keyItem();
        DiscoveryItem unreachable = keyItem();
        doThrow(new UnusableDiscoveredKeyException("The key was reported without anything to identify it."))
                .when(writer)
                .importKey(Mockito.eq(refused), any());
        doThrow(new CannotAcquireLockException("lock timeout")).when(writer).importKey(Mockito.eq(unreachable), any());

        KeyDiscoveredHandler.KeyImportOutcome outcome = handler.importBatch(run, List.of(refused, unreachable));

        // The refusal committed and its row will never be offered again, so the count that reports it has to
        // survive the page ending early -- otherwise that key is lost from the run's messages for good.
        assertThat(outcome.failed()).isEqualTo(1);
        assertThat(outcome.aborted()).isTrue();
        verify(writer).markFailed(Mockito.eq(refused.getUuid()), any());
    }

    private DiscoveryItem keyItem() {
        DiscoveryItem item = new DiscoveryItem();
        item.setUuid(UUID.randomUUID());
        item.setDiscoveryUuid(run.getUuid());
        item.setUniqueRef("ssh://host-a:22");
        DiscoveredKeyDto key = new DiscoveredKeyDto();
        key.setType(KeyType.PUBLIC_KEY);
        key.setAlgorithm(KeyAlgorithm.RSA);
        key.setFingerprint("whatever-the-connector-computed");
        item.setPayload(new ObjectMapper().convertValue(key, new TypeReference<Map<String, Object>>() {
        }));
        return item;
    }
}

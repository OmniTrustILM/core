package com.otilm.core.service.handler.discovery;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.discovery.v2.DiscoveredKeyDto;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryItem;
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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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
        handler = new KeyDiscoveredHandler(writer, enforcer, new ObjectMapper());
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
        // the tick that catches this leaves the backlog alone so the ladder brings the row back.
        assertThatThrownBy(() -> handler.importBatch(run, List.of(item)))
                .isInstanceOf(CannotAcquireLockException.class);
        verify(writer, never()).markFailed(any(), any());
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

package com.otilm.core.model.ai;

import com.otilm.ai.runtime.protocol.ManagementAction;
import com.otilm.core.model.ai.AiModelDispatchState.ConnectionVersion;
import com.otilm.core.model.ai.AiModelManagementSession.Facts;
import com.otilm.core.model.ai.AiModelManagementSession.Request;
import com.otilm.core.model.ai.AiModelManagementSession.Spec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Immutable internal operation data, never an actor/session/CONNECT grant. */
class AiModelManagementSessionTest {
    private static final UUID SESSION = UUID.randomUUID();
    private static final UUID ACTOR = UUID.randomUUID();
    private static final UUID CONFIGURATION = UUID.randomUUID();
    private static final ConnectionVersion CONNECTION = new ConnectionVersion(CONFIGURATION, 2, 3, 4, "lab");
    private static final Instant EXPIRY = Instant.parse("2030-01-01T00:00:00.123456789Z");

    @ParameterizedTest
    @EnumSource(ManagementAction.class)
    void finiteSpecsAreManagementOnlyAndRedacted(ManagementAction action) {
        var request = new Request(SESSION, ACTOR, CONFIGURATION, action, EXPIRY, 1, 32);
        var spec = new Spec(SESSION, ACTOR, CONNECTION, action, EXPIRY, 1, 32);
        assertThat(request.sessionId()).isEqualTo(SESSION);
        assertThat(request.actorId()).isEqualTo(ACTOR);
        assertThat(request.configurationId()).isEqualTo(CONFIGURATION);
        assertThat(request.action()).isEqualTo(action);
        assertThat(request.expiresAt()).isEqualTo(EXPIRY.truncatedTo(ChronoUnit.MICROS));
        assertThat(spec.connection()).isEqualTo(CONNECTION);
        assertThat(spec.expiresAt()).isEqualTo(request.expiresAt());
        assertThat(spec.maxCalls()).isEqualTo(1);
        assertThat(spec.maxTokens()).isEqualTo(32);
        assertThat(request.toString()).doesNotContain(ACTOR.toString(), SESSION.toString(), CONFIGURATION.toString());
        assertThat(spec.toString()).doesNotContain(ACTOR.toString(), SESSION.toString(), CONFIGURATION.toString());
        assertThat(Arrays.stream(Request.class.getRecordComponents()).map(c -> c.getName()))
                .containsExactly("sessionId", "actorId", "configurationId", "action", "expiresAt", "maxCalls",
                        "maxTokens");
    }

    @ParameterizedTest
    @ValueSource(longs = {0, -1})
    void nonPositiveCapsAreNotFiniteOperations(long invalid) {
        assertThatThrownBy(() -> new Request(SESSION, ACTOR, CONFIGURATION, ManagementAction.CONNECTION_CHECK, EXPIRY,
                invalid, 32)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(
                () -> new Request(SESSION, ACTOR, CONFIGURATION, ManagementAction.CONNECTION_CHECK, EXPIRY, 1, invalid))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(
                () -> new Spec(SESSION, ACTOR, CONNECTION, ManagementAction.CONNECTION_CHECK, EXPIRY, invalid, 32))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(
                () -> new Spec(SESSION, ACTOR, CONNECTION, ManagementAction.CONNECTION_CHECK, EXPIRY, 1, invalid))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"session", "actor", "configuration", "action", "expiry"})
    void missingPinnedFactsCannotBeConvertedIntoAnOperation(String field) {
        UUID session = field.equals("session") ? null : SESSION;
        UUID actor = field.equals("actor") ? null : ACTOR;
        UUID configuration = field.equals("configuration") ? null : CONFIGURATION;
        ManagementAction action = field.equals("action") ? null : ManagementAction.CONNECTION_CHECK;
        Instant expiry = field.equals("expiry") ? null : EXPIRY;
        ConnectionVersion connection = field.equals("configuration") ? null : CONNECTION;
        assertThatThrownBy(() -> new Request(session, actor, configuration, action, expiry, 1, 32))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid management session data");
        assertThatThrownBy(() -> new Spec(session, actor, connection, action, expiry, 1, 32))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid management session data");
        assertThatThrownBy(() -> new Facts(session, actor, connection, action, expiry, 1, 32, 0, 0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid management session data");
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({"-1,0", "0,-1", "3,0", "0,65"})
    void storedCountersOutsideTheirFiniteCapsFailClosed(long calls, long tokens) {
        assertThatThrownBy(() -> new Facts(SESSION, ACTOR, CONNECTION, ManagementAction.CONNECTION_CHECK, EXPIRY, 2, 64,
                calls, tokens))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid management session data");
    }

    @Test
    void factsExposeCountersAsDataAndNeverAnEnabledBooleanInput() {
        var facts = new Facts(SESSION, ACTOR, CONNECTION, ManagementAction.CAPABILITY_CHECK, EXPIRY, 2, 64, 1, 32);
        assertThat(facts.sessionId()).isEqualTo(SESSION);
        assertThat(facts.actorId()).isEqualTo(ACTOR);
        assertThat(facts.connection()).isEqualTo(CONNECTION);
        assertThat(facts.action()).isEqualTo(ManagementAction.CAPABILITY_CHECK);
        assertThat(facts.reservedCalls()).isEqualTo(1);
        assertThat(facts.reservedTokens()).isEqualTo(32);
        assertThat(facts.toString()).doesNotContain(ACTOR.toString(), SESSION.toString(), CONFIGURATION.toString());
        assertThat(Arrays.stream(Request.class.getRecordComponents()).map(c -> c.getType().getName()))
                .doesNotContain("boolean", "java.lang.Boolean");
        assertThat(Arrays.stream(Spec.class.getRecordComponents()).map(c -> c.getType().getName()))
                .doesNotContain("boolean", "java.lang.Boolean");
    }
}

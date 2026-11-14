package com.otilm.ai.gateway;

import com.otilm.ai.runtime.protocol.ManagementAction;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Actual local mTLS status polling and effect counts; synthetic replies are not current Core/native authority. */
class GatewayRegistrationBarrierTest {
    @TempDir
    Path directory;

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void boundedPendingUsesOnlyOwnRoleGetsBeforeOneConsumeAndOneProviderSend(boolean management) throws Exception {
        try (var fixture = fixture(management)) {
            fixture.pendingRegistrationReplies = 2;
            long exit = org.junit.jupiter.api.Assertions.assertDoesNotThrow(() -> {
                try {
                    return execute(fixture, management, new ChatCompletionsTransport());
                } catch (GatewayFailure denied) {
                    assertEquals(0, fixture.consumes.get());
                    assertEquals(0, fixture.sends.get());
                    assertEquals(0, fixture.outcomes.get());
                    assertFalse(fixture.coreSawAuthorization.get());
                    assertFalse(fixture.coreSawCookie.get());
                    assertNull(fixture.fixtureFailure.get());
                    throw denied;
                }
            });
            if (exit != 9) {
                assertEquals(0, fixture.consumes.get());
                assertEquals(0, fixture.sends.get());
                assertEquals(0, fixture.outcomes.get());
            }
            assertFalse(fixture.coreSawAuthorization.get());
            assertFalse(fixture.coreSawCookie.get());
            assertNull(fixture.fixtureFailure.get());
            assertEquals(9, exit);
            assertEquals(3, fixture.registrations.get());
            assertEquals(1, fixture.consumes.get());
            assertEquals(1, fixture.sends.get());
            assertEquals(1, fixture.outcomes.get());
            assertEquals(List.of("registration", "registration", "registration", "consume", "outcome"),
                    fixture.coreTrace);
            assertFalse(fixture.coreSawAuthorization.get());
            assertFalse(fixture.coreSawCookie.get());
            assertNull(fixture.fixtureFailure.get());
        }
    }

    static Stream<Arguments> rejectedReplies() {
        return Stream
                .of(false, true)
                .flatMap(management -> Stream
                        .of("opposite-kind", "extra", "duplicate", "trailing", "utf16", "comma-type", "duplicate-type",
                                "cookie", "encoding", "redirect", "401", "407", "503", "reset")
                        .map(defect -> Arguments.of(management, defect)));
    }

    @ParameterizedTest
    @MethodSource("rejectedReplies")
    void uncertainOrForeignRegistrationReplyCannotReachConsumeOrProvider(boolean management, String defect)
            throws Exception {
        try (var fixture = fixture(management)) {
            fixture.registrationMode = defect;
            Files.delete(fixture.secret);
            assertThrows(GatewayFailure.class, () -> execute(fixture, management, new ChatCompletionsTransport()));
            assertEquals(1, fixture.registrations.get());
            assertEquals(0, fixture.consumes.get());
            assertEquals(0, fixture.sends.get());
            assertEquals(0, fixture.outcomes.get());
            assertEquals(List.of("registration"), fixture.coreTrace);
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void permanentlyPendingStatusHasAFixedCountAndNeverAttemptsConsume(boolean management) throws Exception {
        try (var fixture = fixture(management)) {
            fixture.registrationMode = "pending";
            Files.delete(fixture.secret);
            assertThrows(GatewayFailure.class, () -> execute(fixture, management, new ChatCompletionsTransport()));
            assertTrue(fixture.registrations.get() > 0);
            assertTrue(fixture.registrations.get() <= 32);
            assertEquals(0, fixture.consumes.get());
            assertEquals(0, fixture.sends.get());
            assertEquals(0, fixture.outcomes.get());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void waitingAndFreshTlsCannotResetTheOriginalOperationBudget(boolean management) throws Exception {
        try (var fixture = fixture(management)) {
            fixture.pendingRegistrationReplies = 1;
            fixture.registrationDelayMillis = 400;
            var transport = new ChatCompletionsTransport(Duration.ofMillis(700), Duration.ofSeconds(1),
                    Thread.ofPlatform().daemon().factory());
            long start = System.nanoTime();
            assertThrows(GatewayFailure.class, () -> execute(fixture, management, transport));
            assertTrue(System.nanoTime() - start < TimeUnit.SECONDS.toNanos(2));
            assertTrue(fixture.registrations.get() > 0);
            assertTrue(fixture.registrations.get() <= 2);
            assertEquals(0, fixture.consumes.get());
            assertEquals(0, fixture.sends.get());
            assertEquals(0, fixture.outcomes.get());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void aDeniedConsumeAfterReadyIsNotRetriedOrConvertedBackIntoPending(boolean management) throws Exception {
        try (var fixture = fixture(management)) {
            fixture.mode = "deny";
            assertThrows(GatewayFailure.class, () -> execute(fixture, management, new ChatCompletionsTransport()));
            assertEquals(1, fixture.registrations.get());
            assertEquals(1, fixture.consumes.get());
            assertEquals(0, fixture.sends.get());
            assertEquals(0, fixture.outcomes.get());
            assertEquals(List.of("registration", "consume"), fixture.coreTrace);
        }
    }

    private GatewayRunFixture fixture(boolean management) throws Exception {
        return new GatewayRunFixture(directory, "/api", management ? ManagementAction.CONNECTION_CHECK : null);
    }

    private static long execute(GatewayRunFixture fixture, boolean management, ChatCompletionsTransport transport) {
        return management
                ? GatewayRun.executeManagement(fixture.envelope, fixture.config, transport, GatewayRunWireTest.CALL)
                : GatewayRun.execute(fixture.envelope, fixture.config, transport, GatewayRunWireTest.CALL);
    }
}

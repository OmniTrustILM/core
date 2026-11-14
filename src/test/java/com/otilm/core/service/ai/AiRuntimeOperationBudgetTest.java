package com.otilm.core.service.ai;

import com.otilm.api.exception.PlatformException;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AiRuntimeOperationBudgetTest {
    private final AtomicLong nanos = new AtomicLong(100);

    @AfterEach
    void clearInterrupt() {
        Thread.interrupted();
    }

    @Test
    void returnsSafeDomainMessage_whenTheOperationDeadlineExpires() {
        // given
        var budget = AiRuntimeOperationBudget.start(Duration.ofSeconds(5), nanos::get);
        nanos.addAndGet(Duration.ofSeconds(5).toNanos());

        // when
        ThrowingCallable checkBudget = budget::remaining;

        // then
        assertThatThrownBy(checkBudget).isInstanceOfSatisfying(AiRuntimeOperationBudget.Unavailable.class, failure -> {
            assertThat(PlatformException.safeMessage(failure, "fallback")).isEqualTo("Runtime operation unavailable");
            assertThat(failure.interrupted()).isFalse();
        }).hasNoCause();
    }

    @Test
    void elapsedBodyAndActorTimeIsNotGiftedBackAtDatabaseHandoff() {
        var budget = AiRuntimeOperationBudget.start(Duration.ofSeconds(5), nanos::get);
        nanos.addAndGet(Duration.ofSeconds(4).toNanos());
        assertThat(budget.remaining()).isEqualTo(Duration.ofSeconds(1));
        nanos.addAndGet(Duration.ofMillis(500).toNanos());
        Instant returnedDatabaseTime = Instant.parse("2026-11-04T12:00:00Z");
        assertThat(budget.databaseCutoff(returnedDatabaseTime)).isEqualTo(returnedDatabaseTime.plusMillis(500));
        assertThat(budget.remaining()).isEqualTo(Duration.ofMillis(500));
    }

    @Test
    void databasePrecisionIsFlooredRatherThanExtendingAuthority() {
        var budget = AiRuntimeOperationBudget.start(Duration.ofSeconds(5), nanos::get);
        nanos.addAndGet(1234);
        Instant at = Instant.parse("2026-11-04T12:00:00Z");
        assertThat(budget.databaseCutoff(at)).isEqualTo(at.plusNanos(4_999_998_000L));
    }

    @Test
    void exactDeadlineIsUnavailableWithNoRawCauseOrStack() {
        var budget = AiRuntimeOperationBudget.start(Duration.ofSeconds(5), nanos::get);
        nanos.addAndGet(Duration.ofSeconds(5).toNanos());
        assertThatThrownBy(budget::remaining)
                .isInstanceOf(AiRuntimeOperationBudget.Unavailable.class)
                .hasNoCause()
                .satisfies(failure -> assertThat(failure.getStackTrace()).isEmpty());
    }

    @Test
    void subMicrosecondRemainderCannotBeRoundedIntoDatabaseAuthority() {
        var budget = AiRuntimeOperationBudget.start(Duration.ofNanos(999), nanos::get);
        assertThatThrownBy(() -> budget.databaseCutoff(Instant.parse("2026-11-04T12:00:00Z")))
                .isInstanceOf(AiRuntimeOperationBudget.Unavailable.class);
    }

    @Test
    void interruptionIsPreservedAndClassified() {
        var budget = AiRuntimeOperationBudget.start(Duration.ofSeconds(5), nanos::get);
        Thread.currentThread().interrupt();
        assertThatThrownBy(budget::remaining)
                .isInstanceOf(AiRuntimeOperationBudget.Unavailable.class)
                .satisfies(
                        failure -> assertThat(((AiRuntimeOperationBudget.Unavailable) failure).interrupted()).isTrue());
        assertThat(Thread.currentThread().isInterrupted()).isTrue();
    }

    @ParameterizedTest
    @ValueSource(longs = {-1, 0, 5_000_000_001L, Long.MAX_VALUE})
    void onlyPositiveAtMostFiveSecondsMayBeConstructed(long duration) {
        Duration budget = Duration.ofNanos(duration);
        assertThatThrownBy(() -> AiRuntimeOperationBudget.start(budget)).isInstanceOf(IllegalArgumentException.class);
    }
}

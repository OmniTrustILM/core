package com.otilm.core.service.renewal.auto;

import com.otilm.api.model.core.certificate.AutoRenewalMode;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.CertificateRelation;
import com.otilm.core.service.renewal.auto.AutoRenewalGuards.CommonInput;
import com.otilm.core.service.renewal.auto.AutoRenewalGuards.CommonSkip;
import com.otilm.core.service.renewal.auto.AutoRenewalGuards.FailureCount;
import com.otilm.core.service.renewal.auto.AutoRenewalGuards.GuardResult;
import com.otilm.core.service.renewal.auto.AutoRenewalGuards.SuccessorStatus;
import com.otilm.core.service.renewal.auto.AutoRenewalGuards.UnitGuardResult;
import com.otilm.core.service.renewal.auto.AutoRenewalGuards.UnitInput;
import com.otilm.core.service.renewal.auto.AutoRenewalGuards.UnitOutcome;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class AutoRenewalGuardsTest {

    private static final Instant NOW = Instant.parse("2026-11-23T10:00:00Z");
    private static final Instant START = Instant.parse("2026-11-20T00:00:00Z");
    private static final Instant END = Instant.parse("2026-11-30T00:00:00Z");
    private static final int MAX_ATTEMPTS = 5;

    // ── Common guards ─────────────────────────────────────────────────────────

    @Test
    void skips_whenAutomaticRenewalIsDisabled() {
        // when
        GuardResult result = AutoRenewalGuards
                .common(new CommonInput(false, AutoRenewalMode.ILM_KEY, null, START, END), NOW, 0.5);

        // then
        assertThat(result.skip()).isEqualTo(CommonSkip.DISABLED);
        assertThat(result.renewAt()).isNull();
    }

    @Test
    void skips_whenNoModeCanRenewTheCertificate() {
        // when
        GuardResult result = AutoRenewalGuards
                .common(new CommonInput(true, AutoRenewalMode.NONE, null, START, END), NOW, 0.5);

        // then
        assertThat(result.skip()).isEqualTo(CommonSkip.NO_MODE);
        assertThat(result.renewAt()).isNull();
    }

    @Test
    void skips_whenTheCertificateHasNoWindow() {
        // when
        GuardResult result = AutoRenewalGuards
                .common(new CommonInput(true, AutoRenewalMode.ILM_KEY, null, null, null), NOW, 0.5);

        // then
        assertThat(result.skip()).isEqualTo(CommonSkip.NO_WINDOW);
    }

    @Test
    void proceedsAtNow_whenTheLowestTimeOfAStartedWindowIsDrawn() {
        // given
        double lowestDraw = 0.0;

        // when
        GuardResult result = AutoRenewalGuards
                .common(new CommonInput(true, AutoRenewalMode.ILM_KEY, null, START, END), NOW, lowestDraw);

        // then
        assertThat(result.proceeds()).isTrue();
        assertThat(result.renewAt()).isEqualTo(NOW);
    }

    @Test
    void choosesTheRenewalTimeBetweenNowAndTheEnd_whenTheWindowHasStarted() {
        // given
        double middleDraw = 0.5;

        // when
        GuardResult result = AutoRenewalGuards
                .common(new CommonInput(true, AutoRenewalMode.ILM_KEY, null, START, END), NOW, middleDraw);

        // then
        assertThat(result.skip()).isEqualTo(CommonSkip.NOT_DUE);
        assertThat(result.renewAt()).isEqualTo(NOW.plus(Duration.between(NOW, END).dividedBy(2)));
    }

    @Test
    void choosesTheRenewalTimeBetweenTheStartAndTheEnd_whenTheWindowStartsLater() {
        // given
        Instant laterStart = NOW.plus(Duration.ofDays(1));

        // when
        GuardResult result = AutoRenewalGuards
                .common(new CommonInput(true, AutoRenewalMode.LOCATION, null, laterStart, END), NOW, 0.25);

        // then
        assertThat(result.skip()).isEqualTo(CommonSkip.NOT_DUE);
        assertThat(result.renewAt()).isEqualTo(laterStart.plus(Duration.between(laterStart, END).dividedBy(4)));
    }

    @Test
    void choosesNow_whenTheWindowHasEnded() {
        // given
        Instant ended = NOW.minus(Duration.ofHours(1));

        // when
        GuardResult result = AutoRenewalGuards
                .common(new CommonInput(true, AutoRenewalMode.ILM_KEY, null, START, ended), NOW, 0.9);

        // then
        assertThat(result.proceeds()).isTrue();
        assertThat(result.renewAt()).isEqualTo(NOW);
    }

    @Test
    void skipsWithTheStoredRenewalTime_whenItIsNotReached() {
        // given
        Instant storedRenewAt = NOW.plus(Duration.ofHours(2));

        // when
        GuardResult result = AutoRenewalGuards
                .common(new CommonInput(true, AutoRenewalMode.ILM_KEY, storedRenewAt, START, END), NOW, 0.0);

        // then
        assertThat(result.skip()).isEqualTo(CommonSkip.NOT_DUE);
        assertThat(result.renewAt()).isEqualTo(storedRenewAt);
    }

    @Test
    void proceeds_whenTheStoredRenewalTimeIsReached() {
        // given
        Instant storedRenewAt = NOW.minus(Duration.ofMinutes(1));

        // when
        GuardResult result = AutoRenewalGuards
                .common(new CommonInput(true, AutoRenewalMode.ILM_KEY, storedRenewAt, START, END), NOW, 0.9);

        // then
        assertThat(result.proceeds()).isTrue();
        assertThat(result.renewAt()).isEqualTo(storedRenewAt);
    }

    // ── In-flight marker ──────────────────────────────────────────────────────

    @ParameterizedTest(name = "started {0} min ago -> held {1}")
    @CsvSource({"0, true", "14, true", "15, false", "60, false"})
    void holdsTheMarkerForItsLease(long minutesAgo, boolean held) {
        assertThat(AutoRenewalGuards.markerHeld(NOW.minus(Duration.ofMinutes(minutesAgo)), NOW)).isEqualTo(held);
    }

    @Test
    void holdsNoMarker_whenNoneIsStored() {
        assertThat(AutoRenewalGuards.markerHeld(null, NOW)).isFalse();
    }

    // ── Unit guards ───────────────────────────────────────────────────────────

    @ParameterizedTest(name = "{0}")
    @MethodSource("unitTable")
    void appliesTheUnitGuardsInOrder(String row, UnitInput input, UnitOutcome expected, boolean failureCounted) {
        // when
        UnitGuardResult result = AutoRenewalGuards.unit(input, NOW);

        // then
        assertThat(result.outcome()).isEqualTo(expected);
        assertThat(result.failure() != null).isEqualTo(failureCounted);
    }

    static Stream<Arguments> unitTable() {
        Instant later = NOW.plus(Duration.ofMinutes(5));
        return Stream
                .of(arguments("completed -> skip", unit(true, SuccessorStatus.NONE, false, 0, null),
                        UnitOutcome.COMPLETED, false),
                        arguments("successor issued -> mark completed",
                                unit(false, SuccessorStatus.ISSUED, false, 0, null), UnitOutcome.MARK_COMPLETED, false),
                        arguments("successor in flight -> skip", unit(false, SuccessorStatus.IN_FLIGHT, true, 0, null),
                                UnitOutcome.IN_FLIGHT, false),
                        arguments("successor failed -> count and back off",
                                unit(false, SuccessorStatus.FAILED, false, 0, null), UnitOutcome.BACKOFF, true),
                        arguments("successor revoked before completion -> count and back off",
                                unit(false, SuccessorStatus.REVOKED, false, 0, null), UnitOutcome.BACKOFF, true),
                        arguments("successor revoked after completion -> reopen",
                                unit(true, SuccessorStatus.REVOKED, false, 0, null), UnitOutcome.REOPEN, false),
                        arguments("completed with an issued successor -> skip",
                                unit(true, SuccessorStatus.ISSUED, false, 0, null), UnitOutcome.COMPLETED, false),
                        arguments("foreign renewal -> skip", unit(false, SuccessorStatus.NONE, true, 0, null),
                                UnitOutcome.FOREIGN_RENEWAL, false),
                        arguments("attempts at the limit -> skip",
                                unit(false, SuccessorStatus.NONE, false, MAX_ATTEMPTS, null), UnitOutcome.MAX_ATTEMPTS,
                                false),
                        arguments("backoff not over -> skip", unit(false, SuccessorStatus.NONE, false, 1, later),
                                UnitOutcome.BACKOFF, false),
                        arguments("backoff over -> start", unit(false, SuccessorStatus.NONE, false, 1, NOW),
                                UnitOutcome.START, false),
                        arguments("first start -> start", unit(false, SuccessorStatus.NONE, false, 0, null),
                                UnitOutcome.START, false));
    }

    @Test
    void inFlightSuccessorBlocksAndRejectionCountsOnce() {
        // given: a renewal waits in approval while the trigger fires hourly
        Instant firing = NOW;
        for (int hour = 0; hour < 3; hour++) {
            UnitGuardResult waiting = AutoRenewalGuards
                    .unit(unit(false, SuccessorStatus.IN_FLIGHT, false, 0, null), firing);
            assertThat(waiting.outcome()).isEqualTo(UnitOutcome.IN_FLIGHT);
            assertThat(waiting.failure()).isNull();
            firing = firing.plus(Duration.ofHours(1));
        }

        // when: the approval is rejected and the next firing finds it
        UnitGuardResult rejected = AutoRenewalGuards.unit(unit(false, SuccessorStatus.FAILED, false, 0, null), firing);

        // then: one failed attempt, backed off for an hour
        assertThat(rejected.outcome()).isEqualTo(UnitOutcome.BACKOFF);
        assertThat(rejected.failure().attempt()).isEqualTo(1);
        assertThat(rejected.failure().notBefore()).isEqualTo(firing.plus(Duration.ofHours(1)));

        // when: the following firings see the cleared successor and the stored count
        Instant stored = rejected.failure().notBefore();
        UnitGuardResult backingOff = AutoRenewalGuards
                .unit(unit(false, SuccessorStatus.NONE, false, 1, stored), firing.plus(Duration.ofMinutes(30)));
        UnitGuardResult retry = AutoRenewalGuards.unit(unit(false, SuccessorStatus.NONE, false, 1, stored), stored);

        // then: the rejection is not counted again
        assertThat(backingOff.outcome()).isEqualTo(UnitOutcome.BACKOFF);
        assertThat(backingOff.failure()).isNull();
        assertThat(retry.outcome()).isEqualTo(UnitOutcome.START);
        assertThat(retry.failure()).isNull();
    }

    @Test
    void reportsTheLimitOnce_whenAFoundFailureReachesIt() {
        // when
        UnitGuardResult reaching = AutoRenewalGuards
                .unit(unit(false, SuccessorStatus.FAILED, false, MAX_ATTEMPTS - 1, null), NOW);
        UnitGuardResult afterwards = AutoRenewalGuards
                .unit(unit(false, SuccessorStatus.NONE, false, MAX_ATTEMPTS, reaching.failure().notBefore()), NOW);

        // then
        assertThat(reaching.outcome()).isEqualTo(UnitOutcome.MAX_ATTEMPTS);
        assertThat(reaching.failure().limitReached()).isTrue();
        assertThat(afterwards.outcome()).isEqualTo(UnitOutcome.MAX_ATTEMPTS);
        assertThat(afterwards.failure()).isNull();
    }

    @ParameterizedTest(name = "attempt {0} of 3 -> limit reached {1}")
    @CsvSource({"1, false", "2, true", "3, false"})
    void reachesTheLimitThroughAReopen_whenTheCountFirstGetsThere(int previousAttempts, boolean limitReached) {
        // when
        FailureCount reopen = AutoRenewalGuards.countReopen(previousAttempts, 3);

        // then
        assertThat(reopen.limitReached()).isEqualTo(limitReached);
    }

    @Test
    void stopsRenewal_whenReopensHaveUsedUpTheAttempts() {
        // given
        var reopenedAtTheLimit = unit(false, SuccessorStatus.NONE, false, MAX_ATTEMPTS, null);

        // when
        UnitGuardResult result = AutoRenewalGuards.unit(reopenedAtTheLimit, NOW);

        // then
        assertThat(result.outcome()).isEqualTo(UnitOutcome.MAX_ATTEMPTS);
        assertThat(result.failure()).isNull();
    }

    @Test
    void countsOneMoreAttemptWithoutBackoff_whenAUnitIsReopened() {
        // given
        int previousAttempts = 2;

        // when
        FailureCount reopen = AutoRenewalGuards.countReopen(previousAttempts, MAX_ATTEMPTS);

        // then
        assertThat(reopen.attempt()).isEqualTo(previousAttempts + 1);
        assertThat(reopen.notBefore()).isNull();
        assertThat(reopen.limitReached()).isFalse();
    }

    // ── Failure counting ──────────────────────────────────────────────────────

    @ParameterizedTest(name = "attempt {0} -> {1} h")
    @CsvSource({"0, 1", "1, 6", "2, 24", "3, 24", "10, 24"})
    void backsOffOnTheRamp(int previousAttempts, long hours) {
        // when
        FailureCount failure = AutoRenewalGuards.countFailure(previousAttempts, 20, NOW);

        // then
        assertThat(failure.attempt()).isEqualTo(previousAttempts + 1);
        assertThat(failure.notBefore()).isEqualTo(NOW.plus(Duration.ofHours(hours)));
        assertThat(failure.limitReached()).isFalse();
    }

    @ParameterizedTest(name = "attempt {0} of 3 -> limit reached {1}")
    @CsvSource({"1, false", "2, true", "3, false"})
    void reachesTheLimitOnlyWhenTheCountFirstGetsThere(int previousAttempts, boolean limitReached) {
        assertThat(AutoRenewalGuards.countFailure(previousAttempts, 3, NOW).limitReached()).isEqualTo(limitReached);
    }

    // ── Successor status ──────────────────────────────────────────────────────

    @ParameterizedTest
    @EnumSource(CertificateState.class)
    void mapsTheCertificateState_toItsSuccessorStatus(CertificateState state) {
        // given
        SuccessorStatus expected = switch (state) {
            case ISSUED -> SuccessorStatus.ISSUED;
            case REVOKED -> SuccessorStatus.REVOKED;
            case FAILED, REJECTED -> SuccessorStatus.FAILED;
            default -> SuccessorStatus.IN_FLIGHT;
        };

        // when
        SuccessorStatus status = SuccessorStatus.of(state);

        // then
        assertThat(status).isEqualTo(expected);
    }

    @Test
    void readsAGoneSuccessorAsFailed() {
        assertThat(SuccessorStatus.of(null)).isEqualTo(SuccessorStatus.FAILED);
    }

    @ParameterizedTest
    @EnumSource(SuccessorStatus.class)
    void reportsIssued_whenTheSuccessorWasIssuedOrRevokedSince(SuccessorStatus status) {
        // given
        boolean issuedOrRevoked = status == SuccessorStatus.ISSUED || status == SuccessorStatus.REVOKED;

        // when
        boolean wasIssued = status.wasIssued();

        // then
        assertThat(wasIssued).isEqualTo(issuedOrRevoked);
    }

    // ── Foreign renewal ───────────────────────────────────────────────────────

    @Test
    void readsAForeignRenewal_whenARelationNamesASuccessorNotStarted() {
        // given
        var foreign = relationTo(CertificateState.PENDING_ISSUE);

        // when
        boolean foreignRenewal = AutoRenewalGuards.foreignRenewal(List.of(foreign), Set.of());

        // then
        assertThat(foreignRenewal).isTrue();
    }

    @Test
    void readsNoForeignRenewal_whenTheOnlyOtherSuccessorIsRevoked() {
        // given
        var revoked = relationTo(CertificateState.REVOKED);

        // when
        boolean foreignRenewal = AutoRenewalGuards.foreignRenewal(List.of(revoked), Set.of());

        // then
        assertThat(foreignRenewal).isFalse();
    }

    @Test
    void readsNoForeignRenewal_whenTheSuccessorWasStartedByTheUnit() {
        // given
        var started = relationTo(CertificateState.ISSUED);

        // when
        boolean foreignRenewal = AutoRenewalGuards
                .foreignRenewal(List.of(started), Set.of(started.getId().getSuccessorCertificateUuid()));

        // then
        assertThat(foreignRenewal).isFalse();
    }

    private static CertificateRelation relationTo(CertificateState successorState) {
        var successor = aCertificate().withUuid(UUID.randomUUID()).withState(successorState).build();
        var relation = new CertificateRelation();
        relation.getId().setSuccessorCertificateUuid(successor.getUuid());
        relation.setSuccessorCertificate(successor);
        return relation;
    }

    private static UnitInput unit(boolean completed, SuccessorStatus successor, boolean foreignRenewal, int attempt,
            Instant notBefore) {
        return new UnitInput(completed, successor, foreignRenewal, attempt, notBefore, MAX_ATTEMPTS);
    }
}

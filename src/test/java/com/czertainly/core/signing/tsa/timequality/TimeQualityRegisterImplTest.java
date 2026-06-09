package com.czertainly.core.signing.tsa.timequality;

import com.czertainly.api.model.messaging.timequality.LeapSecondWarning;
import com.czertainly.api.model.messaging.timequality.TimeQualityStatus;
import com.czertainly.core.model.signing.timequality.ExplicitTimeQualityConfigurationBuilder;
import com.czertainly.core.model.signing.timequality.LocalClockTimeQualityConfiguration;
import com.czertainly.core.util.clocksource.TestClockSource;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static com.czertainly.core.model.signing.timequality.ExplicitTimeQualityConfigurationBuilder.anExplicitTimeQualityConfiguration;
import static com.czertainly.core.signing.tsa.timequality.builders.TimeQualityResultBuilder.aTimeQualityResult;
import static org.assertj.core.api.Assertions.assertThat;

class TimeQualityRegisterImplTest {
    private static final Instant FIXED_NOW = Instant.parse("2026-03-04T10:05:00Z");
    private static final Duration MAX_DRIFT_500MS = Duration.ofMillis(500);

    // ── GetStatus ─────────────────────────────────────────────────────────────

    @Nested
    class GetStatus {

        @Test
        void returnsDegraded_whenNoResultExists() {
            // given
            var clock = TestClockSource.ofWallTime(FIXED_NOW);
            var register = new TimeQualityRegisterImpl(clock);

            // when
            var status = register.getStatus(ExplicitTimeQualityConfigurationBuilder.valid("profile1"));

            // then
            assertThat(status).isEqualTo(TimeQualityStatus.DEGRADED);
        }

        @Test
        void returnsOk_forFreshOkResult() {
            // given — result timestamp is 3 minutes ago, maxAge is 5 minutes → fresh
            var clock = TestClockSource.ofWallTime(FIXED_NOW);
            var register = new TimeQualityRegisterImpl(clock);
            var profile = ExplicitTimeQualityConfigurationBuilder.valid("profile1");
            register.update(aTimeQualityResult().withDefaults().configurationId(profile.uuid()).status(TimeQualityStatus.OK).timestamp(FIXED_NOW.minus(Duration.ofMinutes(3))).build());

            // when
            var status = register.getStatus(profile);

            // then
            assertThat(status).isEqualTo(TimeQualityStatus.OK);
        }

        @Test
        void returnsDegraded_forFreshDegradedResult() {
            // given — result is fresh but status is DEGRADED
            var clock = TestClockSource.ofWallTime(FIXED_NOW);
            var register = new TimeQualityRegisterImpl(clock);
            var profile = ExplicitTimeQualityConfigurationBuilder.valid("profile1");
            register.update(aTimeQualityResult().withDefaults().configurationId(profile.uuid()).status(TimeQualityStatus.DEGRADED).timestamp(FIXED_NOW.minus(Duration.ofMinutes(3))).build());

            // when
            var status = register.getStatus(profile);

            // then
            assertThat(status).isEqualTo(TimeQualityStatus.DEGRADED);
        }

        @Test
        void returnsDegraded_forStaleResult() {
            // given — result timestamp is 6 minutes ago, maxAge is 5 minutes → stale
            var clock = TestClockSource.ofWallTime(FIXED_NOW);
            var register = new TimeQualityRegisterImpl(clock);
            var profile = ExplicitTimeQualityConfigurationBuilder.valid("profile1");
            register.update(aTimeQualityResult().withDefaults().configurationId(profile.uuid()).status(TimeQualityStatus.OK).timestamp(FIXED_NOW.minus(Duration.ofMinutes(6))).build());

            // when
            var status = register.getStatus(profile);

            // then
            assertThat(status).isEqualTo(TimeQualityStatus.DEGRADED);
        }

        @Test
        void returnsDegraded_whenClockDriftsAboveThreshold() {
            // given — OK result received, then wall clock jumps forward beyond maxClockDrift
            var clock = TestClockSource.ofWallTime(FIXED_NOW);
            var profile = anExplicitTimeQualityConfiguration().withDefaults().name("rfc3161").maxClockDrift(MAX_DRIFT_500MS).build();
            var register = new TimeQualityRegisterImpl(clock);

            register.update(aTimeQualityResult().withDefaults().status(TimeQualityStatus.OK).timestamp(FIXED_NOW).build());

            // mono: +1s, wall: +2s → drift = 1000ms > 500ms
            clock.advanceMonoNanos(1_000_000_000L).advanceWallMillis(2_000);

            // when
            var status = register.getStatus(profile);

            // then
            assertThat(status).isEqualTo(TimeQualityStatus.DEGRADED);
        }

        @Test
        void returnsOk_whenClockDriftWithinThreshold() {
            // given — small drift within threshold
            var clock = TestClockSource.ofWallTime(FIXED_NOW);
            var profile = anExplicitTimeQualityConfiguration().withDefaults().name("rfc3161").maxClockDrift(MAX_DRIFT_500MS).build();
            var register = new TimeQualityRegisterImpl(clock);

            register.update(aTimeQualityResult().withDefaults().status(TimeQualityStatus.OK).timestamp(FIXED_NOW).build());

            // mono: +5s, wall: +5.4s → drift = 400ms < 500ms
            clock.advanceMonoNanos(5_000_000_000L);
            clock.advanceWallMillis(5_400);

            // when
            var status = register.getStatus(profile);

            // then
            assertThat(status).isEqualTo(TimeQualityStatus.OK);
        }

        @Test
        void returnsDegraded_whenInLeapSecondGuardWindow() {
            // given — wall clock at 23:59:59 UTC, leap indicator POSITIVE, guard enabled
            var midnight = Instant.parse("2026-06-30T23:59:59Z");
            var clock = TestClockSource.ofWallTimeMillis(midnight.toEpochMilli());
            var profile = anExplicitTimeQualityConfiguration().withDefaults().name("rfc3161").leapSecondGuard(true).build();
            var register = new TimeQualityRegisterImpl(clock);

            register.update(aTimeQualityResult().withDefaults().status(TimeQualityStatus.OK).leapSecondWarning(LeapSecondWarning.POSITIVE).timestamp(midnight).build());

            // when
            var status = register.getStatus(profile);

            // then
            assertThat(status).isEqualTo(TimeQualityStatus.DEGRADED);
        }

        @Test
        void returnsOk_whenLeapSecondGuardDisabled() {
            // given — in guard window with POSITIVE indicator, but guard disabled
            var midnight = Instant.parse("2026-06-30T23:59:59Z");
            var clock = TestClockSource.ofWallTimeMillis(midnight.toEpochMilli());
            var profile = anExplicitTimeQualityConfiguration().withDefaults().name("rfc3161").leapSecondGuard(false).build();
            var register = new TimeQualityRegisterImpl(clock);

            register.update(aTimeQualityResult().withDefaults().status(TimeQualityStatus.OK).leapSecondWarning(LeapSecondWarning.POSITIVE).timestamp(midnight).build());

            // when
            var status = register.getStatus(profile);

            // then
            assertThat(status).isEqualTo(TimeQualityStatus.OK);
        }

        @Test
        void alwaysReturnsOk_forLocalClockTimeQualityConfiguration() {
            // given — result timestamp is 3 minutes ago, maxAge is 5 minutes → fresh
            var clock = TestClockSource.ofWallTime(FIXED_NOW);
            var register = new TimeQualityRegisterImpl(clock);
            // inject a DEGRADED result — LocalClock profile ignores stored results and always returns OK
            register.update(aTimeQualityResult().withDefaults().status(TimeQualityStatus.DEGRADED).timestamp(FIXED_NOW.minus(Duration.ofMinutes(3))).build());

            // when
            var status = register.getStatus(LocalClockTimeQualityConfiguration.INSTANCE);

            // then
            assertThat(status).isEqualTo(TimeQualityStatus.OK);
        }
    }

    // ── Update ────────────────────────────────────────────────────────────────

    @Nested
    class Update {

        @Test
        void storesResult_forKnownProfile() {
            // given
            var clock = TestClockSource.ofWallTime(FIXED_NOW);
            var register = new TimeQualityRegisterImpl(clock);
            var profile = ExplicitTimeQualityConfigurationBuilder.valid("profile1");
            var result = aTimeQualityResult().withDefaults().configurationId(profile.uuid()).timestamp(FIXED_NOW.minus(Duration.ofMinutes(1))).build();

            // when
            register.update(result);

            // then
            assertThat(register.getStatus(profile)).isEqualTo(TimeQualityStatus.OK);
        }

        @Test
        void replacesExistingResult() {
            // given
            var clock = TestClockSource.ofWallTime(FIXED_NOW);
            var register = new TimeQualityRegisterImpl(clock);
            var profile = ExplicitTimeQualityConfigurationBuilder.valid("profile1");
            var first = aTimeQualityResult().withDefaults().configurationId(profile.uuid()).status(TimeQualityStatus.DEGRADED).timestamp(FIXED_NOW.minus(Duration.ofMinutes(1))).build();
            var second = aTimeQualityResult().withDefaults().configurationId(profile.uuid()).status(TimeQualityStatus.OK).timestamp(FIXED_NOW.minus(Duration.ofMinutes(1))).build();

            // when
            register.update(first);
            register.update(second);

            // then
            assertThat(register.getStatus(profile)).isEqualTo(TimeQualityStatus.OK);
        }

        @Test
        void clearsReferencePair_whenDegradedResultArrives() {
            // given — OK result sets reference pair, DEGRADED clears it
            var clock = TestClockSource.ofWallTime(FIXED_NOW);
            var register = new TimeQualityRegisterImpl(clock);
            var profile = ExplicitTimeQualityConfigurationBuilder.valid("profile1");

            register.update(aTimeQualityResult().withDefaults().configurationId(profile.uuid()).status(TimeQualityStatus.OK).timestamp(FIXED_NOW).build());
            register.update(aTimeQualityResult().withDefaults().configurationId(profile.uuid()).status(TimeQualityStatus.DEGRADED).timestamp(FIXED_NOW).build());

            // when — DEGRADED result stored, so getStatus returns DEGRADED
            var status = register.getStatus(profile);

            // then
            assertThat(status).isEqualTo(TimeQualityStatus.DEGRADED);
        }

        @Test
        void clearsAllPerKeyState_onRemove() {
            // given — register holds an OK result and a captured drift reference for an id
            var clock = TestClockSource.ofWallTime(FIXED_NOW);
            var register = new TimeQualityRegisterImpl(clock);
            var profile = ExplicitTimeQualityConfigurationBuilder.valid("profile1");
            register.update(aTimeQualityResult().withDefaults().configurationId(profile.uuid()).status(TimeQualityStatus.OK).timestamp(FIXED_NOW).build());
            // status read also populates lastLoggedStatus
            register.getStatus(profile);

            // when
            register.remove(profile.uuid());

            // then — after removal, status reverts to "no result yet" → DEGRADED
            assertThat(register.getStatus(profile)).isEqualTo(TimeQualityStatus.DEGRADED);
        }

        @Test
        void storesResult_whenUpdatesRunConcurrently() throws Exception {
            // given
            var clock = TestClockSource.ofWallTime(FIXED_NOW);
            var register = new TimeQualityRegisterImpl(clock);
            var profile = ExplicitTimeQualityConfigurationBuilder.valid("profile1");
            int threadCount = 50;
            var latch = new CountDownLatch(threadCount);

            // when
            try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
                for (int i = 0; i < threadCount; i++) {
                    var drift = (double) i;
                    executor.submit(() -> {
                        register.update(aTimeQualityResult().withDefaults().configurationId(profile.uuid()).measuredDriftMs(drift).timestamp(FIXED_NOW.minus(Duration.ofMinutes(1))).build());
                        latch.countDown();
                    });
                }
                assertThat(latch.await(30, TimeUnit.SECONDS))
                        .as("All virtual threads should complete within 30 s")
                        .isTrue();
            }

            // then — entry exists and has a valid status
            assertThat(register.getStatus(profile)).isEqualTo(TimeQualityStatus.OK);
        }
    }
}

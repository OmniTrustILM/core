package com.otilm.core.util.crl;

import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CrlDownloadGuardTest {

    private static final Duration WAIT_TIMEOUT = Duration.ofMillis(200);
    private static final Duration RETRY_AFTER_FAILURE = Duration.ofMinutes(1);
    private static final String ISSUER = "CN=Issuer|01";

    private final AtomicLong tickerNanos = new AtomicLong();
    private final ExecutorService executor = Executors.newFixedThreadPool(2);

    @AfterEach
    void stopExecutor() {
        executor.shutdownNow();
    }

    // ── UnderIssuerLock ──────────────────────────────────────────────────────

    @Nested
    class UnderIssuerLock {

        @Test
        void startsWorkForIssuer_onlyAfterRunningWorkForItEnds() throws Exception {
            // given
            var guard = new CrlDownloadGuard(1, Duration.ofSeconds(5), RETRY_AFTER_FAILURE, tickerNanos::get);
            var releaseFirst = new CountDownLatch(1);
            var firstRunning = new CountDownLatch(1);
            var secondStarted = new AtomicBoolean();
            executor.submit(() -> guard.underIssuerLock(ISSUER, () -> {
                firstRunning.countDown();
                return awaitRelease(releaseFirst);
            }));
            firstRunning.await(5, TimeUnit.SECONDS);

            // when
            Future<Boolean> second = executor.submit(() -> guard.underIssuerLock(ISSUER, () -> {
                secondStarted.set(true);
                return true;
            }));

            // then
            assertThat(waitBriefly(second)).as("second work waits for the first").isFalse();
            assertThat(secondStarted).isFalse();
            releaseFirst.countDown();
            assertThat(second.get(5, TimeUnit.SECONDS)).isTrue();
        }

        @Test
        void failsWaitingForIssuer_whenRunningWorkOutlastsWaitTimeout() throws Exception {
            // given
            var guard = guard(1);
            var releaseFirst = new CountDownLatch(1);
            var firstRunning = new CountDownLatch(1);
            executor.submit(() -> guard.underIssuerLock(ISSUER, () -> {
                firstRunning.countDown();
                return awaitRelease(releaseFirst);
            }));
            firstRunning.await(5, TimeUnit.SECONDS);

            // when
            ThrowingCallable second = () -> guard.underIssuerLock(ISSUER, () -> true);

            // then
            assertThatThrownBy(second)
                    .isInstanceOf(IOException.class)
                    .hasMessageContaining("Another validation is still reading the CRL of this issuer");
            releaseFirst.countDown();
        }

        // ── Helpers ──────────────────────────────────────────────────────────

        private static boolean waitBriefly(Future<Boolean> work) {
            try {
                return work.get(300, TimeUnit.MILLISECONDS);
            } catch (Exception e) {
                return false;
            }
        }
    }

    // ── WithDownloadPermit ───────────────────────────────────────────────────

    @Nested
    class WithDownloadPermit {

        @Test
        void failsWaitingForPermit_whenEveryPermitIsHeldPastWaitTimeout() throws Exception {
            // given
            var guard = guard(1);
            var releaseFirst = new CountDownLatch(1);
            var firstRunning = new CountDownLatch(1);
            executor.submit(() -> guard.withDownloadPermit(() -> {
                firstRunning.countDown();
                return awaitRelease(releaseFirst);
            }));
            firstRunning.await(5, TimeUnit.SECONDS);

            // when
            ThrowingCallable second = () -> guard.withDownloadPermit(() -> true);

            // then
            assertThatThrownBy(second)
                    .isInstanceOf(IOException.class)
                    .hasMessageContaining("Too many CRLs are being read at once");
            releaseFirst.countDown();
        }

        @Test
        void returnsPermit_whenWorkFails() throws Exception {
            // given
            var guard = guard(1);
            ThrowingCallable failingWork = () -> guard.withDownloadPermit(() -> {
                throw new IOException("unreachable");
            });
            assertThatThrownBy(failingWork).isInstanceOf(IOException.class);

            // when
            Boolean result = guard.withDownloadPermit(() -> true);

            // then
            assertThat(result).isTrue();
        }
    }

    // ── RecentFailures ───────────────────────────────────────────────────────

    @Nested
    class RecentFailures {

        @Test
        void rethrowsFailure_whenRetryIsNotDueYet() {
            // given
            var guard = guard(1);
            guard.rememberFailure("download", new IOException("Failed to read a usable CRL"));
            tickerNanos.addAndGet(RETRY_AFTER_FAILURE.minusSeconds(1).toNanos());

            // when
            ThrowingCallable rethrow = () -> guard.rethrowRecentFailure("download");

            // then
            assertThatThrownBy(rethrow)
                    .isInstanceOf(IOException.class)
                    .hasMessageContaining("Failed to read a usable CRL");
        }

        @Test
        void forgetsFailure_whenRetryIsDue() {
            // given
            var guard = guard(1);
            guard.rememberFailure("download", new IOException("Failed to read a usable CRL"));
            tickerNanos.addAndGet(RETRY_AFTER_FAILURE.plusSeconds(1).toNanos());

            // when
            ThrowingCallable rethrow = () -> guard.rethrowRecentFailure("download");

            // then
            assertThatCode(rethrow).doesNotThrowAnyException();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private CrlDownloadGuard guard(int maxConcurrentDownloads) {
        return new CrlDownloadGuard(maxConcurrentDownloads, WAIT_TIMEOUT, RETRY_AFTER_FAILURE, tickerNanos::get);
    }

    private static boolean awaitRelease(CountDownLatch release) throws IOException {
        try {
            return release.await(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException(e);
        }
    }
}

package com.otilm.core.util.crl;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Ticker;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Bounds what CRL downloads cost this Core instance. Each downloaded CRL is held in memory until it is stored, so:
 * <ul>
 * <li>validations of one issuer read its CRL one at a time, and those that waited find it stored;</li>
 * <li>at most {@code validation.crl.max-concurrent-downloads} CRLs are read at once;</li>
 * <li>a failed download is reported again for further certificates of the issuer until
 * {@code validation.crl.retry-after-failure} has passed, instead of being repeated for each of them.</li>
 * </ul>
 * Waits end after twice {@code validation.crl.download-timeout}, so one stuck download cannot hold up validations for
 * longer than that. The locks are reentrant locks, not monitors, so a virtual thread waiting for one releases its
 * carrier thread.
 */
@Component
public class CrlDownloadGuard {

    private static final int MAX_REMEMBERED_FAILURES = 10_000;

    private final ConcurrentHashMap<String, IssuerLock> issuerLocks = new ConcurrentHashMap<>();
    private final Semaphore downloadPermits;
    private final Duration waitTimeout;
    private final Cache<String, String> recentFailures;

    @Autowired
    public CrlDownloadGuard(@Value("${validation.crl.max-concurrent-downloads:4}") int maxConcurrentDownloads,
            @Value("${validation.crl.download-timeout:60s}") Duration downloadTimeout,
            @Value("${validation.crl.retry-after-failure:60s}") Duration retryAfterFailure) {
        this(maxConcurrentDownloads, downloadTimeout.multipliedBy(2), retryAfterFailure, Ticker.systemTicker());
    }

    CrlDownloadGuard(int maxConcurrentDownloads, Duration waitTimeout, Duration retryAfterFailure, Ticker ticker) {
        this.downloadPermits = new Semaphore(maxConcurrentDownloads, true);
        this.waitTimeout = waitTimeout;
        this.recentFailures = Caffeine
                .newBuilder()
                .ticker(ticker)
                .expireAfterWrite(retryAfterFailure)
                .maximumSize(MAX_REMEMBERED_FAILURES)
                .build();
    }

    /** Runs the work once no other work for the issuer runs. */
    public <T> T underIssuerLock(String issuerKey, CrlWork<T> work) throws IOException {
        IssuerLock issuerLock = issuerLocks.compute(issuerKey, (key, current) -> {
            IssuerLock used = current == null ? new IssuerLock() : current;
            used.users++;
            return used;
        });
        try {
            if (!await(() -> issuerLock.lock.tryLock(waitTimeout.toNanos(), TimeUnit.NANOSECONDS))) {
                throw new IOException("Another validation is still reading the CRL of this issuer");
            }
            try {
                return work.run();
            } finally {
                issuerLock.lock.unlock();
            }
        } finally {
            issuerLocks.computeIfPresent(issuerKey, (key, current) -> --current.users == 0 ? null : current);
        }
    }

    /** Runs the work holding one of the download permits. */
    public <T> T withDownloadPermit(CrlWork<T> work) throws IOException {
        if (!await(() -> downloadPermits.tryAcquire(waitTimeout.toNanos(), TimeUnit.NANOSECONDS))) {
            throw new IOException("Too many CRLs are being read at once");
        }
        try {
            return work.run();
        } finally {
            downloadPermits.release();
        }
    }

    public void rememberFailure(String downloadKey, IOException failure) {
        recentFailures.put(downloadKey, failure.getMessage());
    }

    /** Throws the failure remembered for the download, if it is not due for another attempt yet. */
    public void rethrowRecentFailure(String downloadKey) throws IOException {
        String failure = recentFailures.getIfPresent(downloadKey);
        if (failure != null) {
            throw new IOException(failure);
        }
    }

    private static boolean await(Wait wait) throws InterruptedIOException {
        try {
            return wait.acquired();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("Interrupted while waiting to read a CRL");
        }
    }

    @FunctionalInterface
    public interface CrlWork<T> {
        T run() throws IOException;
    }

    @FunctionalInterface
    private interface Wait {
        boolean acquired() throws InterruptedException;
    }

    /** A lock and the number of callers using it, so the map keeps a lock only while an issuer's work runs or waits. */
    private static final class IssuerLock {
        private final ReentrantLock lock = new ReentrantLock();
        private int users;
    }
}

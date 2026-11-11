package com.otilm.core.util.crl;

import com.otilm.core.util.LdapUtils;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLConnection;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.unit.DataSize;

/**
 * Downloads CRLs within a size limit and an overall deadline. A CRL is held whole in memory while it is checked and
 * stored, and the read timeout bounds each read only, so a server sending a byte now and then could otherwise keep a
 * download going for ever. Until the response headers have arrived, which includes connecting, the TLS handshake and
 * redirects, a watchdog closes the connection at the deadline; the body is read in a loop that checks the deadline
 * after each read.
 */
@Component
public class CrlDownloader {

    private static final int INITIAL_BUFFER_SIZE = 64 * 1024;

    private static final ScheduledExecutorService WATCHDOG = Executors
            .newSingleThreadScheduledExecutor(Thread.ofPlatform().daemon().name("crl-download-watchdog").factory());

    private final int connectTimeoutMillis;
    private final int readTimeoutMillis;
    private final DataSize maxSize;
    private final Duration downloadTimeout;

    @Autowired
    public CrlDownloader(@Value("${validation.crl.connect-timeout:1000}") int connectTimeoutMillis,
            @Value("${validation.crl.read-timeout:2000}") int readTimeoutMillis,
            @Value("${validation.crl.max-size:64MB}") DataSize maxSize,
            @Value("${validation.crl.download-timeout:60s}") Duration downloadTimeout) {
        if (maxSize.toBytes() <= 0 || maxSize.toBytes() > Integer.MAX_VALUE - 8) {
            throw new IllegalArgumentException("validation.crl.max-size must be between 1 byte and 2 GB");
        }
        this.connectTimeoutMillis = connectTimeoutMillis;
        this.readTimeoutMillis = readTimeoutMillis;
        this.maxSize = maxSize;
        this.downloadTimeout = downloadTimeout;
    }

    /**
     * Returns the CRL the URL serves.
     *
     * @throws CrlDownloadException when the CRL is larger than the size limit, or an HTTP download outlasts the
     * deadline; an LDAP download outlasting it fails as unreadable
     * @throws IOException when the CRL cannot be read
     */
    public byte[] download(String crlUrl) throws IOException {
        if (crlUrl.startsWith("ldap")) {
            return downloadFromLdap(crlUrl);
        }
        long deadline = System.nanoTime() + downloadTimeout.toNanos();
        URLConnection connection = URI.create(crlUrl).toURL().openConnection();
        connection.setConnectTimeout(connectTimeoutMillis);
        connection.setReadTimeout(readTimeoutMillis);
        AtomicBoolean timedOut = new AtomicBoolean();
        ScheduledFuture<?> watchdog = connection instanceof HttpURLConnection httpConnection ? WATCHDOG.schedule(() -> {
            timedOut.set(true);
            httpConnection.disconnect();
        }, downloadTimeout.toNanos(), TimeUnit.NANOSECONDS) : null;
        try {
            InputStream body = connection.getInputStream();
            if (watchdog != null) {
                watchdog.cancel(false);
            }
            try (body) {
                long declaredLength = connection.getContentLengthLong();
                if (declaredLength > maxSize.toBytes()) {
                    throw tooLarge(crlUrl);
                }
                return readWithinLimits(crlUrl, body, declaredLength, deadline);
            }
        } catch (IOException e) {
            if (timedOut.get()) {
                throw tooSlow(crlUrl);
            }
            throw e;
        } finally {
            if (watchdog != null) {
                watchdog.cancel(false);
            }
            if (connection instanceof HttpURLConnection httpConnection) {
                httpConnection.disconnect();
            }
        }
    }

    /**
     * Reads the body into an array that grows as bytes arrive, so a server cannot make Core hold memory it has not
     * sent. Growth stops at the declared length, so a body that matches it ends in an array of its exact size, without
     * a final copy; a body longer than declared, or without a declared length, grows up to the size limit.
     */
    private byte[] readWithinLimits(String crlUrl, InputStream body, long declaredLength, long deadline)
            throws IOException {
        long maxBytes = maxSize.toBytes();
        long expected = declaredLength > 0 ? declaredLength : maxBytes;
        byte[] data = new byte[(int) Math.min(expected, INITIAL_BUFFER_SIZE)];
        int size = 0;
        while (true) {
            if (size == data.length) {
                int next = body.read();
                if (next == -1) {
                    return data;
                }
                if (size >= maxBytes) {
                    throw tooLarge(crlUrl);
                }
                long grown = size < expected ? Math.min(expected, 2L * size) : 2L * size;
                data = Arrays.copyOf(data, (int) Math.min(maxBytes, grown));
                data[size++] = (byte) next;
            }
            int read = body.read(data, size, data.length - size);
            if (read == -1) {
                return Arrays.copyOf(data, size);
            }
            size += read;
            if (System.nanoTime() - deadline > 0) {
                throw tooSlow(crlUrl);
            }
        }
    }

    /** JNDI reads the whole attribute before returning it, so its size can be checked only afterwards. */
    private byte[] downloadFromLdap(String crlUrl) throws IOException {
        byte[] crl;
        try {
            crl = LdapUtils.downloadFromLdap(crlUrl, connectTimeoutMillis, (int) downloadTimeout.toMillis());
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Failed to read the CRL from LDAP: " + e.getMessage(), e);
        }
        if (crl == null) {
            throw new IOException("Crl not available in LDAP.");
        }
        if (crl.length > maxSize.toBytes()) {
            throw tooLarge(crlUrl);
        }
        return crl;
    }

    private CrlDownloadException tooSlow(String crlUrl) {
        return new CrlDownloadException(crlUrl, "its download took longer than " + describe(downloadTimeout));
    }

    private CrlDownloadException tooLarge(String crlUrl) {
        return new CrlDownloadException(crlUrl, "it is larger than the " + describe(maxSize) + " limit");
    }

    private static String describe(DataSize size) {
        long bytes = size.toBytes();
        if (bytes % DataSize.ofMegabytes(1).toBytes() == 0) {
            return size.toMegabytes() + " MB";
        }
        if (bytes % DataSize.ofKilobytes(1).toBytes() == 0) {
            return size.toKilobytes() + " KB";
        }
        return bytes + " bytes";
    }

    private static String describe(Duration duration) {
        if (duration.toMillis() % 1_000 == 0) {
            return duration.toSeconds() + " s";
        }
        return duration.toMillis() + " ms";
    }
}

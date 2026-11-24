package com.otilm.core.util.crl;

import com.otilm.core.util.LdapUtils;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.time.Duration;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import javax.naming.NamingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.unit.DataSize;

/**
 * Downloads CRLs within a size limit and a deadline, since a CRL is held whole in memory and the read timeout bounds
 * each read only. The caller interrupts the HTTP download at the deadline. The worker also checks the deadline between
 * reads because buffered reads can finish without blocking.
 */
@Component
public class CrlDownloader {

    private static final int INITIAL_BUFFER_SIZE = 64 * 1024;

    private static final ExecutorService DOWNLOADS = Executors
            .newThreadPerTaskExecutor(Thread.ofVirtual().name("crl-download-", 0).factory());

    private final ConnectionOpener connectionOpener;
    private final int connectTimeoutMillis;
    private final int readTimeoutMillis;
    private final DataSize maxSize;
    private final Duration downloadTimeout;

    @Autowired
    public CrlDownloader(@Value("${validation.crl.connect-timeout:1000}") int connectTimeoutMillis,
            @Value("${validation.crl.read-timeout:2000}") int readTimeoutMillis,
            @Value("${validation.crl.max-size:64MB}") DataSize maxSize,
            @Value("${validation.crl.download-timeout:60s}") Duration downloadTimeout) {
        this(URL::openConnection, connectTimeoutMillis, readTimeoutMillis, maxSize, downloadTimeout);
    }

    CrlDownloader(ConnectionOpener connectionOpener, int connectTimeoutMillis, int readTimeoutMillis, DataSize maxSize,
            Duration downloadTimeout) {
        if (maxSize.toBytes() <= 0 || maxSize.toBytes() > Integer.MAX_VALUE - 8) {
            throw new IllegalArgumentException("validation.crl.max-size must be between 1 byte and 2 GB");
        }
        this.connectionOpener = connectionOpener;
        this.connectTimeoutMillis = connectTimeoutMillis;
        this.readTimeoutMillis = readTimeoutMillis;
        this.maxSize = maxSize;
        this.downloadTimeout = downloadTimeout;
    }

    /** How long downloading may take: one download, or all those of one read of an issuer's CRLs. */
    public Duration downloadTimeout() {
        return downloadTimeout;
    }

    /** Returns the CRL the URL serves within one download timeout from now, as {@link #download(String, long)}. */
    public byte[] download(String crlUrl) throws IOException {
        return download(crlUrl, System.nanoTime() + downloadTimeout.toNanos());
    }

    /**
     * Returns the CRL the URL serves, read before the deadline. Only http, https, ldap and ldaps URLs are read: the JDK
     * opens other schemes, such as {@code jar:}, over connections that take none of the timeouts.
     *
     * @param deadline as {@link System#nanoTime()}
     * @throws CrlDownloadException when the URL's scheme is not read, the CRL is larger than the size limit, the
     * deadline has passed before the download starts, or an HTTP download outlasts it; an LDAP download outlasting it
     * fails as unreadable
     * @throws IOException when the CRL cannot be read
     */
    public byte[] download(String crlUrl, long deadline) throws IOException {
        String scheme = schemeOf(crlUrl);
        boolean ldap = scheme.equals("ldap") || scheme.equals("ldaps");
        if (!ldap && !scheme.equals("http") && !scheme.equals("https")) {
            throw new CrlDownloadException(crlUrl, "its URL is not an http, https, ldap or ldaps URL");
        }
        long remaining = deadline - System.nanoTime();
        if (remaining <= 0) {
            throw new CrlDownloadException(crlUrl,
                    "the " + describe(downloadTimeout) + " for reading the CRL had passed before it was requested");
        }
        if (ldap) {
            return downloadFromLdap(crlUrl, remaining);
        }
        return downloadFromHttp(crlUrl, URI.create(crlUrl).toURL(), deadline);
    }

    /**
     * Runs the download on a virtual thread and stops waiting for it at the deadline. Disconnecting cannot bound the
     * download: it has no effect while the JDK opens a connection, for a redirect it follows or a request it retries by
     * itself, and one read of a chunked body runs until a chunk's data arrives, however slowly its framing comes in.
     * Interrupting a virtual thread instead closes the socket it is blocked on, whichever phase the download is in. A
     * name lookup cannot be interrupted; it ends at the resolver's own time-out, and the caller no longer waits for it.
     */
    private byte[] downloadFromHttp(String crlUrl, URL url, long deadline) throws IOException {
        Future<byte[]> download = DOWNLOADS.submit(() -> readFromHttp(crlUrl, url, deadline));
        try {
            return download.get(deadline - System.nanoTime(), TimeUnit.NANOSECONDS);
        } catch (TimeoutException e) {
            throw tooSlow(crlUrl);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("Interrupted while reading a CRL");
        } catch (ExecutionException e) {
            if (e.getCause() instanceof IOException failure) {
                throw failure;
            }
            if (e.getCause() instanceof RuntimeException failure) {
                throw failure;
            }
            if (e.getCause() instanceof Error failure) {
                throw failure;
            }
            throw new IllegalStateException("The CRL download failed unexpectedly", e.getCause());
        } finally {
            download.cancel(true);
        }
    }

    private byte[] readFromHttp(String crlUrl, URL url, long deadline) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) connectionOpener.open(url);
        connection.setConnectTimeout(connectTimeoutMillis);
        connection.setReadTimeout(readTimeoutMillis);
        try (InputStream body = connection.getInputStream()) {
            long declaredLength = connection.getContentLengthLong();
            if (declaredLength > maxSize.toBytes()) {
                throw tooLarge(crlUrl);
            }
            return readWithinLimits(crlUrl, body, declaredLength, deadline);
        } finally {
            connection.disconnect();
        }
    }

    /**
     * Reads the body into an array that grows as bytes arrive, so a server cannot make Core hold memory it has not
     * sent. Growth stops at the declared length, so a body that matches it ends in an array of its exact size, without
     * a final copy; a body longer than declared, or without a declared length, grows up to the size limit.
     */
    byte[] readWithinLimits(String crlUrl, InputStream body, long declaredLength, long deadline) throws IOException {
        long maxBytes = maxSize.toBytes();
        long expected = declaredLength > 0 ? declaredLength : maxBytes;
        byte[] data = new byte[(int) Math.min(expected, INITIAL_BUFFER_SIZE)];
        int size = 0;
        while (true) {
            if (size == data.length) {
                int next = body.read();
                requireWithinDeadline(crlUrl, deadline);
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
            requireWithinDeadline(crlUrl, deadline);
            if (read == -1) {
                return Arrays.copyOf(data, size);
            }
            size += read;
        }
    }

    /** Checked after every read, also the one that ends the body, so a body ending past the deadline is refused. */
    private void requireWithinDeadline(String crlUrl, long deadline) throws CrlDownloadException {
        if (System.nanoTime() - deadline > 0) {
            throw tooSlow(crlUrl);
        }
    }

    private static String schemeOf(String crlUrl) {
        int colon = crlUrl.indexOf(':');
        return colon < 0 ? "" : crlUrl.substring(0, colon).toLowerCase(Locale.ROOT);
    }

    /**
     * JNDI reads the whole attribute before returning it, so its size can be checked only afterwards. The time left
     * bounds the wait for each LDAP response, as JNDI has no deadline for the whole exchange.
     */
    private byte[] downloadFromLdap(String crlUrl, long remainingNanos) throws IOException {
        int remainingMillis = Math.clamp(TimeUnit.NANOSECONDS.toMillis(remainingNanos), 1, Integer.MAX_VALUE);
        byte[] crl;
        try {
            crl = LdapUtils.downloadFromLdap(crlUrl, Math.min(connectTimeoutMillis, remainingMillis), remainingMillis);
        } catch (NamingException | RuntimeException e) {
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

    @FunctionalInterface
    interface ConnectionOpener {
        URLConnection open(URL url) throws IOException;
    }
}

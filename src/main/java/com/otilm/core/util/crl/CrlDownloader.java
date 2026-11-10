package com.otilm.core.util.crl;

import com.otilm.core.util.LdapUtils;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLConnection;
import java.time.Duration;
import java.util.Arrays;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.unit.DataSize;

/**
 * Downloads CRLs within a size limit and an overall deadline. A CRL is held whole in memory while it is checked and
 * stored, and the read timeout bounds each read only, so a server sending a byte now and then could otherwise keep a
 * download going for ever.
 */
@Component
public class CrlDownloader {

    private static final int INITIAL_BUFFER_SIZE = 64 * 1024;

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
     * @throws CrlDownloadException when the CRL is larger than the size limit or its download outlasts the deadline
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
        try {
            long declaredLength = connection.getContentLengthLong();
            if (declaredLength > maxSize.toBytes()) {
                throw tooLarge(crlUrl);
            }
            try (InputStream body = connection.getInputStream()) {
                return readWithinLimits(crlUrl, body, (int) Math.max(declaredLength, 0), deadline);
            }
        } finally {
            if (connection instanceof HttpURLConnection httpConnection) {
                httpConnection.disconnect();
            }
        }
    }

    /**
     * Reads the body into an array sized to the declared length, so a CRL that declares it is not copied, and grows the
     * array only for a body longer than declared or without a declared length.
     */
    private byte[] readWithinLimits(String crlUrl, InputStream body, int declaredLength, long deadline)
            throws IOException {
        byte[] data = new byte[declaredLength > 0 ? declaredLength : INITIAL_BUFFER_SIZE];
        int size = 0;
        while (true) {
            if (size == data.length) {
                int next = body.read();
                if (next == -1) {
                    return data;
                }
                if (size >= maxSize.toBytes()) {
                    throw tooLarge(crlUrl);
                }
                data = Arrays.copyOf(data, (int) Math.min(maxSize.toBytes(), Math.max(INITIAL_BUFFER_SIZE, 2L * size)));
                data[size++] = (byte) next;
            }
            int read = body.read(data, size, data.length - size);
            if (read == -1) {
                return Arrays.copyOf(data, size);
            }
            size += read;
            if (System.nanoTime() - deadline > 0) {
                throw new CrlDownloadException(crlUrl, "its download took longer than " + describe(downloadTimeout));
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

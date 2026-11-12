package com.otilm.core.util.crl;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.otilm.core.util.LoopbackWireMock;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.SequenceInputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.util.Arrays;
import java.util.Random;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.util.unit.DataSize;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;

class CrlDownloaderTest {

    private static final DataSize SIZE_LIMIT = DataSize.ofKilobytes(64);
    private static final Duration DOWNLOAD_TIMEOUT = Duration.ofSeconds(5);
    private static final int CONNECT_TIMEOUT_MILLIS = 1_000;
    private static final int READ_TIMEOUT_MILLIS = 1_000;
    private static final String CRL_PATH = "/ca.crl";
    /** Bounds how long a silent server holds a connection its client never closes. */
    private static final int HOLD_LIMIT_MILLIS = 20_000;

    private WireMockServer crlServer;

    @BeforeEach
    void startCrlServer() {
        crlServer = LoopbackWireMock.start();
    }

    @AfterEach
    void stopCrlServer() {
        crlServer.stop();
    }

    @Test
    void returnsBody_whenCrlFitsSizeLimit() throws Exception {
        // given
        byte[] crlWithinLimit = bytes((int) SIZE_LIMIT.toBytes());
        stubCrl(aResponse().withBody(crlWithinLimit));

        // when
        byte[] downloaded = downloader(DOWNLOAD_TIMEOUT).download(crlUrl());

        // then
        assertThat(downloaded).isEqualTo(crlWithinLimit);
    }

    @Test
    void returnsBody_whenDeclaredBodyOutgrowsTheInitialBuffer() throws Exception {
        // given
        byte[] crlLargerThanInitialBuffer = distinctBytes(200 * 1024);
        stubCrl(aResponse().withBody(crlLargerThanInitialBuffer));

        // when
        byte[] downloaded = downloader(DOWNLOAD_TIMEOUT, DataSize.ofMegabytes(1)).download(crlUrl());

        // then
        assertThat(downloaded).isEqualTo(crlLargerThanInitialBuffer);
    }

    @Test
    void returnsBody_whenUndeclaredBodyOutgrowsTheInitialBuffer() throws Exception {
        // given
        byte[] crlLargerThanInitialBuffer = distinctBytes(200 * 1024);
        stubCrl(aResponse().withBody(crlLargerThanInitialBuffer).withChunkedDribbleDelay(8, 200));

        // when
        byte[] downloaded = downloader(DOWNLOAD_TIMEOUT, DataSize.ofMegabytes(1)).download(crlUrl());

        // then
        assertThat(downloaded).isEqualTo(crlLargerThanInitialBuffer);
    }

    @ParameterizedTest
    @ValueSource(strings = {"jar:http://%s:%d/x.jar!/ca.crl", "ftp://%s:%d/ca.crl", "file:///%s/%d/ca.crl"})
    @Timeout(20)
    void refusesCrl_whenUrlIsNotHttpOrLdap(String urlPattern) throws Exception {
        // given
        try (ServerSocket silentServer = new ServerSocket(0, 1, InetAddress.getByName(LoopbackWireMock.HOST))) {
            Thread.ofVirtual().start(() -> readRequestWithoutAnswering(silentServer));
            String unreadScheme = urlPattern.formatted(LoopbackWireMock.HOST, silentServer.getLocalPort());

            // when
            ThrowingCallable download = () -> downloader(DOWNLOAD_TIMEOUT).download(unreadScheme);

            // then
            assertThatThrownBy(download)
                    .isInstanceOfSatisfying(CrlDownloadException.class,
                            e -> assertThat(e.reason()).isEqualTo("its URL is not an http, https, ldap or ldaps URL"));
        }
    }

    @Test
    void refusesCrlWithoutRequestingIt_whenSharedDeadlineHasPassed() {
        // given
        stubCrl(aResponse().withBody(bytes(10)));
        long passedDeadline = System.nanoTime() - 1;

        // when
        ThrowingCallable download = () -> downloader(DOWNLOAD_TIMEOUT).download(crlUrl(), passedDeadline);

        // then
        assertThatThrownBy(download)
                .isInstanceOfSatisfying(CrlDownloadException.class, e -> assertThat(e.reason())
                        .isEqualTo("the 5 s for reading the CRL had passed before it was requested"));
        crlServer.verify(0, getRequestedFor(urlPathEqualTo(CRL_PATH)));
    }

    @Test
    @Timeout(20)
    void failsWithinDeadline_whenLdapServerNeverAnswers() throws Exception {
        // given
        var deadlineShorterThanReadTimeout = Duration.ofMillis(800);
        var readTimeoutMillis = 5_000;
        try (ServerSocket silentServer = new ServerSocket(0, 1, InetAddress.getByName(LoopbackWireMock.HOST))) {
            Thread.ofVirtual().start(() -> readRequestWithoutAnswering(silentServer));
            String ldapUrl = "ldap://%s:%d/cn=CA?certificateRevocationList;binary?base"
                    .formatted(LoopbackWireMock.HOST, silentServer.getLocalPort());
            var downloader = new CrlDownloader(CONNECT_TIMEOUT_MILLIS, readTimeoutMillis, SIZE_LIMIT,
                    deadlineShorterThanReadTimeout);

            // when
            long start = System.nanoTime();
            ThrowingCallable download = () -> downloader.download(ldapUrl);

            // then
            assertThatThrownBy(download).isInstanceOf(IOException.class).hasMessageContaining("read timed out");
            assertThat(Duration.ofNanos(System.nanoTime() - start))
                    .as("stopped by the deadline, not by the 5 s read timeout")
                    .isLessThan(Duration.ofSeconds(3));
        }
    }

    @Test
    void refusesCrl_whenDeclaredLengthExceedsSizeLimit() {
        // given
        byte[] crlOverLimit = bytes((int) SIZE_LIMIT.toBytes() + 1);
        stubCrl(aResponse().withBody(crlOverLimit));

        // when
        ThrowingCallable download = () -> downloader(DOWNLOAD_TIMEOUT).download(crlUrl());

        // then
        assertThatThrownBy(download)
                .isInstanceOfSatisfying(CrlDownloadException.class,
                        e -> assertThat(e.reason()).isEqualTo("it is larger than the 64 KB limit"));
    }

    @Test
    void refusesCrl_whenUndeclaredLengthExceedsSizeLimit() {
        // given
        byte[] crlOverLimit = bytes((int) SIZE_LIMIT.toBytes() * 3);
        stubCrl(aResponse().withBody(crlOverLimit).withChunkedDribbleDelay(6, 100));

        // when
        ThrowingCallable download = () -> downloader(DOWNLOAD_TIMEOUT).download(crlUrl());

        // then
        assertThatThrownBy(download)
                .isInstanceOfSatisfying(CrlDownloadException.class,
                        e -> assertThat(e.reason()).isEqualTo("it is larger than the 64 KB limit"));
    }

    @Test
    void refusesCrl_whenDownloadOutlastsDeadline() {
        // given
        var deadlineShorterThanTransfer = Duration.ofMillis(500);
        byte[] slowlySentCrl = bytes(10_000);
        stubCrl(aResponse().withBody(slowlySentCrl).withChunkedDribbleDelay(10, 2_000));

        // when
        ThrowingCallable download = () -> downloader(deadlineShorterThanTransfer).download(crlUrl());

        // then
        assertThatThrownBy(download)
                .isInstanceOfSatisfying(CrlDownloadException.class,
                        e -> assertThat(e.reason()).isEqualTo("its download took longer than 500 ms"));
    }

    @Test
    @Timeout(20)
    void refusesCrl_whenNoResponseHeadersArriveBeforeDeadline() throws Exception {
        // given
        var deadlineShorterThanReadTimeout = Duration.ofMillis(800);
        var readTimeoutMillis = 5_000;
        try (ServerSocket silentServer = new ServerSocket(0, 1, InetAddress.getByName(LoopbackWireMock.HOST))) {
            Thread.ofVirtual().start(() -> readRequestWithoutAnswering(silentServer));
            String url = LoopbackWireMock.url(silentServer.getLocalPort()) + CRL_PATH;
            var downloader = new CrlDownloader(CONNECT_TIMEOUT_MILLIS, readTimeoutMillis, SIZE_LIMIT,
                    deadlineShorterThanReadTimeout);

            // when
            long start = System.nanoTime();
            ThrowingCallable download = () -> downloader.download(url);

            // then
            assertThatThrownBy(download)
                    .isInstanceOfSatisfying(CrlDownloadException.class,
                            e -> assertThat(e.reason()).isEqualTo("its download took longer than 800 ms"));
            assertThat(Duration.ofNanos(System.nanoTime() - start))
                    .as("stopped by the deadline, not by the 5 s read timeout")
                    .isLessThan(Duration.ofSeconds(3));
        }
    }

    @Test
    void refusesCrl_whenEndOfDeclaredBodyArrivesAfterDeadline() {
        // given
        var downloadTimeout = Duration.ofMillis(200);
        long deadline = System.nanoTime() + downloadTimeout.toNanos();
        byte[] declaredBody = bytes(10);
        InputStream bodyEndingLate = bodyEndingAfter(declaredBody, deadline);

        // when
        ThrowingCallable read = () -> downloader(downloadTimeout)
                .readWithinLimits(CRL_PATH, bodyEndingLate, declaredBody.length, deadline);

        // then
        assertThatThrownBy(read)
                .isInstanceOfSatisfying(CrlDownloadException.class,
                        e -> assertThat(e.reason()).isEqualTo("its download took longer than 200 ms"));
    }

    @Test
    void refusesCrl_whenEndOfUndeclaredBodyArrivesAfterDeadline() {
        // given
        var downloadTimeout = Duration.ofMillis(200);
        long deadline = System.nanoTime() + downloadTimeout.toNanos();
        InputStream bodyEndingLate = bodyEndingAfter(bytes(10), deadline);

        // when
        ThrowingCallable read = () -> downloader(downloadTimeout)
                .readWithinLimits(CRL_PATH, bodyEndingLate, -1, deadline);

        // then
        assertThatThrownBy(read)
                .isInstanceOfSatisfying(CrlDownloadException.class,
                        e -> assertThat(e.reason()).isEqualTo("its download took longer than 200 ms"));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Returns the bytes at once, then signals the end of the body only once the deadline has passed. */
    private static InputStream bodyEndingAfter(byte[] body, long deadline) {
        return new SequenceInputStream(new ByteArrayInputStream(body), new InputStream() {
            @Override
            public int read() {
                await()
                        .atMost(Duration.ofSeconds(5))
                        .pollInterval(Duration.ofMillis(10))
                        .until(() -> System.nanoTime() - deadline > 0);
                return -1;
            }
        });
    }

    /**
     * Reads the request and never answers, holding the connection until the client hangs up, as a stalled server does.
     */
    private static void readRequestWithoutAnswering(ServerSocket server) {
        try (Socket client = server.accept()) {
            client.setSoTimeout(HOLD_LIMIT_MILLIS);
            client.getInputStream().transferTo(OutputStream.nullOutputStream());
        } catch (IOException connectionEnded) {
            // the client hung up, or the hold limit passed
        }
    }

    private void stubCrl(ResponseDefinitionBuilder response) {
        crlServer.stubFor(get(urlPathEqualTo(CRL_PATH)).willReturn(response.withStatus(200)));
    }

    private String crlUrl() {
        return LoopbackWireMock.url(crlServer) + CRL_PATH;
    }

    private static CrlDownloader downloader(Duration downloadTimeout) {
        return downloader(downloadTimeout, SIZE_LIMIT);
    }

    private static CrlDownloader downloader(Duration downloadTimeout, DataSize sizeLimit) {
        return new CrlDownloader(CONNECT_TIMEOUT_MILLIS, READ_TIMEOUT_MILLIS, sizeLimit, downloadTimeout);
    }

    /** Bytes that differ along the body, so a byte lost or repeated where the buffer grows shows. */
    private static byte[] distinctBytes(int length) {
        byte[] bytes = new byte[length];
        new Random(length).nextBytes(bytes);
        return bytes;
    }

    private static byte[] bytes(int length) {
        byte[] bytes = new byte[length];
        Arrays.fill(bytes, (byte) 0x5a);
        return bytes;
    }
}

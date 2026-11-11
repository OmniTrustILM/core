package com.otilm.core.util.crl;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.otilm.core.util.LoopbackWireMock;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.util.Arrays;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.util.unit.DataSize;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CrlDownloaderTest {

    private static final DataSize SIZE_LIMIT = DataSize.ofKilobytes(64);
    private static final Duration DOWNLOAD_TIMEOUT = Duration.ofSeconds(5);
    private static final int CONNECT_TIMEOUT_MILLIS = 1_000;
    private static final int READ_TIMEOUT_MILLIS = 1_000;
    private static final String CRL_PATH = "/ca.crl";

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
        try (ServerSocket silentServer = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
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
        byte[] declaredBody = bytes(10);
        InputStream bodyEndingLate = bodyThatEndsAfter(declaredBody, Duration.ofMillis(400));
        long deadline = System.nanoTime() + downloadTimeout.toNanos();

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
        InputStream bodyEndingLate = bodyThatEndsAfter(bytes(10), Duration.ofMillis(400));
        long deadline = System.nanoTime() + downloadTimeout.toNanos();

        // when
        ThrowingCallable read = () -> downloader(downloadTimeout)
                .readWithinLimits(CRL_PATH, bodyEndingLate, -1, deadline);

        // then
        assertThatThrownBy(read)
                .isInstanceOfSatisfying(CrlDownloadException.class,
                        e -> assertThat(e.reason()).isEqualTo("its download took longer than 200 ms"));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Returns the bytes at once, then signals the end of the body only after the delay. */
    private static InputStream bodyThatEndsAfter(byte[] body, Duration delay) {
        return new SequenceInputStream(new ByteArrayInputStream(body), new InputStream() {
            @Override
            public int read() throws IOException {
                try {
                    Thread.sleep(delay.toMillis());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException(e);
                }
                return -1;
            }
        });
    }

    /** Reads the request and keeps the connection open without answering, as a stalled server does. */
    private static void readRequestWithoutAnswering(ServerSocket server) {
        try (Socket client = server.accept()) {
            client.getInputStream().read(new byte[4096]);
            Thread.sleep(15_000);
        } catch (Exception e) {
            Thread.currentThread().interrupt();
        }
    }

    private void stubCrl(ResponseDefinitionBuilder response) {
        crlServer.stubFor(get(urlPathEqualTo(CRL_PATH)).willReturn(response.withStatus(200)));
    }

    private String crlUrl() {
        return LoopbackWireMock.url(crlServer) + CRL_PATH;
    }

    private static CrlDownloader downloader(Duration downloadTimeout) {
        return new CrlDownloader(CONNECT_TIMEOUT_MILLIS, READ_TIMEOUT_MILLIS, SIZE_LIMIT, downloadTimeout);
    }

    private static byte[] bytes(int length) {
        byte[] bytes = new byte[length];
        Arrays.fill(bytes, (byte) 0x5a);
        return bytes;
    }
}

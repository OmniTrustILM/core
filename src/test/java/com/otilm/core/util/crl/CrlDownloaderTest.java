package com.otilm.core.util.crl;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.otilm.core.util.LoopbackWireMock;
import java.time.Duration;
import java.util.Arrays;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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

    // ── Helpers ───────────────────────────────────────────────────────────────

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

package com.otilm.core.service.acme;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.otilm.api.exception.AcmeProblemDocumentException;
import com.otilm.api.model.core.acme.Problem;
import com.otilm.core.util.LoopbackWireMock;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Timeout.ThreadMode.SEPARATE_THREAD;

/**
 * Challenge hosts are reached through a loopback proxy, so the challenge URL keeps the port 80 every HTTP-01 challenge
 * starts on while a local server plays the host.
 */
class AcmeHttpChallengeValidatorTest {

    private static final String IDENTIFIER = "www.example.test";
    private static final String TOKEN = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0";
    private static final String KEY_AUTHORIZATION = TOKEN + ".9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI";
    private static final String CHALLENGE_PATH = "/.well-known/acme-challenge/" + TOKEN;
    private static final int CONNECT_TIMEOUT_MILLIS = 1_000;
    private static final int READ_TIMEOUT_MILLIS = 5_000;
    private static final Duration DEADLINE = Duration.ofSeconds(5);
    /** Bounds how long a silent host holds a connection its client never closes. */
    private static final int HOLD_LIMIT_MILLIS = 20_000;
    /** Well below the read timeout, so only the cancelled fetch, not its own timeouts, can close in time. */
    private static final Duration CONNECTION_CLOSE_WAIT = Duration.ofSeconds(2);

    private WireMockServer challengeHost;

    @BeforeEach
    void startChallengeHost() {
        challengeHost = LoopbackWireMock.start();
    }

    @AfterEach
    void stopChallengeHost() {
        challengeHost.stop();
    }

    @Test
    void acceptsChallenge_whenHostServesKeyAuthorization() throws Exception {
        // given
        stubChallenge(aResponse().withStatus(200).withBody(KEY_AUTHORIZATION + "\r\n"));

        // when
        ChallengeValidationResult result = validatorThrough(challengeHost.port(), DEADLINE)
                .validate(IDENTIFIER, TOKEN, KEY_AUTHORIZATION);

        // then
        assertThat(result.valid()).isTrue();
    }

    @Test
    void acceptsChallenge_whenRedirectLeadsToKeyAuthorization() throws Exception {
        // given
        var redirectTarget = "/.well-known/acme-challenge/moved";
        stubChallenge(aResponse().withStatus(302).withHeader("Location", "http://" + IDENTIFIER + redirectTarget));
        challengeHost
                .stubFor(get(urlPathEqualTo(redirectTarget))
                        .willReturn(aResponse().withStatus(200).withBody(KEY_AUTHORIZATION)));

        // when
        ChallengeValidationResult result = validatorThrough(challengeHost.port(), DEADLINE)
                .validate(IDENTIFIER, TOKEN, KEY_AUTHORIZATION);

        // then
        assertThat(result.valid()).isTrue();
    }

    @Test
    void acceptsChallenge_whenFollowedRedirectHasBodyAboveSizeLimit() throws Exception {
        // given
        var redirectTarget = "/.well-known/acme-challenge/moved";
        var pageAboveSizeLimit = "a".repeat(64 * 1024);
        stubChallenge(aResponse()
                .withStatus(301)
                .withHeader("Location", "http://" + IDENTIFIER + redirectTarget)
                .withBody(pageAboveSizeLimit));
        challengeHost
                .stubFor(get(urlPathEqualTo(redirectTarget))
                        .willReturn(aResponse().withStatus(200).withBody(KEY_AUTHORIZATION)));

        // when
        ChallengeValidationResult result = validatorThrough(challengeHost.port(), DEADLINE)
                .validate(IDENTIFIER, TOKEN, KEY_AUTHORIZATION);

        // then
        assertThat(result.valid()).isTrue();
    }

    @Test
    void acceptsChallenge_whenRedirectTargetIsNotStrictUriSyntax() throws Exception {
        // given
        var unescapedPipePath = "/.well-known/acme-challenge/moved|here";
        stubChallenge(aResponse().withStatus(302).withHeader("Location", "http://" + IDENTIFIER + unescapedPipePath));
        challengeHost
                .stubFor(get(urlPathMatching("/\\.well-known/acme-challenge/moved.*here"))
                        .willReturn(aResponse().withStatus(200).withBody(KEY_AUTHORIZATION)));

        // when
        ChallengeValidationResult result = validatorThrough(challengeHost.port(), DEADLINE)
                .validate(IDENTIFIER, TOKEN, KEY_AUTHORIZATION);

        // then
        assertThat(result.valid()).isTrue();
    }

    @Test
    void rejectsWithIncorrectResponse_whenHostServesOtherValue() throws Exception {
        // given
        var otherKeyAuthorization = TOKEN + ".another-account-thumbprint";
        stubChallenge(aResponse().withStatus(200).withBody(otherKeyAuthorization));

        // when
        ChallengeValidationResult result = validatorThrough(challengeHost.port(), DEADLINE)
                .validate(IDENTIFIER, TOKEN, KEY_AUTHORIZATION);

        // then
        assertThat(result.valid()).isFalse();
        assertThat(result.problem()).isEqualTo(Problem.INCORRECT_RESPONSE);
    }

    @Test
    void refusesWithTlsProblem_whenRedirectTargetsOtherPort() {
        // given
        var otherPortTarget = "http://" + IDENTIFIER + ":8080" + CHALLENGE_PATH;
        stubChallenge(aResponse().withStatus(302).withHeader("Location", otherPortTarget));
        AcmeHttpChallengeValidator validator = validatorThrough(challengeHost.port(), DEADLINE);

        // when
        ThrowingCallable validate = () -> validator.validate(IDENTIFIER, TOKEN, KEY_AUTHORIZATION);

        // then
        assertThatThrownBy(validate)
                .isInstanceOfSatisfying(AcmeProblemDocumentException.class,
                        refused -> assertThat(refused.getProblemDocument().getType()).isEqualTo(Problem.TLS.getType()));
    }

    @Test
    @Timeout(value = 30, threadMode = SEPARATE_THREAD)
    void failsWithConnectionProblem_whenHostAcceptsButNeverAnswers() throws Exception {
        // given
        var deadlineShorterThanReadTimeout = Duration.ofMillis(800);
        try (ServerSocket silentHost = loopbackServerSocket()) {
            var heldConnection = new FutureTask<Void>(() -> readRequestWithoutAnswering(silentHost), null);
            Thread.ofVirtual().start(heldConnection);
            AcmeHttpChallengeValidator validator = validatorThrough(silentHost.getLocalPort(),
                    deadlineShorterThanReadTimeout);

            // when
            long start = System.nanoTime();
            ChallengeValidationResult result = validator.validate(IDENTIFIER, TOKEN, KEY_AUTHORIZATION);

            // then
            assertThat(result.valid()).isFalse();
            assertThat(result.problem()).isEqualTo(Problem.CONNECTION);
            assertThat(Duration.ofNanos(System.nanoTime() - start))
                    .as("stopped by the deadline, not by the read timeout")
                    .isLessThan(Duration.ofMillis(READ_TIMEOUT_MILLIS));
            assertThat(heldConnection)
                    .as("the fetch closed its connection once validation stopped waiting")
                    .succeedsWithin(CONNECTION_CLOSE_WAIT);
        }
    }

    @Test
    @Timeout(value = 30, threadMode = SEPARATE_THREAD)
    void failsWithConnectionProblem_whenHostIsSilentPastReadTimeout() throws Exception {
        // given
        var readTimeoutShorterThanDeadline = 300;
        try (ServerSocket silentHost = loopbackServerSocket()) {
            Thread.ofVirtual().start(() -> readRequestWithoutAnswering(silentHost));
            AcmeHttpChallengeValidator validator = validatorThrough(silentHost.getLocalPort(),
                    readTimeoutShorterThanDeadline, DEADLINE);

            // when
            long start = System.nanoTime();
            ChallengeValidationResult result = validator.validate(IDENTIFIER, TOKEN, KEY_AUTHORIZATION);

            // then
            assertThat(result.valid()).isFalse();
            assertThat(result.problem()).isEqualTo(Problem.CONNECTION);
            assertThat(Duration.ofNanos(System.nanoTime() - start))
                    .as("stopped by the read timeout, not by the deadline")
                    .isLessThan(DEADLINE);
        }
    }

    @Test
    @Timeout(value = 30, threadMode = SEPARATE_THREAD)
    void failsWithConnectionProblem_whenChunkFramingOutlastsDeadline() throws Exception {
        // given
        var deadlineShorterThanFraming = Duration.ofSeconds(1);
        try (ServerSocket framingHost = loopbackServerSocket()) {
            var framingConnection = new FutureTask<Void>(() -> serveEndlessChunkSizeLine(framingHost), null);
            Thread.ofVirtual().start(framingConnection);
            AcmeHttpChallengeValidator validator = validatorThrough(framingHost.getLocalPort(),
                    deadlineShorterThanFraming);

            // when
            long start = System.nanoTime();
            ChallengeValidationResult result = validator.validate(IDENTIFIER, TOKEN, KEY_AUTHORIZATION);

            // then
            assertThat(result.valid()).isFalse();
            assertThat(result.problem()).isEqualTo(Problem.CONNECTION);
            assertThat(Duration.ofNanos(System.nanoTime() - start))
                    .as("stopped by the deadline, while one read of the chunk framing still runs")
                    .isLessThan(Duration.ofMillis(READ_TIMEOUT_MILLIS));
            assertThat(framingConnection)
                    .as("the fetch closed its connection once validation stopped waiting")
                    .succeedsWithin(CONNECTION_CLOSE_WAIT);
        }
    }

    @Test
    @Timeout(value = 30, threadMode = SEPARATE_THREAD)
    void rejectsWithIncorrectResponse_whenRedirectLoopReachesRequestCap() throws Exception {
        // given
        var redirectToItself = aResponse()
                .withStatus(302)
                .withHeader("Location", "http://" + IDENTIFIER + CHALLENGE_PATH);
        stubChallenge(redirectToItself);

        // when
        ChallengeValidationResult result = validatorThrough(challengeHost.port(), DEADLINE)
                .validate(IDENTIFIER, TOKEN, KEY_AUTHORIZATION);

        // then
        assertThat(result.valid()).isFalse();
        assertThat(result.problem()).isEqualTo(Problem.INCORRECT_RESPONSE);
        assertThat(challengeHost.findAll(getRequestedFor(urlPathEqualTo(CHALLENGE_PATH))))
                .as("requests made before the cap ended the loop, well within the deadline")
                .hasSize(AcmeConstants.MAX_REDIRECT_COUNT);
    }

    @Test
    @Timeout(value = 30, threadMode = SEPARATE_THREAD)
    void failsWithConnectionProblem_whenRedirectChainOutlastsDeadline() throws Exception {
        // given
        var deadlineShorterThanChain = Duration.ofSeconds(1);
        var eachHopWellWithinReadTimeout = 300;
        stubChallenge(aResponse()
                .withStatus(302)
                .withHeader("Location", "http://" + IDENTIFIER + CHALLENGE_PATH)
                .withFixedDelay(eachHopWellWithinReadTimeout));

        // when
        ChallengeValidationResult result = validatorThrough(challengeHost.port(), deadlineShorterThanChain)
                .validate(IDENTIFIER, TOKEN, KEY_AUTHORIZATION);

        // then
        assertThat(result.valid()).isFalse();
        assertThat(result.problem()).isEqualTo(Problem.CONNECTION);
    }

    @Test
    @Timeout(value = 30, threadMode = SEPARATE_THREAD)
    void failsWithConnectionProblem_whenResponseBodyOutlastsDeadline() throws Exception {
        // given
        var deadlineShorterThanBody = Duration.ofSeconds(1);
        stubChallenge(aResponse().withStatus(200).withBody(KEY_AUTHORIZATION).withChunkedDribbleDelay(10, 3_000));

        // when
        ChallengeValidationResult result = validatorThrough(challengeHost.port(), deadlineShorterThanBody)
                .validate(IDENTIFIER, TOKEN, KEY_AUTHORIZATION);

        // then
        assertThat(result.valid()).isFalse();
        assertThat(result.problem()).isEqualTo(Problem.CONNECTION);
    }

    @Test
    @Timeout(value = 60, threadMode = SEPARATE_THREAD)
    void stopsReadingWithIncorrectResponse_whenResponseExceedsSizeLimit() throws Exception {
        // given
        long declaredBodyFarAboveLimit = 16L * 1024 * 1024;
        try (ServerSocket verboseHost = loopbackServerSocket()) {
            var served = new FutureTask<>(
                    () -> serveKeyAuthorizationPaddedWithLineBreaks(verboseHost, declaredBodyFarAboveLimit));
            Thread.ofVirtual().start(served);

            // when
            ChallengeValidationResult result = validatorThrough(verboseHost.getLocalPort(), DEADLINE)
                    .validate(IDENTIFIER, TOKEN, KEY_AUTHORIZATION);

            // then
            assertThat(result.valid()).isFalse();
            assertThat(result.problem()).isEqualTo(Problem.INCORRECT_RESPONSE);
            assertThat(served.get(20, TimeUnit.SECONDS))
                    .as("body bytes the host got to send before the connection was closed")
                    .isLessThan(declaredBodyFarAboveLimit);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static AcmeHttpChallengeValidator validatorThrough(int proxyPort, Duration deadline) {
        return validatorThrough(proxyPort, READ_TIMEOUT_MILLIS, deadline);
    }

    private static AcmeHttpChallengeValidator validatorThrough(int proxyPort, int readTimeoutMillis,
            Duration deadline) {
        var proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(LoopbackWireMock.HOST, proxyPort));
        return new AcmeHttpChallengeValidator(url -> url.openConnection(proxy), CONNECT_TIMEOUT_MILLIS,
                readTimeoutMillis, deadline);
    }

    private void stubChallenge(ResponseDefinitionBuilder response) {
        challengeHost.stubFor(get(urlPathEqualTo(CHALLENGE_PATH)).willReturn(response));
    }

    private static ServerSocket loopbackServerSocket() throws IOException {
        return new ServerSocket(0, 1, InetAddress.getByName(LoopbackWireMock.HOST));
    }

    /**
     * Reads the request and never answers, holding the connection until the client hangs up, as a stalled host does.
     */
    private static void readRequestWithoutAnswering(ServerSocket server) {
        try (Socket client = server.accept()) {
            client.setSoTimeout(HOLD_LIMIT_MILLIS);
            client.getInputStream().transferTo(OutputStream.nullOutputStream());
        } catch (IOException connectionEnded) {
            // the client hung up, or the hold limit passed
        }
    }

    /**
     * Answers with the key authorization followed by line breaks up to the declared length, a body that matches once
     * its line breaks are dropped, written until the client hangs up.
     *
     * @return how many body bytes the host got to write
     */
    private static long serveKeyAuthorizationPaddedWithLineBreaks(ServerSocket server, long declaredLength) {
        long written = 0;
        try (Socket client = server.accept()) {
            client.setSoTimeout(HOLD_LIMIT_MILLIS);
            readRequestHead(client.getInputStream());
            OutputStream out = client.getOutputStream();
            out
                    .write(("HTTP/1.1 200 OK\r\nContent-Length: " + declaredLength + "\r\n\r\n")
                            .getBytes(StandardCharsets.US_ASCII));
            byte[] keyAuthorization = KEY_AUTHORIZATION.getBytes(StandardCharsets.US_ASCII);
            out.write(keyAuthorization);
            written += keyAuthorization.length;
            byte[] lineBreaks = new byte[8 * 1024];
            Arrays.fill(lineBreaks, (byte) '\n');
            while (written < declaredLength) {
                int length = (int) Math.min(lineBreaks.length, declaredLength - written);
                out.write(lineBreaks, 0, length);
                written += length;
            }
            out.flush();
        } catch (IOException connectionEnded) {
            // the client hung up
        }
        return written;
    }

    /**
     * Answers with a chunked body whose first chunk-size line never ends, sent one digit at a time well within the read
     * timeout, so no single socket read stalls.
     */
    private static void serveEndlessChunkSizeLine(ServerSocket server) {
        try (Socket client = server.accept()) {
            client.setSoTimeout(HOLD_LIMIT_MILLIS);
            readRequestHead(client.getInputStream());
            OutputStream out = client.getOutputStream();
            out.write("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
            long holdUntil = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(HOLD_LIMIT_MILLIS);
            while (System.nanoTime() - holdUntil < 0) {
                out.write('0');
                out.flush();
                TimeUnit.MILLISECONDS.sleep(200);
            }
        } catch (IOException connectionEnded) {
            // the client hung up
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private static void readRequestHead(InputStream in) throws IOException {
        byte[] endOfHead = "\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
        int matched = 0;
        while (matched < endOfHead.length) {
            int next = in.read();
            if (next == -1) {
                throw new EOFException("request ended before its head");
            }
            if (next == endOfHead[matched]) {
                matched++;
            } else {
                matched = next == endOfHead[0] ? 1 : 0;
            }
        }
    }
}

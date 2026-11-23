package com.otilm.core.service.acme;

import com.otilm.api.exception.AcmeProblemDocumentException;
import com.otilm.api.exception.PlatformException;
import com.otilm.api.model.core.acme.Problem;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;

/**
 * Validates an HTTP-01 challenge by fetching the key authorization its host serves. The fetch is bounded, so validation
 * ends whatever the host does: each request has a connect and a read timeout, the whole redirect chain has one deadline
 * after which the challenge fails, and at most a few kilobytes of the response body are read. The size of the response
 * headers is left to the JDK's own limit.
 */
public final class AcmeHttpChallengeValidator {

    private static final Logger logger = LoggerFactory.getLogger(AcmeHttpChallengeValidator.class);

    private static final int CONNECT_TIMEOUT_MILLIS = 5_000;
    private static final int READ_TIMEOUT_MILLIS = 5_000;
    private static final Duration DEADLINE = Duration.ofSeconds(10);
    /** A key authorization is a token and a key thumbprint, about 130 characters. */
    private static final int MAX_RESPONSE_BYTES = 4 * 1024;

    private static final ExecutorService FETCHES = Executors
            .newThreadPerTaskExecutor(Thread.ofVirtual().name("acme-http-challenge-fetch-", 0).factory());

    private final ConnectionOpener connectionOpener;
    private final int connectTimeoutMillis;
    private final int readTimeoutMillis;
    private final Duration deadline;

    public AcmeHttpChallengeValidator() {
        this(URL::openConnection, CONNECT_TIMEOUT_MILLIS, READ_TIMEOUT_MILLIS, DEADLINE);
    }

    AcmeHttpChallengeValidator(ConnectionOpener connectionOpener, int connectTimeoutMillis, int readTimeoutMillis,
            Duration deadline) {
        this.connectionOpener = connectionOpener;
        this.connectTimeoutMillis = connectTimeoutMillis;
        this.readTimeoutMillis = readTimeoutMillis;
        this.deadline = deadline;
    }

    public ChallengeValidationResult validate(String identifierValue, String token, String expectedKeyAuthorization)
            throws AcmeProblemDocumentException {
        String url = AcmeConstants.HTTP_CHALLENGE_BASE_URL.formatted(identifierValue.replace("*.", ""), token);
        String response;
        try {
            response = fetchWithinDeadline(url);
        } catch (ChallengeFetchException e) {
            return ChallengeValidationResult
                    .failure(e.problem, "The HTTP-01 challenge of " + identifierValue + " failed: " + e.getMessage());
        }
        logger
                .debug("HTTP01 validation response from the server: {}, expected response: {}", response,
                        expectedKeyAuthorization);
        if (!response.equals(expectedKeyAuthorization)) {
            return ChallengeValidationResult
                    .failure(Problem.INCORRECT_RESPONSE, "The response served for the HTTP-01 challenge of "
                            + identifierValue + " does not match the expected key authorization");
        }
        return ChallengeValidationResult.success();
    }

    /**
     * Runs the fetch on a virtual thread and stops waiting for it at the deadline. A check between reads cannot bound
     * the fetch: one read of a chunked body runs until a chunk's data arrives, however slowly its framing comes in, and
     * the JDK retries a failed request on a new connection by itself. Interrupting a virtual thread instead closes the
     * socket it is blocked on, whichever phase the fetch is in. A name lookup cannot be interrupted; it ends at the
     * resolver's own time-out, and the caller no longer waits for it.
     */
    private String fetchWithinDeadline(String url) throws AcmeProblemDocumentException, ChallengeFetchException {
        Future<String> fetch = FETCHES.submit(() -> getResponseFollowRedirects(url));
        try {
            return fetch.get(deadline.toNanos(), TimeUnit.NANOSECONDS);
        } catch (TimeoutException e) {
            throw notAnsweredInTime();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AcmeProblemDocumentException(HttpStatus.INTERNAL_SERVER_ERROR, Problem.SERVER_INTERNAL);
        } catch (ExecutionException e) {
            if (e.getCause() instanceof ChallengeFetchException stopped) {
                throw stopped;
            }
            if (e.getCause() instanceof AcmeProblemDocumentException refused) {
                throw refused;
            }
            throw new IllegalStateException("The HTTP-01 challenge fetch failed unexpectedly", e.getCause());
        } finally {
            fetch.cancel(true);
        }
    }

    /**
     * Follows redirects by hand, to ports 80 and 443 only, and returns the body of the response the chain ends with.
     * Redirect targets are parsed as {@link URL}s, which accept some targets that a {@link java.net.URI} rejects, such
     * as an unescaped {@code |} in the path. A redirect to another port is refused with a problem document; other
     * failures, apart from the limits, end the chain with an empty response.
     */
    @SuppressWarnings("deprecation")
    private String getResponseFollowRedirects(String url) throws AcmeProblemDocumentException, ChallengeFetchException {
        String finalUrl = url;
        try {
            for (int requestCount = 1;; requestCount++) {
                URL urlObject = new URL(finalUrl);
                if (!(urlObject.getPort() == 80 || urlObject.getPort() == 443 || urlObject.getPort() == -1)) {
                    throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.TLS,
                            "Only 80 and 443 ports can be followed");
                }
                boolean mayRedirect = requestCount < AcmeConstants.MAX_REDIRECT_COUNT;
                ChallengeResponse response = request(urlObject, mayRedirect);
                if (response.redirectTarget() == null) {
                    return response.body();
                }
                finalUrl = response.redirectTarget();
            }
        } catch (AcmeProblemDocumentException | ChallengeFetchException e) {
            throw e;
        } catch (Exception e) {
            if (!Thread.currentThread().isInterrupted()) {
                logger.error("Failed to fetch the HTTP-01 challenge response: {}", e.getClass().getSimpleName());
            }
            return "";
        }
    }

    /**
     * The body of a redirect that is followed is neither compared nor held to the size limit: only the body the chain
     * ends with is, and a redirect page may be larger than the limit.
     */
    private ChallengeResponse request(URL url, boolean mayRedirect) throws IOException, ChallengeFetchException {
        HttpURLConnection connection = (HttpURLConnection) connectionOpener.open(url);
        connection.setConnectTimeout(connectTimeoutMillis);
        connection.setReadTimeout(readTimeoutMillis);
        connection.setInstanceFollowRedirects(false);
        connection.setUseCaches(false);
        connection.setRequestMethod(AcmeConstants.HTTP_CHALLENGE_REQUEST_METHOD);
        try {
            int responseCode = connection.getResponseCode();
            boolean redirect = 300 <= responseCode && responseCode <= 399;
            String location = connection.getHeaderField(AcmeConstants.LOCATION_HEADER_NAME);
            if (redirect && location != null && mayRedirect) {
                return new ChallengeResponse(null, location);
            }
            String body = 100 <= responseCode && responseCode <= 399 ? readBody(connection) : "";
            return new ChallengeResponse(body, null);
        } catch (SocketTimeoutException e) {
            throw notAnsweredInTime();
        } finally {
            connection.disconnect();
        }
    }

    /** Line breaks are dropped, so a key authorization served with a trailing newline still matches. */
    private static String readBody(HttpURLConnection connection) throws IOException, ChallengeFetchException {
        byte[] body = new byte[MAX_RESPONSE_BYTES + 1];
        int size;
        try (InputStream stream = connection.getInputStream()) {
            size = stream.readNBytes(body, 0, body.length);
        }
        if (size > MAX_RESPONSE_BYTES) {
            throw new ChallengeFetchException(Problem.INCORRECT_RESPONSE,
                    "its response body is larger than " + MAX_RESPONSE_BYTES + " bytes");
        }
        return new String(body, 0, size, StandardCharsets.UTF_8).lines().collect(Collectors.joining());
    }

    private static ChallengeFetchException notAnsweredInTime() {
        return new ChallengeFetchException(Problem.CONNECTION, "its host did not answer in time");
    }

    @FunctionalInterface
    interface ConnectionOpener {
        URLConnection open(URL url) throws IOException;
    }

    /** Either the body a redirect chain ends with or the target of a redirect to follow. */
    private record ChallengeResponse(String body, String redirectTarget) {
    }

    /** A fetch stopped at one of the limits, with the reason worded to follow "the challenge failed:". */
    private static final class ChallengeFetchException extends Exception implements PlatformException {

        private final Problem problem;

        private ChallengeFetchException(Problem problem, String reason) {
            super(reason);
            this.problem = problem;
        }
    }
}

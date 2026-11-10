package com.otilm.core.service.handler.discovery;

import com.otilm.api.exception.ConnectorClientException;
import com.otilm.api.exception.ConnectorEntityNotFoundException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.common.error.ProblemDetailExtended;
import java.net.URI;
import java.time.Duration;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpStatus;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Named.named;

/**
 * The two questions every tick asks about a connector failure: is this definitive, and what may an operator be told.
 * Both answers are load-bearing — the first decides whether a run ends now or spends its budget, the second reaches an
 * API response.
 */
class DiscoveryConnectorErrorsTest {

    private static final URI INSTANCE = URI.create("https://example.com/discovery");

    @Test
    void notTrackedOn404_isDefinitive() {
        assertThat(DiscoveryConnectorErrors.isRunNoLongerTracked(problem(ErrorCode.OPERATION_NOT_TRACKED))).isTrue();
    }

    @Test
    void terse404WithNoProblemBody_isDefinitiveToo() {
        // What the AMQP proxy leaves after discarding the problem body (see
        // DiscoveryConnectorErrors#isRunNoLongerTracked for why both shapes are accepted).
        assertThat(DiscoveryConnectorErrors.isRunNoLongerTracked(new ConnectorEntityNotFoundException("gone")))
                .isTrue();
    }

    @Test
    void notTrackedCodeOnANon404_isNotDefinitive() {
        // REGISTRATION_NOT_FOUND is also declared on a 422, meaning something else entirely there.
        assertThat(DiscoveryConnectorErrors.isRunNoLongerTracked(problem(ErrorCode.REGISTRATION_NOT_FOUND))).isFalse();
    }

    @Test
    void unrelatedCodeOn404_isNotDefinitive() {
        assertThat(DiscoveryConnectorErrors.isRunNoLongerTracked(problem(ErrorCode.INTERNAL_SERVER_ERROR))).isFalse();
    }

    @Test
    void plainConnectorFailure_isNotDefinitive() {
        assertThat(DiscoveryConnectorErrors.isRunNoLongerTracked(new ConnectorException("connection refused")))
                .isFalse();
    }

    @Test
    void nonConnectorFailure_isNotDefinitive() {
        assertThat(DiscoveryConnectorErrors.isRunNoLongerTracked(new IllegalStateException("boom"))).isFalse();
    }

    @Test
    void knownCodes_yieldCoreAuthoredText() {
        assertThat(DiscoveryConnectorErrors.describe(problem(ErrorCode.OPERATION_NOT_TRACKED)))
                .isEqualTo("the connector no longer tracks the run");
        assertThat(DiscoveryConnectorErrors.describe(problem(ErrorCode.UNAUTHORIZED)))
                .isEqualTo("the connector refused Core's credentials");
        assertThat(DiscoveryConnectorErrors.describe(problem(ErrorCode.SERVICE_UNAVAILABLE)))
                .isEqualTo("the connector was unreachable");
        assertThat(DiscoveryConnectorErrors.describe(problem(ErrorCode.CHECKPOINT_LOST)))
                .isEqualTo("the connector lost the run's checkpoint");
    }

    @Test
    void validationRefusal_isARefusalOfTheConfiguration() {
        assertThat(DiscoveryConnectorErrors.isConfigurationRefused(problem(ErrorCode.VALIDATION_FAILED))).isTrue();
    }

    @Test
    void otherAnswersAndFailures_areNotARefusalOfTheConfiguration() {
        assertThat(DiscoveryConnectorErrors.isConfigurationRefused(problem(ErrorCode.INTERNAL_SERVER_ERROR))).isFalse();
        assertThat(DiscoveryConnectorErrors.isConfigurationRefused(problem(ErrorCode.SERVICE_UNAVAILABLE))).isFalse();
        assertThat(DiscoveryConnectorErrors.isConfigurationRefused(new ConnectorException("connection refused")))
                .isFalse();
    }

    @Test
    void validationRefusal_saysTheConnectorAnswered() {
        // The connector answered, naming what it refused; "did not answer" would send an operator to check its
        // availability instead of the run's configuration.
        assertThat(DiscoveryConnectorErrors.describe(problem(ErrorCode.VALIDATION_FAILED)))
                .isEqualTo("the connector refused the run's configuration");
    }

    @Test
    void connectorSuppliedProse_neverReachesTheRun() {
        ProblemDetailExtended detail = ProblemDetailExtended
                .fromErrorCode(ErrorCode.INTERNAL_SERVER_ERROR,
                        "NullPointerException at scanner.internal.Host(10.0.0.7:8443) using cert /etc/ssl/priv.pem",
                        INSTANCE, null);

        String described = DiscoveryConnectorErrors.describe(new ConnectorProblemException(detail));

        // The run's message is a user-visible surface. An obligation on the connector to curate its detail is not
        // a guarantee, so nothing it wrote is forwarded — only text keyed on the closed error-code vocabulary.
        assertThat(described)
                .isEqualTo("the connector reported an internal error")
                .doesNotContain("10.0.0.7", "priv.pem", "NullPointerException");
    }

    @Test
    void unmappedCodeAndPlainFailure_fallBackToTheGenericPhrase() {
        assertThat(DiscoveryConnectorErrors.describe(problem(ErrorCode.POLICY_VIOLATION)))
                .isEqualTo("the connector did not answer");
        assertThat(DiscoveryConnectorErrors.describe(new ConnectorException("connection refused")))
                .isEqualTo("the connector did not answer");
    }

    @ParameterizedTest
    @MethodSource("refusals")
    void readsARefusal_whenTheConnectorAnswered422(Exception refusal) {
        // when
        boolean isRefusal = DiscoveryConnectorErrors.isRefusal(refusal);

        // then
        assertThat(isRefusal).isTrue();
    }

    @ParameterizedTest
    @MethodSource("busyAnswers")
    void readsNoRefusal_whenTheConnectorWasBusy(Exception busy) {
        // when
        boolean isRefusal = DiscoveryConnectorErrors.isRefusal(busy);

        // then
        assertThat(isRefusal).isFalse();
    }

    @ParameterizedTest
    @MethodSource("busyAnswers")
    void readsBusy_whenTheConnectorAnswered503(Exception busy) {
        // when
        boolean isBusy = DiscoveryConnectorErrors.isBusy(busy);

        // then
        assertThat(isBusy).isTrue();
    }

    @ParameterizedTest
    @MethodSource("notBusyFailures")
    void readsNotBusy_whenTheFailureWasSomethingElse(Exception failure) {
        // when
        boolean isBusy = DiscoveryConnectorErrors.isBusy(failure);

        // then
        assertThat(isBusy).isFalse();
    }

    @Test
    void returnsTheRetryAfter_whenTheProblemDocumentCarriesOne() {
        // given
        var retryAfterSeconds = 40;
        ConnectorProblemException busy = problem(ErrorCode.SERVICE_UNAVAILABLE);
        busy.getProblemDetail().setRetryAfterSeconds(retryAfterSeconds);

        // when
        Optional<Duration> retryAfter = DiscoveryConnectorErrors.retryAfter(busy);

        // then
        assertThat(retryAfter).contains(Duration.ofSeconds(retryAfterSeconds));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -5})
    void returnsNoRetryAfter_whenTheProblemDocumentCarriesNoUsableOne(int unusableSeconds) {
        // given
        ConnectorProblemException busy = problem(ErrorCode.SERVICE_UNAVAILABLE);
        busy.getProblemDetail().setRetryAfterSeconds(unusableSeconds);

        // when
        Optional<Duration> retryAfter = DiscoveryConnectorErrors.retryAfter(busy);

        // then
        assertThat(retryAfter).isEmpty();
    }

    @Test
    void returnsNoRetryAfter_whenTheTransportCarriesNone() {
        // given
        var proxied = new ConnectorServerException("HTTP 503", HttpStatus.SERVICE_UNAVAILABLE);

        // when
        Optional<Duration> retryAfter = DiscoveryConnectorErrors.retryAfter(proxied);

        // then
        assertThat(retryAfter).isEmpty();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    static Stream<Named<Exception>> refusals() {
        return Stream
                .of(named("a problem document over REST", problem(ErrorCode.VALIDATION_FAILED)),
                        named("a plain 422 over REST",
                                new ConnectorClientException("HTTP 422", HttpStatus.UNPROCESSABLE_ENTITY)),
                        named("a validation failure over the proxy", new ValidationException("HTTP 422")));
    }

    static Stream<Named<Exception>> busyAnswers() {
        return Stream
                .of(named("a problem document over REST", problem(ErrorCode.SERVICE_UNAVAILABLE)),
                        named("a server failure over either transport",
                                new ConnectorServerException("HTTP 503", HttpStatus.SERVICE_UNAVAILABLE)));
    }

    static Stream<Named<Exception>> notBusyFailures() {
        return Stream
                .of(named("an internal error",
                        new ConnectorServerException("HTTP 500", HttpStatus.INTERNAL_SERVER_ERROR)),
                        named("a gateway timeout", problem(ErrorCode.GATEWAY_TIMEOUT)),
                        named("a refusal", problem(ErrorCode.VALIDATION_FAILED)),
                        named("an unreachable connector", new ConnectorException("connection refused")));
    }

    private static ConnectorProblemException problem(ErrorCode code) {
        return new ConnectorProblemException(ProblemDetailExtended.fromErrorCode(code, "detail", INSTANCE, null));
    }
}

package com.otilm.core.logging;

import com.fasterxml.jackson.core.JsonParseException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.LocationException;
import com.otilm.api.exception.ValidationException;
import java.io.IOException;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Named.named;

class RedactedFailureTest {

    private static final String ECHOED_SECRET = "passphrase-the-connector-echoed";

    @Test
    void keepsTheFailure_whenNoConnectorWroteItsChain() {
        // given
        var coreFailure = new IllegalStateException("registration already completed", new IOException("disk full"));

        // when
        Throwable logged = RedactedFailure.forLog(coreFailure);

        // then
        assertThat(logged).isSameAs(coreFailure);
    }

    @ParameterizedTest
    @MethodSource("connectorWrittenFailures")
    void redactsEveryLinkOfTheChain_whenAConnectorWrotePartOfIt(Exception connectorWritten) {
        // given
        var shapedFailure = new IllegalStateException("submission failed: " + ECHOED_SECRET, connectorWritten);

        // when
        Throwable logged = RedactedFailure.forLog(shapedFailure);

        // then
        assertThat(logged)
                .hasMessageContaining(IllegalStateException.class.getName())
                .hasMessageNotContaining(ECHOED_SECRET);
        assertThat(logged.getStackTrace()).isEqualTo(shapedFailure.getStackTrace());
        assertThat(logged.getCause())
                .hasMessageContaining(connectorWritten.getClass().getName())
                .hasMessageNotContaining(ECHOED_SECRET)
                .hasNoCause();
        assertThat(logged.getCause().getStackTrace()).isEqualTo(connectorWritten.getStackTrace());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Stream<Named<Exception>> connectorWrittenFailures() {
        return Stream
                .of(named("a connector's error", new ConnectorException(ECHOED_SECRET)),
                        named("a connector's refusal", new ValidationException(ECHOED_SECRET)),
                        named("a location connector's refusal", new LocationException(ECHOED_SECRET)),
                        named("an answer Core could not parse", new JsonParseException(null, ECHOED_SECRET)));
    }
}

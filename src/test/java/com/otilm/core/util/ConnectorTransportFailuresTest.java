package com.otilm.core.util;

import com.fasterxml.jackson.core.JsonParseException;
import java.net.ConnectException;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ConnectorTransportFailuresTest {

    @Test
    void countsAsTransportFailure_whenTheConnectionWasRefused() {
        // given
        ConnectException refused = new ConnectException("Connection refused");

        // when
        boolean transport = ConnectorTransportFailures.isTransportFailure(refused);

        // then
        assertThat(transport).isTrue();
    }

    @Test
    void countsAsTransportFailure_whenTheCallTimedOut() {
        // given
        TimeoutException timedOut = new TimeoutException("timed out");

        // when
        boolean transport = ConnectorTransportFailures.isTransportFailure(timedOut);

        // then
        assertThat(transport).isTrue();
    }

    @Test
    void doesNotCountAsTransportFailure_whenTheAnswerCouldNotBeParsed() {
        // given
        JsonParseException unreadable = new JsonParseException(null, "Unexpected character");

        // when
        boolean transport = ConnectorTransportFailures.isTransportFailure(unreadable);

        // then
        assertThat(transport).isFalse();
    }

    @Test
    void doesNotCountAsTransportFailure_whenThereIsNoCause() {
        // given — no cause

        // when
        boolean transport = ConnectorTransportFailures.isTransportFailure(null);

        // then
        assertThat(transport).isFalse();
    }
}

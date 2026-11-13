package com.otilm.core.service.est;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import java.io.IOException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class EstConnectorFailuresTest {

    @Test
    void recognisesConnectorFailure_whenItIsTheFailureItself() {
        // given
        Exception failure = new ConnectorException("text");

        // when
        boolean recognised = EstConnectorFailures.isConnectorFailure(failure);

        // then
        assertThat(recognised).isTrue();
    }

    @Test
    void recognisesConnectorFailure_whenItIsANestedCause() {
        // given
        Exception wrapped = new IllegalStateException("outer", new IOException("middle", new ValidationException("x")));

        // when
        boolean recognised = EstConnectorFailures.isConnectorFailure(wrapped);

        // then
        assertThat(recognised).isTrue();
    }

    @Test
    void recognisesNoConnectorFailure_whenNoCauseIsOne() {
        // given
        Exception failure = new IllegalStateException("a", new IOException("b"));

        // when
        boolean recognised = EstConnectorFailures.isConnectorFailure(failure);

        // then
        assertThat(recognised).isFalse();
    }

    @Test
    void recognisesNoConnectorFailure_whenThereIsNoFailure() {
        // given
        Throwable noFailure = null;

        // when
        boolean recognised = EstConnectorFailures.isConnectorFailure(noFailure);

        // then
        assertThat(recognised).isFalse();
    }

    @Test
    void listsClassNamesWithoutMessages_whenFailureHasCauses() {
        // given
        Exception failure = new IllegalStateException("secret-text", new ValidationException("more-secret"));

        // when
        String names = EstConnectorFailures.classNames(failure);

        // then
        assertThat(names).contains(IllegalStateException.class.getName(), ValidationException.class.getName());
        assertThat(names).doesNotContain("secret");
    }

    @Test
    void stops_whenCausesAreCyclic() {
        // given
        RuntimeException first = new RuntimeException("a");
        RuntimeException second = new RuntimeException("b", first);
        first.initCause(second);

        // when
        boolean recognised = EstConnectorFailures.isConnectorFailure(first);

        // then
        assertThat(recognised).isFalse();
    }
}

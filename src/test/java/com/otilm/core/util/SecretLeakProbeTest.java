package com.otilm.core.util;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SecretLeakProbeTest {

    private static final Logger LOGGER = LoggerFactory.getLogger("com.otilm.core.util.SecretLeakProbeTest");

    private static final String MESSAGE_MARKER = "probe-message-marker-9f21";
    private static final String EXCEPTION_MARKER = "probe-exception-marker-4d7a";

    @Test
    void logged_capturesADebugLineAndItsThrowable() {
        try (SecretLeakProbe probe = SecretLeakProbe.capture()) {
            // when
            LOGGER.debug(MESSAGE_MARKER, new RuntimeException(EXCEPTION_MARKER));

            // then
            List<String> logged = probe.logged();
            assertThat(logged)
                    .anyMatch(line -> line.contains(MESSAGE_MARKER))
                    .anyMatch(line -> line.contains(EXCEPTION_MARKER));
            assertThatThrownBy(() -> SecretLeakProbe.assertNoneReveals(logged, EXCEPTION_MARKER))
                    .isInstanceOf(AssertionError.class);
        }
    }

    @Test
    void assertNoneReveals_refusesToPassOnNothingCollected() {
        assertThatThrownBy(() -> SecretLeakProbe.assertNoneReveals(List.of(), EXCEPTION_MARKER))
                .isInstanceOf(AssertionError.class);
    }
}

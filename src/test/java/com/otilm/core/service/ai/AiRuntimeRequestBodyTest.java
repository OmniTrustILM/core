package com.otilm.core.service.ai;

import com.otilm.api.exception.PlatformException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicLong;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AiRuntimeRequestBodyTest {
    private final AtomicLong nanos = new AtomicLong();
    private final AiRuntimeOperationBudget budget = AiRuntimeOperationBudget.start(nanos::get);

    @AfterEach
    void clearInterruption() {
        Thread.interrupted();
    }

    @Test
    void returnsSafeDomainMessage_whenRequestExceedsTheBodyLimit() {
        // given
        var requestCanary = "SYNTHETIC_REQUEST_SECRET_CANARY";
        var oversizedBody = stream(requestCanary);

        // when
        ThrowingCallable readBody = () -> AiRuntimeRequestBody.read(oversizedBody, 2, budget);

        // then
        assertThatThrownBy(readBody)
                .isInstanceOfSatisfying(AiRuntimeRequestBody.LimitExceeded.class,
                        failure -> assertThat(PlatformException.safeMessage(failure, "fallback"))
                                .isEqualTo("Runtime request body exceeds the limit")
                                .doesNotContain(requestCanary))
                .hasNoCause();
    }

    @Test
    void preservesExactBytesAndLeavesServletStreamOwnershipWithTheCaller() throws Exception {
        var closed = new java.util.concurrent.atomic.AtomicBoolean();
        byte[] bytes = "{\"prompt\":\"Žluťoučký\"}".getBytes(StandardCharsets.UTF_8);
        var input = new ByteArrayInputStream(bytes) {
            @Override
            public void close() {
                closed.set(true);
            }
        };

        assertThat(AiRuntimeRequestBody.read(input, 8192, budget)).isEqualTo(bytes);
        assertThat(closed.get()).isFalse();
    }

    @Test
    void acceptsTheExactLimitAndRejectsOtherwiseValidJsonWithOneExtraWhitespaceByte() throws Exception {
        assertThat(AiRuntimeRequestBody.read(stream("{}"), 2, budget)).isEqualTo(new byte[]{'{', '}'});
        assertThatThrownBy(() -> AiRuntimeRequestBody.read(stream("{} "), 2, budget))
                .isInstanceOf(AiRuntimeRequestBody.LimitExceeded.class)
                .hasNoCause();
    }

    @Test
    void handlesAZeroLengthBulkReadWithoutSpinningOrLosingTheNextByte() throws Exception {
        var delegate = stream("{}");
        var input = new InputStream() {
            @Override
            public int read(byte[] bytes, int offset, int length) {
                return 0;
            }

            @Override
            public int read() {
                return delegate.read();
            }
        };
        assertThat(AiRuntimeRequestBody.read(input, 8, budget)).isEqualTo(new byte[]{'{', '}'});
    }

    @Test
    void doesNotReturnBytesWhenTheReadCompletesAfterTheBudgetIsSpent() {
        var input = new InputStream() {
            @Override
            public int read(byte[] bytes, int offset, int length) {
                bytes[offset] = '{';
                nanos.set(5_000_000_000L);
                return 1;
            }

            @Override
            public int read() {
                throw new AssertionError("Bulk read must be checked before fallback");
            }
        };
        assertThatThrownBy(() -> AiRuntimeRequestBody.read(input, 8, budget))
                .isInstanceOf(AiRuntimeOperationBudget.Unavailable.class);
    }

    @Test
    void interruptionStopsBeforeTouchingTheInput() {
        var input = new InputStream() {
            @Override
            public int read() {
                throw new AssertionError("Interrupted request must not read");
            }
        };
        Thread.currentThread().interrupt();
        assertThatThrownBy(() -> AiRuntimeRequestBody.read(input, 8, budget))
                .isInstanceOf(AiRuntimeOperationBudget.Unavailable.class);
        assertThat(Thread.currentThread().isInterrupted()).isTrue();
    }

    @Test
    void preservesIoFailureForTheContentFreeEndpointErrorBoundary() {
        var failure = new IOException("synthetic-stream-failure");
        var input = new InputStream() {
            @Override
            public int read() throws IOException {
                throw failure;
            }
        };
        assertThatThrownBy(() -> AiRuntimeRequestBody.read(input, 8, budget)).isSameAs(failure);
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 0, 1500001})
    void rejectsInvalidTrustedCaps(int cap) {
        assertThatThrownBy(() -> AiRuntimeRequestBody.read(stream("{}"), cap, budget))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsMissingBodyAndPreservesAnEmptyBodyForTheWireParser() throws Exception {
        assertThatThrownBy(() -> AiRuntimeRequestBody.read(null, 8, budget))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(AiRuntimeRequestBody.read(stream(""), 8, budget)).isEmpty();
    }

    private static ByteArrayInputStream stream(String text) {
        return new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8));
    }
}

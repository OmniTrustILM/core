package com.otilm.core.service.est.message;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.function.ThrowingConsumer;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** The limit is small here so that a test can cross it with a few bytes. */
@ExtendWith(MockitoExtension.class)
class EstBoundedRequestTest {

    private static final int LIMIT = 8;

    @Mock
    private HttpServletRequest containerRequest;

    @Mock
    private ServletInputStream containerStream;

    @Mock
    private ReadListener readListener;

    @Test
    void readsTheBody_whenItIsExactlyTheLimit() throws Exception {
        // given
        byte[] bodyAtTheLimit = bytesOfLength(LIMIT);
        EstBoundedRequest request = aBoundedRequestWith(bodyAtTheLimit);

        // when
        byte[] read = request.getInputStream().readAllBytes();

        // then
        assertThat(read).isEqualTo(bodyAtTheLimit);
    }

    @Test
    void readsTheBodyOneByteAtATime_whenItIsWithinTheLimit() throws Exception {
        // given
        byte[] bodyAtTheLimit = bytesOfLength(LIMIT);
        ServletInputStream body = aBoundedRequestWith(bodyAtTheLimit).getInputStream();

        // when
        byte[] read = readOneByteAtATime(body);

        // then
        assertThat(read).isEqualTo(bodyAtTheLimit);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("waysToReadTheBody")
    void throwsPayloadTooLarge_whenTheBodyIsOneByteOverTheLimit(ThrowingConsumer<ServletInputStream> readTheBody)
            throws Exception {
        // given
        ServletInputStream body = aBoundedRequestWith(bytesOfLength(LIMIT + 1)).getInputStream();

        // when
        ThrowingCallable readPastTheLimit = () -> readTheBody.accept(body);

        // then
        assertThatThrownBy(readPastTheLimit)
                .isInstanceOfSatisfying(EstException.class,
                        thrown -> assertThat(thrown.error()).isEqualTo(EstError.PAYLOAD_TOO_LARGE));
    }

    @Test
    void throwsPayloadTooLarge_whenTheStreamIsRequestedAgainAfterTheLimitIsRead() throws Exception {
        // given — a body one byte over the limit, of which the first stream has taken exactly the limit
        EstBoundedRequest request = aBoundedRequestWith(bytesOfLength(LIMIT + 1));
        request.getInputStream().readNBytes(LIMIT);

        // when
        ThrowingCallable readTheLastByte = () -> request.getInputStream().read();

        // then
        assertThatThrownBy(readTheLastByte)
                .isInstanceOfSatisfying(EstException.class,
                        thrown -> assertThat(thrown.error()).isEqualTo(EstError.PAYLOAD_TOO_LARGE));
    }

    @Test
    void leavesTheRestOfTheBodyUnread_whenTheLimitIsExceeded() throws Exception {
        // given — a body far larger than the limit
        MockHttpServletRequest container = new MockHttpServletRequest();
        container.setContent(bytesOfLength(200_000));
        EstBoundedRequest request = new EstBoundedRequest(container, LIMIT);

        // when
        ThrowingCallable readTheBody = () -> request.getInputStream().readAllBytes();

        // then
        assertThatThrownBy(readTheBody).isInstanceOf(EstException.class);
        assertThat(container.getInputStream().available()).isPositive();
    }

    @Test
    void throwsUnsupported_whenAReaderIsRequested() {
        // given — a reader would read the body past the count of the bounded stream
        EstBoundedRequest request = aBoundedRequestWith(bytesOfLength(LIMIT));

        // when
        ThrowingCallable requestAReader = request::getReader;

        // then
        assertThatThrownBy(requestAReader).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void reportsFinished_whenTheWholeBodyIsRead() throws Exception {
        // given
        ServletInputStream body = aBoundedRequestWith(bytesOfLength(LIMIT)).getInputStream();
        boolean finishedBeforeReading = body.isFinished();

        // when
        body.readAllBytes();

        // then
        assertThat(finishedBeforeReading).isFalse();
        assertThat(body.isFinished()).isTrue();
    }

    @Test
    void reportsReady_whenTheContainerStreamIsReady() throws Exception {
        // given
        ServletInputStream body = aBoundedRequestWith(bytesOfLength(LIMIT)).getInputStream();

        // when
        boolean ready = body.isReady();

        // then
        assertThat(ready).isTrue();
    }

    @Test
    void passesTheReadListenerOn_whenOneIsSet() throws Exception {
        // given
        when(containerRequest.getInputStream()).thenReturn(containerStream);
        ServletInputStream body = new EstBoundedRequest(containerRequest, LIMIT).getInputStream();

        // when
        body.setReadListener(readListener);

        // then
        verify(containerStream).setReadListener(readListener);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Stream<Named<ThrowingConsumer<ServletInputStream>>> waysToReadTheBody() {
        return Stream
                .of(named("one byte at a time", EstBoundedRequestTest::readOneByteAtATime),
                        named("into a buffer of four bytes", body -> readInBuffersOf(4, body)),
                        named("all bytes at once", InputStream::readAllBytes),
                        named("transferred to another stream",
                                body -> body.transferTo(OutputStream.nullOutputStream())),
                        named("skipped", body -> body.skip(Long.MAX_VALUE)),
                        named("into a byte buffer", body -> body.read(ByteBuffer.allocate(64))),
                        named("as a line", body -> body.readLine(new byte[64], 0, 64)));
    }

    private static byte[] readOneByteAtATime(InputStream body) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        int next = body.read();
        while (next != -1) {
            bytes.write(next);
            next = body.read();
        }
        return bytes.toByteArray();
    }

    private static void readInBuffersOf(int size, InputStream body) throws IOException {
        byte[] buffer = new byte[size];
        int count = body.read(buffer);
        while (count != -1) {
            count = body.read(buffer);
        }
    }

    private static EstBoundedRequest aBoundedRequestWith(byte[] body) {
        MockHttpServletRequest container = new MockHttpServletRequest();
        container.setContent(body);
        return new EstBoundedRequest(container, LIMIT);
    }

    private static byte[] bytesOfLength(int length) {
        byte[] bytes = new byte[length];
        for (int index = 0; index < length; index++) {
            bytes[index] = (byte) ('a' + index % 26);
        }
        return bytes;
    }
}

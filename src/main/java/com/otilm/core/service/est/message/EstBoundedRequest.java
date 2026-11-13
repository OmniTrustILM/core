package com.otilm.core.service.est.message;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.io.BufferedReader;
import java.io.IOException;

/**
 * A request whose body cannot exceed a limit: the read that takes the body past the limit throws an
 * {@link EstException} of {@link EstError#PAYLOAD_TOO_LARGE}. {@link EstRequestGuard} refuses a request that declares a
 * body over the limit before dispatch; this limits one that declares no length, as a chunked body does.
 */
public final class EstBoundedRequest extends HttpServletRequestWrapper {

    private final int limit;
    private ServletInputStream body;

    /**
     * @param request the request to limit
     * @param limit the most bytes of body that can be read
     */
    public EstBoundedRequest(HttpServletRequest request, int limit) {
        super(request);
        this.limit = limit;
    }

    /**
     * The same stream on every call, so that the limit counts what is read through all of them.
     */
    @Override
    public ServletInputStream getInputStream() throws IOException {
        if (body == null) {
            body = new BoundedInputStream(super.getInputStream(), limit);
        }
        return body;
    }

    /**
     * A reader would read the body without the count of {@link #getInputStream()}, and the body of an EST request is
     * read as bytes.
     */
    @Override
    public BufferedReader getReader() {
        throw new UnsupportedOperationException("The body of an EST request is read as a stream of bytes.");
    }

    private static final class BoundedInputStream extends ServletInputStream {

        private final ServletInputStream source;
        private final int limit;
        private long bytesRead;

        BoundedInputStream(ServletInputStream source, int limit) {
            this.source = source;
            this.limit = limit;
        }

        @Override
        public int read() throws IOException {
            int value = source.read();
            if (value != -1) {
                countRead(1);
            }
            return value;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            int count = source.read(buffer, offset, length);
            if (count > 0) {
                countRead(count);
            }
            return count;
        }

        @Override
        public boolean isFinished() {
            return source.isFinished();
        }

        @Override
        public boolean isReady() {
            return source.isReady();
        }

        @Override
        public void setReadListener(ReadListener readListener) {
            source.setReadListener(readListener);
        }

        private void countRead(int count) {
            bytesRead += count;
            if (bytesRead > limit) {
                throw new EstException(EstError.PAYLOAD_TOO_LARGE);
            }
        }
    }
}

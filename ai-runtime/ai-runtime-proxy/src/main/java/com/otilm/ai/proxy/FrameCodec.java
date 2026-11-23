package com.otilm.ai.proxy;

import com.otilm.ai.runtime.protocol.ProtocolException;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.UUID;

/** One byte-bounded frame and EOF. The receiving owner must enforce time and peer identity. */
public final class FrameCodec {
    public static final int MAX_PAYLOAD_BYTES = 4096;
    private static final int VERSION = 1;
    private static final int REQUEST_MAGIC = 0x494c4d51;
    private static final int REPLY_MAGIC = 0x494c4d52;

    private FrameCodec() {
    }

    public static ProxyRequest readRequest(InputStream stream) throws IOException {
        var input = new DataInputStream(stream);
        try {
            readPreamble(input, REQUEST_MAGIC);
            var operation = LocalOperation.fromTag(input.readUnsignedByte());
            UUID correlation = new UUID(input.readLong(), input.readLong());
            return new ProxyRequest(operation, correlation, readBody(input));
        } catch (EOFException truncated) {
            throw new ProtocolException(ProtocolException.Reason.INVALID_MESSAGE);
        }
    }

    public static ProxyReply readReply(InputStream stream) throws IOException {
        var input = new DataInputStream(stream);
        try {
            readPreamble(input, REPLY_MAGIC);
            var outcome = ProxyReply.Outcome.fromTag(input.readUnsignedByte());
            UUID correlation = new UUID(input.readLong(), input.readLong());
            int status = input.readUnsignedShort();
            return new ProxyReply(outcome, correlation, status, readBody(input));
        } catch (EOFException truncated) {
            throw new ProtocolException(ProtocolException.Reason.INVALID_MESSAGE);
        }
    }

    public static void writeRequest(OutputStream stream, ProxyRequest request) throws IOException {
        byte[] payload = request.payload();
        stream
                .write(header(REQUEST_MAGIC, request.operation().tag(), request.correlationId(), 26 + payload.length)
                        .putInt(payload.length)
                        .put(payload)
                        .array());
    }

    public static void writeReply(OutputStream stream, ProxyReply reply) throws IOException {
        byte[] payload = reply.payload();
        stream
                .write(header(REPLY_MAGIC, reply.outcome().tag(), reply.correlationId(), 28 + payload.length)
                        .putShort((short) reply.httpStatus())
                        .putInt(payload.length)
                        .put(payload)
                        .array());
    }

    private static ByteBuffer header(int magic, int tag, UUID correlation, int size) {
        return ByteBuffer
                .allocate(size)
                .putInt(magic)
                .put((byte) VERSION)
                .put((byte) tag)
                .putLong(correlation.getMostSignificantBits())
                .putLong(correlation.getLeastSignificantBits());
    }

    private static void readPreamble(DataInputStream input, int expectedMagic) throws IOException {
        if (input.readInt() != expectedMagic) {
            throw new ProtocolException(ProtocolException.Reason.INVALID_MESSAGE);
        }
        if (input.readUnsignedByte() != VERSION) {
            throw new ProtocolException(ProtocolException.Reason.UNSUPPORTED_VERSION);
        }
    }

    private static byte[] readBody(DataInputStream input) throws IOException {
        int size = input.readInt();
        if (size > MAX_PAYLOAD_BYTES) {
            throw new ProtocolException(ProtocolException.Reason.INPUT_TOO_LARGE);
        }
        if (size < 0) {
            throw new ProtocolException(ProtocolException.Reason.INVALID_MESSAGE);
        }
        byte[] payload = new byte[size];
        input.readFully(payload);
        if (input.read() != -1) {
            throw new ProtocolException(ProtocolException.Reason.INVALID_MESSAGE);
        }
        return payload;
    }
}

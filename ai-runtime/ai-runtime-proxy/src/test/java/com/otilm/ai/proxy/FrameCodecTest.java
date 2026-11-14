package com.otilm.ai.proxy;

import com.otilm.ai.runtime.protocol.BootstrapRequest;
import com.otilm.ai.runtime.protocol.ClaimBinding;
import com.otilm.ai.runtime.protocol.ClaimHeartbeatRequest;
import com.otilm.ai.runtime.protocol.ProtocolCodec;
import com.otilm.ai.runtime.protocol.ProtocolException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FrameCodecTest {
    private static final UUID CALL = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff");
    private static final UUID RUN = UUID.fromString("10000000-0000-0000-0000-000000000001");
    private static final UUID ATTEMPT = UUID.fromString("20000000-0000-0000-0000-000000000002");
    private static final UUID POD = UUID.fromString("30000000-0000-0000-0000-000000000003");
    private final ProtocolCodec protocol = new ProtocolCodec();

    @Test
    void bootstrapRoundtripHasIndependentGoldenHeader() throws IOException {
        byte[] body = protocol.writeBootstrapRequest(new BootstrapRequest(1, RUN, ATTEMPT, POD));
        var request = new ProxyRequest(LocalOperation.BOOTSTRAP, CALL, body);
        byte[] bytes = requestBytes(request);
        byte[] golden = HexFormat.of().parseHex("494c4d51010100112233445566778899aabbccddeeff");
        assertArrayEquals(golden, Arrays.copyOf(bytes, 22));
        assertEquals(body.length, ByteBuffer.wrap(bytes, 22, 4).getInt());
        assertEquals(26 + body.length, bytes.length);
        var decoded = FrameCodec.readRequest(new ByteArrayInputStream(bytes));
        assertEquals(request, decoded);
        assertArrayEquals(body, decoded.payload());
        assertEquals("/internal/ai-runtime/v1/runner/bootstrap", decoded.operation().path());
    }

    @Test
    void heartbeatUsesOnlyItsClosedRequestTypeAndFixedPath() throws IOException {
        var binding = new ClaimBinding(RUN, ATTEMPT, POD, CALL, 1);
        byte[] body = protocol.writeClaimHeartbeatRequest(new ClaimHeartbeatRequest(1, binding, 1));
        var request = new ProxyRequest(LocalOperation.HEARTBEAT, CALL, body);
        assertEquals(request, FrameCodec.readRequest(new ByteArrayInputStream(requestBytes(request))));
        assertEquals("/internal/ai-runtime/v1/runner/claims/heartbeat", request.operation().path());
        assertThrows(ProtocolException.class, () -> new ProxyRequest(LocalOperation.BOOTSTRAP, CALL, body));
    }

    @Test
    void requestOwnsItsInputAndReturnsIndependentCopies() {
        byte[] body = protocol.writeBootstrapRequest(new BootstrapRequest(1, RUN, ATTEMPT, POD));
        byte[] expected = body.clone();
        var request = new ProxyRequest(LocalOperation.BOOTSTRAP, CALL, body);
        Arrays.fill(body, (byte) 0);
        Arrays.fill(request.payload(), (byte) 0);
        assertArrayEquals(expected, request.payload());
        assertTrue(request.toString().contains("[redacted]"));
        assertFalse(request.toString().contains("protocolVersion"));
    }

    @Test
    void wrongMagicVersionOperationOrNegativeLengthAreRejected() throws IOException {
        byte[] valid = requestBytes(bootstrap());
        for (int offset : new int[]{0, 4, 5, 22}) {
            byte[] changed = valid.clone();
            changed[offset] = (byte) 255;
            assertThrows(ProtocolException.class, () -> FrameCodec.readRequest(new ByteArrayInputStream(changed)));
        }
    }

    @Test
    void everyTruncatedRequestIsRejected() throws IOException {
        byte[] valid = requestBytes(bootstrap());
        for (int length = 0; length < valid.length; length++) {
            byte[] cut = Arrays.copyOf(valid, length);
            assertThrows(ProtocolException.class, () -> FrameCodec.readRequest(new ByteArrayInputStream(cut)));
        }
    }

    @Test
    void oversizedDeclaredRequestIsDeniedBeforeReadingAnyBody() throws IOException {
        byte[] prefix = Arrays.copyOf(requestBytes(bootstrap()), 26);
        ByteBuffer.wrap(prefix, 22, 4).putInt(4097);
        InputStream input = new InputStream() {
            private int position;

            @Override
            public int read() {
                if (position == prefix.length) {
                    throw new AssertionError("Oversized frame attempted a body read");
                }
                return Byte.toUnsignedInt(prefix[position++]);
            }
        };
        assertEquals(ProtocolException.Reason.INPUT_TOO_LARGE,
                assertThrows(ProtocolException.class, () -> FrameCodec.readRequest(input)).reason());
    }

    @Test
    void extraBytesAndConcatenatedFramesAreDenied() throws IOException {
        byte[] valid = requestBytes(bootstrap());
        for (byte[] suffix : new byte[][]{{0}, valid}) {
            byte[] extra = Arrays.copyOf(valid, valid.length + suffix.length);
            System.arraycopy(suffix, 0, extra, valid.length, suffix.length);
            assertThrows(ProtocolException.class, () -> FrameCodec.readRequest(new ByteArrayInputStream(extra)));
        }
    }

    @Test
    void malformedClosedJsonNeverExposesItsInputOrCause() {
        byte[] body = "{\"unexpected\":\"PRIVATE_CANARY\"}".getBytes(StandardCharsets.UTF_8);
        var failure = assertThrows(ProtocolException.class,
                () -> new ProxyRequest(LocalOperation.BOOTSTRAP, CALL, body));
        assertFalse(failure.getMessage().contains("PRIVATE_CANARY"));
        assertNull(failure.getCause());
    }

    @Test
    void nullAndEmptyRequestValuesAreDenied() {
        assertThrows(ProtocolException.class, () -> new ProxyRequest(null, CALL, new byte[]{1}));
        assertThrows(ProtocolException.class, () -> new ProxyRequest(LocalOperation.BOOTSTRAP, null, new byte[]{1}));
        assertThrows(ProtocolException.class, () -> new ProxyRequest(LocalOperation.BOOTSTRAP, CALL, null));
        assertThrows(ProtocolException.class, () -> new ProxyRequest(LocalOperation.BOOTSTRAP, CALL, new byte[0]));
        assertThrows(ProtocolException.class, () -> new ProxyRequest(LocalOperation.BOOTSTRAP, CALL, new byte[4097]));
    }

    @Test
    void replyRoundtripKeepsPayloadOpaqueAndOwnsItsBytes() throws IOException {
        byte[] payload = {(byte) 255, 0, 1};
        var reply = new ProxyReply(ProxyReply.Outcome.UPSTREAM_REPLY, CALL, 200, payload);
        payload[0] = 0;
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        FrameCodec.writeReply(output, reply);
        byte[] encoded = output.toByteArray();
        assertArrayEquals(HexFormat.of().parseHex("494c4d52010100112233445566778899aabbccddeeff00c800000003"),
                Arrays.copyOf(encoded, 28));
        assertEquals(reply, FrameCodec.readReply(new ByteArrayInputStream(encoded)));
        Arrays.fill(reply.payload(), (byte) 0);
        assertArrayEquals(new byte[]{(byte) 255, 0, 1}, reply.payload());
        assertTrue(reply.toString().contains("[redacted]"));
    }

    @Test
    void safeOutcomesHaveNoStatusOrBody() throws IOException {
        for (var outcome : new ProxyReply.Outcome[]{ProxyReply.Outcome.NOT_SENT, ProxyReply.Outcome.UNKNOWN}) {
            var reply = new ProxyReply(outcome, CALL, 0, new byte[0]);
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            FrameCodec.writeReply(output, reply);
            assertEquals(reply, FrameCodec.readReply(new ByteArrayInputStream(output.toByteArray())));
            assertThrows(ProtocolException.class, () -> new ProxyReply(outcome, CALL, 200, new byte[0]));
            assertThrows(ProtocolException.class, () -> new ProxyReply(outcome, CALL, 0, new byte[]{1}));
        }
    }

    @Test
    void invalidReplyCombinationsAreDenied() {
        assertThrows(ProtocolException.class, () -> new ProxyReply(null, CALL, 0, new byte[0]));
        assertThrows(ProtocolException.class, () -> new ProxyReply(ProxyReply.Outcome.UNKNOWN, null, 0, new byte[0]));
        assertThrows(ProtocolException.class, () -> new ProxyReply(ProxyReply.Outcome.UNKNOWN, CALL, 0, null));
        for (int status : new int[]{0, 199, 600, 65535}) {
            assertThrows(ProtocolException.class,
                    () -> new ProxyReply(ProxyReply.Outcome.UPSTREAM_REPLY, CALL, status, new byte[]{1}));
        }
        assertThrows(ProtocolException.class,
                () -> new ProxyReply(ProxyReply.Outcome.UPSTREAM_REPLY, CALL, 200, new byte[0]));
        assertThrows(ProtocolException.class,
                () -> new ProxyReply(ProxyReply.Outcome.UPSTREAM_REPLY, CALL, 200, new byte[4097]));
    }

    @Test
    void replyRejectsEveryTruncationInvalidHeaderAndTrailingData() throws IOException {
        var output = new ByteArrayOutputStream();
        FrameCodec.writeReply(output, new ProxyReply(ProxyReply.Outcome.UPSTREAM_REPLY, CALL, 200, new byte[]{1}));
        byte[] valid = output.toByteArray();
        for (int length = 0; length < valid.length; length++) {
            byte[] cut = Arrays.copyOf(valid, length);
            assertThrows(ProtocolException.class, () -> FrameCodec.readReply(new ByteArrayInputStream(cut)));
        }
        for (int offset : new int[]{0, 4, 5, 22, 24}) {
            byte[] changed = valid.clone();
            changed[offset] = (byte) 255;
            assertThrows(ProtocolException.class, () -> FrameCodec.readReply(new ByteArrayInputStream(changed)));
        }
        byte[] extra = Arrays.copyOf(valid, valid.length + 1);
        assertThrows(ProtocolException.class, () -> FrameCodec.readReply(new ByteArrayInputStream(extra)));
        byte[] oversized = Arrays.copyOf(valid, 28);
        ByteBuffer.wrap(oversized, 24, 4).putInt(4097);
        assertEquals(ProtocolException.Reason.INPUT_TOO_LARGE,
                assertThrows(ProtocolException.class, () -> FrameCodec.readReply(new ByteArrayInputStream(oversized)))
                        .reason());
    }

    @Test
    void closedTransportFailuresStayIoFailures() throws IOException {
        var input = InputStream.nullInputStream();
        input.close();
        assertThrows(IOException.class, () -> FrameCodec.readRequest(input));
        var output = java.io.OutputStream.nullOutputStream();
        output.close();
        assertThrows(IOException.class, () -> FrameCodec.writeRequest(output, bootstrap()));
    }

    private ProxyRequest bootstrap() {
        return new ProxyRequest(LocalOperation.BOOTSTRAP, CALL,
                protocol.writeBootstrapRequest(new BootstrapRequest(1, RUN, ATTEMPT, POD)));
    }

    private byte[] requestBytes(ProxyRequest request) throws IOException {
        var output = new ByteArrayOutputStream();
        FrameCodec.writeRequest(output, request);
        return output.toByteArray();
    }
}

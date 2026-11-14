package com.otilm.core.feasibility;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Encodes one finite frame before any response write; JSON text cannot inject SSE fields. */
public final class ConversationStreamFrames {
    private static final int MAXIMUM = 32768;
    private final ObjectMapper mapper;

    public ConversationStreamFrames(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public byte[] entry(ConversationTimeline.Event event) {
        Buffer buffer = new Buffer();
        try {
            buffer.write(("id: " + event.cursor() + "\nevent: entry\ndata: ").getBytes(StandardCharsets.UTF_8));
            try (JsonGenerator json = mapper.getFactory().createGenerator(buffer)) {
                json.disable(JsonGenerator.Feature.AUTO_CLOSE_TARGET);
                json.writeStartObject();
                json.writeStringField("cursor", event.cursor().toString());
                json.writeStringField("runId", event.runId().toString());
                json.writeStringField("value", event.value());
                json.writeEndObject();
            }
            buffer.write("\n\n".getBytes(StandardCharsets.UTF_8));
            return buffer.bytes();
        } catch (IOException failure) {
            throw new FrameUnavailable();
        }
    }

    public byte[] heartbeat() {
        return ": keep-alive\n\n".getBytes(StandardCharsets.UTF_8);
    }

    public byte[] connected() {
        return ": connected\n\n".getBytes(StandardCharsets.UTF_8);
    }

    public byte[] complete() {
        return "event: complete\ndata:\n\n".getBytes(StandardCharsets.UTF_8);
    }

    public byte[] forbidden() {
        return "event: forbidden\ndata:\n\n".getBytes(StandardCharsets.UTF_8);
    }

    public static final class FrameUnavailable extends RuntimeException {
        public FrameUnavailable() {
            super("Frame unavailable", null, false, false);
        }
    }

    private static final class Buffer extends OutputStream {
        private final byte[] content = new byte[MAXIMUM];
        private int count;

        @Override
        public void write(int value) {
            if (count == content.length) {
                throw new FrameUnavailable();
            }
            content[count++] = (byte) value;
        }

        @Override
        public void write(byte[] bytes, int offset, int length) {
            if (length > content.length - count) {
                throw new FrameUnavailable();
            }
            System.arraycopy(bytes, offset, content, count, length);
            count += length;
        }

        byte[] bytes() {
            return Arrays.copyOf(content, count);
        }
    }
}

package com.otilm.ai.proxy;

import com.otilm.ai.runtime.protocol.ProtocolException;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

/** Bounded opaque response bytes; the parent does not decode protected response content. */
public record ProxyReply(Outcome outcome, UUID correlationId, int httpStatus, byte[] payload) {
    public enum Outcome {
        UPSTREAM_REPLY(1),
        NOT_SENT(2),
        UNKNOWN(3);

        private final int tag;

        Outcome(int tag) {
            this.tag = tag;
        }

        int tag() {
            return tag;
        }

        static Outcome fromTag(int tag) {
            return switch (tag) {
                case 1 -> UPSTREAM_REPLY;
                case 2 -> NOT_SENT;
                case 3 -> UNKNOWN;
                default -> throw new ProtocolException(ProtocolException.Reason.INVALID_MESSAGE);
            };
        }
    }

    public ProxyReply {
        if (outcome == null || correlationId == null || payload == null
                || payload.length > FrameCodec.MAX_PAYLOAD_BYTES) {
            throw new ProtocolException(ProtocolException.Reason.INVALID_MESSAGE);
        }
        if (outcome == Outcome.UPSTREAM_REPLY
                ? httpStatus < 200 || httpStatus > 599 || payload.length == 0
                : httpStatus != 0 || payload.length != 0) {
            throw new ProtocolException(ProtocolException.Reason.INVALID_MESSAGE);
        }
        payload = payload.clone();
    }

    @Override
    public byte[] payload() {
        return payload.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof ProxyReply reply && outcome == reply.outcome
                && correlationId.equals(reply.correlationId) && httpStatus == reply.httpStatus
                && Arrays.equals(payload, reply.payload);
    }

    @Override
    public int hashCode() {
        return Objects.hash(outcome, correlationId, httpStatus, Arrays.hashCode(payload));
    }

    @Override
    public String toString() {
        return "ProxyReply[outcome=" + outcome + ", correlationId=" + correlationId + ", httpStatus=" + httpStatus
                + ", payload=[redacted]]";
    }
}

package com.otilm.ai.proxy;

import com.otilm.ai.runtime.protocol.ProtocolCodec;
import com.otilm.ai.runtime.protocol.ProtocolException;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

/** A local request label and closed body; neither supplies execution authority. */
public record ProxyRequest(LocalOperation operation, UUID correlationId, byte[] payload) {
    private static final ProtocolCodec CODEC = new ProtocolCodec();

    public ProxyRequest {
        if (operation == null || correlationId == null || payload == null || payload.length == 0
                || payload.length > FrameCodec.MAX_PAYLOAD_BYTES) {
            throw new ProtocolException(ProtocolException.Reason.INVALID_MESSAGE);
        }
        payload = payload.clone();
        switch (operation) {
            case BOOTSTRAP -> CODEC.readBootstrapRequest(payload);
            case HEARTBEAT -> CODEC.readClaimHeartbeatRequest(payload);
        }
    }

    @Override
    public byte[] payload() {
        return payload.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof ProxyRequest request && operation == request.operation
                && correlationId.equals(request.correlationId) && Arrays.equals(payload, request.payload);
    }

    @Override
    public int hashCode() {
        return Objects.hash(operation, correlationId, Arrays.hashCode(payload));
    }

    @Override
    public String toString() {
        return "ProxyRequest[operation=" + operation + ", correlationId=" + correlationId + ", payload=[redacted]]";
    }
}

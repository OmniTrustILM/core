package com.otilm.ai.proxy;

import com.otilm.ai.runtime.protocol.ProtocolException;

public enum LocalOperation {
    BOOTSTRAP(1, "/internal/ai-runtime/v1/runner/bootstrap"),
    HEARTBEAT(2, "/internal/ai-runtime/v1/runner/claims/heartbeat");

    private final int tag;
    private final String path;

    LocalOperation(int tag, String path) {
        this.tag = tag;
        this.path = path;
    }

    public String path() {
        return path;
    }

    int tag() {
        return tag;
    }

    static LocalOperation fromTag(int tag) {
        return switch (tag) {
            case 1 -> BOOTSTRAP;
            case 2 -> HEARTBEAT;
            default -> throw new ProtocolException(ProtocolException.Reason.INVALID_MESSAGE);
        };
    }
}

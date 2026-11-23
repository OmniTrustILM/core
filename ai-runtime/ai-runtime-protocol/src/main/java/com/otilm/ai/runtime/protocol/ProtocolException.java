package com.otilm.ai.runtime.protocol;

public final class ProtocolException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final Reason reason;

    public enum Reason {
        INVALID_DISPATCH,
        INVALID_MESSAGE,
        UNSUPPORTED_VERSION,
        INPUT_TOO_LARGE,
        LIMIT_EXCEEDED,
        FINGERPRINT_UNAVAILABLE
    }

    public ProtocolException(Reason reason) {
        super(reason.name(), null, false, false);
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }
}

package com.otilm.ai.gateway;

final class GatewayFailure extends RuntimeException {
    private static final long serialVersionUID = 1L;

    enum Code {
        INVALID_REQUEST,
        UPSTREAM_FAILURE,
        RESPONSE_LIMIT,
        UNSUPPORTED_ENCODING
    }

    private final Code code;

    GatewayFailure(Code code) {
        super(code.name(), null, false, false);
        this.code = code;
    }

    // Provider transport fact only; the finite executable may already hold a consumed intent.
    // A later validation never reopens that intent, even when no provider request was sent.
    boolean mayHaveSent() {
        return code != Code.INVALID_REQUEST;
    }

    Code code() {
        return code;
    }
}

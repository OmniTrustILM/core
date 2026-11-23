package com.otilm.ai.runtime.protocol;

import java.util.UUID;
import java.util.regex.Pattern;

final class ProtocolValidation {
    static final int MAX_BYTES = 1_048_576;
    static final int MAX_CONTROL_BYTES = 4096;
    private static final Pattern DIGEST = Pattern.compile("[0-9a-f]{64}");

    private ProtocolValidation() {
    }

    static void envelope(int version, UUID intentId, String digest, Object binding) {
        version(version);
        required(intentId, digest, binding);
        if (!DIGEST.matcher(digest).matches()) {
            throw invalid();
        }
    }

    static void message(int version, Object... values) {
        version(version);
        required(ProtocolException.Reason.INVALID_MESSAGE, values);
    }

    private static void version(int version) {
        if (version != 1) {
            throw new ProtocolException(ProtocolException.Reason.UNSUPPORTED_VERSION);
        }
    }

    static void required(Object... values) {
        required(ProtocolException.Reason.INVALID_DISPATCH, values);
    }

    static void required(ProtocolException.Reason reason, Object... values) {
        for (Object value : values) {
            if (value == null) {
                throw new ProtocolException(reason);
            }
        }
    }

    static void positive(long value) {
        positive(value, ProtocolException.Reason.INVALID_DISPATCH);
    }

    static void positive(long value, ProtocolException.Reason reason) {
        if (value <= 0) {
            throw new ProtocolException(reason);
        }
    }

    static void bounded(byte[] bytes) {
        bounded(bytes, MAX_BYTES, ProtocolException.Reason.INVALID_DISPATCH);
    }

    static void bounded(byte[] bytes, int maximum, ProtocolException.Reason reason) {
        if (bytes == null) {
            throw new ProtocolException(reason);
        }
        if (bytes.length > maximum) {
            throw new ProtocolException(ProtocolException.Reason.INPUT_TOO_LARGE);
        }
    }

    static ProtocolException invalid() {
        return new ProtocolException(ProtocolException.Reason.INVALID_DISPATCH);
    }
}

package com.otilm.ai.runtime.protocol;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

public final class PayloadFingerprint {
    private PayloadFingerprint() {
    }

    /** Hashes exact bytes, including an empty vector; this does not validate a model request. */
    public static String sha256(byte[] payload) {
        ProtocolValidation.bounded(payload);
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(payload);
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new ProtocolException(ProtocolException.Reason.FINGERPRINT_UNAVAILABLE);
        }
    }
}

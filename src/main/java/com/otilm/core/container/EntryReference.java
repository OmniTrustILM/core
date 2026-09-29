package com.otilm.core.container;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** How an entry, and the file itself, is named: by the SHA-256 of its content. */
public final class EntryReference {

    private EntryReference() {
    }

    /**
     * The reference of the content.
     *
     * @param content the bytes to name, whatever they hold
     * @return the lowercase hex SHA-256 of the content
     */
    public static String of(byte[] content) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available.", e);
        }
    }
}

package com.otilm.core.container;

import java.util.Arrays;
import java.util.List;

/** What a format finds, in file order, before any key is opened. */
// S6218: nothing compares, hashes or prints an item; it only carries what the format found to the assembler.
@SuppressWarnings("java:S6218")
sealed interface RawItem {

    /**
     * Overwrites the key of every key item, once nothing is to read them any more.
     *
     * @param items the items a format found
     */
    static void overwriteKeys(List<RawItem> items) {
        for (RawItem item : items) {
            if (item instanceof Key key) {
                Arrays.fill(key.keyFile(), (byte) 0);
            }
        }
    }

    /**
     * A certificate.
     *
     * @param der the certificate's DER
     * @param alias the name the file gives the certificate, or {@code null}
     * @param localKeyId the identifier the file gives the certificate's key, or {@code null}
     */
    record Certificate(byte[] der, String alias, byte[] localKeyId) implements RawItem {
    }

    /**
     * A key, as the file holds it.
     *
     * @param keyFile the key, readable on its own by the normalizer; a copy the format made, overwritten by whoever
     * keeps it last
     * @param alias the name the file gives the key, or {@code null}
     * @param localKeyId the identifier the file gives the key, or {@code null}
     * @param secret whether the file stores the key as a secret key
     */
    record Key(byte[] keyFile, String alias, byte[] localKeyId, boolean secret) implements RawItem {
    }

    /**
     * A certificate request.
     *
     * @param der the request's DER
     */
    record SigningRequest(byte[] der) implements RawItem {
    }
}

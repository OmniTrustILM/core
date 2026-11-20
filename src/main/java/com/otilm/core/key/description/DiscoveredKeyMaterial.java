package com.otilm.core.key.description;

import java.util.Base64;

/** Base64 key material a discovery connector reports. It may arrive line-wrapped. */
public final class DiscoveredKeyMaterial {

    private DiscoveredKeyMaterial() {
    }

    /**
     * @param material the reported Base64
     * @return the decoded bytes
     * @throws IllegalArgumentException for malformed material
     */
    public static byte[] decoded(String material) {
        return Base64.getDecoder().decode(material.replaceAll("\\s", ""));
    }
}

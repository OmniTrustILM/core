package com.otilm.core.signing.contentsigning;

import java.util.Objects;
import java.util.UUID;

/**
 * One document's result in a content-signing batch.
 *
 * @param identifier the caller-chosen identifier of the document
 * @param signingRecordUuid the UUID of the document's signing record, or {@code null} when the profile records nothing
 */
public record SignedItem(String identifier, SignedContent content, UUID signingRecordUuid) {

    public SignedItem {
        Objects.requireNonNull(identifier, "identifier");
        Objects.requireNonNull(content, "content");
    }
}

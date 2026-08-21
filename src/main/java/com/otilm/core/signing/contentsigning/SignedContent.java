package com.otilm.core.signing.contentsigning;

import com.otilm.api.model.common.signature.SignatureLevel;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * A signed document and what it took to get there.
 *
 * @param timestampSerials serials of the timestamp tokens embedded in it, in the order they were issued, so the
 * operation traces to its timestamp records
 */
public record SignedContent(byte[] signedDocument, SignatureLevel level, List<BigInteger> timestampSerials) {

    public SignedContent {
        Objects.requireNonNull(signedDocument, "signedDocument");
        Objects.requireNonNull(level, "level");
        signedDocument = signedDocument.clone();
        timestampSerials = List.copyOf(timestampSerials);
    }

    @Override
    public byte[] signedDocument() {
        return signedDocument.clone();
    }

    /** A record's generated {@code equals} would compare the document by identity, so two equal results differ. */
    @Override
    public boolean equals(Object other) {
        return other instanceof SignedContent content && level == content.level
                && Arrays.equals(signedDocument, content.signedDocument)
                && timestampSerials.equals(content.timestampSerials);
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(signedDocument), level, timestampSerials);
    }

    /** The signed document is customer content, so only its size is logged. */
    @Override
    public String toString() {
        return "SignedContent[signedDocument=" + signedDocument.length + " bytes, level=" + level
                + ", timestampSerials=" + timestampSerials + "]";
    }
}

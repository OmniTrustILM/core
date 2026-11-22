package com.otilm.core.signing.contentsigning;

import com.otilm.api.model.common.signature.SignatureLevel;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * A signing output and what it took to get there.
 *
 * @param output the signed document, the detached signature or the container, as the signature format produces
 * @param mediaType the media type the formatting connector named for the output
 * @param timestampSerials serials of the timestamp tokens embedded in it, in the order they were issued, so the
 * operation traces to its timestamp records
 */
public record SignedContent(byte[] output, String mediaType, SignatureLevel level, List<BigInteger> timestampSerials) {

    public SignedContent {
        Objects.requireNonNull(output, "output");
        Objects.requireNonNull(mediaType, "mediaType");
        Objects.requireNonNull(level, "level");
        output = output.clone();
        timestampSerials = List.copyOf(timestampSerials);
    }

    @Override
    public byte[] output() {
        return output.clone();
    }

    /** A record's generated {@code equals} would compare the output by identity, so two equal results differ. */
    @Override
    public boolean equals(Object other) {
        return other instanceof SignedContent content && level == content.level && Arrays.equals(output, content.output)
                && mediaType.equals(content.mediaType) && timestampSerials.equals(content.timestampSerials);
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(output), mediaType, level, timestampSerials);
    }

    /** The output is customer content, so only its size is logged. */
    @Override
    public String toString() {
        return "SignedContent[output=" + output.length + " bytes, mediaType=" + mediaType + ", level=" + level
                + ", timestampSerials=" + timestampSerials + "]";
    }
}

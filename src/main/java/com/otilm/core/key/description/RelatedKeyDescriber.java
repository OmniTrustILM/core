package com.otilm.core.key.description;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.core.model.crypto.KeyMaterial;
import java.util.List;
import java.util.Optional;

/** Describes a key half among the halves stored or returned with it. */
public final class RelatedKeyDescriber {

    /**
     * A key half as its provider stated it, with its key data in the form Core stores it.
     *
     * @param algorithm the stated algorithm
     * @param length the stated length in bits
     * @param material the stored key data, or null
     */
    public record KeyHalf(KeyType type, KeyAlgorithm algorithm, Integer length, KeyMaterial material) {
    }

    private RelatedKeyDescriber() {
    }

    /**
     * Core describes the half from the first readable source: its own key data, its agreeing public siblings, the
     * software provider's custom map, or else its statement. Agreeing siblings also supply an RSA modulus missing from
     * the half's own key data.
     *
     * @param related the halves stored or returned with it, which may include the half itself
     */
    public static DescribedKey describe(KeyHalf half, List<KeyHalf> related) {
        KeyParameters parameters = KeyParameters
                .ofStoredKeyData(half.material())
                .map(own -> withSiblingModulus(own, half, related))
                .or(() -> agreedByPublicSiblings(half, related))
                .or(() -> SoftwareProviderKeyValues.parametersOf(half.algorithm(), half.material()))
                .orElse(null);
        return KeyDescriber.describe(parameters, half.type(), half.algorithm(), half.length());
    }

    /**
     * The parameters the half's public siblings carry, when every sibling Core reads names the same ones.
     *
     * @param related the halves stored or returned with it
     * @return the parameters, present when Core reads at least one public sibling and all it reads carry the same
     * parameters
     */
    public static Optional<KeyParameters> agreedByPublicSiblings(KeyHalf half, List<KeyHalf> related) {
        if (half.type() == KeyType.SECRET_KEY) {
            return Optional.empty();
        }
        List<KeyParameters> read = related
                .stream()
                .filter(sibling -> sibling.type() == KeyType.PUBLIC_KEY)
                .flatMap(sibling -> KeyParameters.ofStoredKeyData(sibling.material()).stream())
                .toList();
        if (read.isEmpty()) {
            return Optional.empty();
        }
        boolean agree = read.stream().distinct().count() == 1;
        return agree ? Optional.of(read.getFirst()) : Optional.empty();
    }

    private static KeyParameters withSiblingModulus(KeyParameters own, KeyHalf half, List<KeyHalf> related) {
        if (own.modulusBits() != null) {
            return own;
        }
        return agreedByPublicSiblings(half, related)
                .filter(agreed -> agreed.identifier().equals(own.identifier()))
                .orElse(own);
    }
}

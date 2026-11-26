package com.otilm.core.key.description;

import com.otilm.core.key.description.RelatedKeyDescriber.KeyHalf;
import com.otilm.core.model.crypto.ProviderKeyItem;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/** Describes the key items a provider returns, each among the items it returned with it. */
public final class ProviderKeyItems {

    private ProviderKeyItems() {
    }

    public record DescribedPair(ProviderKeyItem publicKey, ProviderKeyItem privateKey) {
    }

    /** Describes an item a provider returned without a sibling, such as a secret key. */
    public static ProviderKeyItem described(ProviderKeyItem item) {
        return describedAmong(item, List.of(halfOf(item)));
    }

    public static DescribedPair describedPair(ProviderKeyItem publicKeyItem, ProviderKeyItem privateKeyItem) {
        List<KeyHalf> pair = List.of(halfOf(publicKeyItem), halfOf(privateKeyItem));
        ProviderKeyItem describedPublicKey = describedAmong(publicKeyItem, pair);
        ProviderKeyItem describedPrivateKey = describedAmong(privateKeyItem, pair);
        return new DescribedPair(describedPublicKey, describedPrivateKey);
    }

    /**
     * Describes listed items, each among the items sharing its association. An unassociated item is described alone.
     *
     * @return the items, each described, in the same order
     */
    public static List<ProviderKeyItem> describedByAssociation(List<ProviderKeyItem> listed) {
        Map<String, List<KeyHalf>> halvesByAssociation = listed
                .stream()
                .filter(ProviderKeyItems::hasAssociation)
                .collect(Collectors
                        .groupingBy(ProviderKeyItem::association,
                                Collectors.mapping(ProviderKeyItems::halfOf, Collectors.toList())));
        return listed.stream().map(item -> describedAmong(item, halvesSharing(item, halvesByAssociation))).toList();
    }

    private static List<KeyHalf> halvesSharing(ProviderKeyItem item, Map<String, List<KeyHalf>> halvesByAssociation) {
        return hasAssociation(item) ? halvesByAssociation.get(item.association()) : List.of(halfOf(item));
    }

    private static ProviderKeyItem describedAmong(ProviderKeyItem item, List<KeyHalf> related) {
        return item.describedAs(RelatedKeyDescriber.describe(halfOf(item), related));
    }

    private static boolean hasAssociation(ProviderKeyItem item) {
        return item.association() != null && !item.association().isEmpty();
    }

    private static KeyHalf halfOf(ProviderKeyItem item) {
        return new KeyHalf(item.type(), item.algorithm(), item.length(), item.material());
    }
}

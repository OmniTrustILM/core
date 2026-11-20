package com.otilm.core.key.description;

import com.otilm.core.key.description.RelatedKeyDescriber.KeyHalf;
import com.otilm.core.model.crypto.ProviderKeyItem;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Describes the key items a provider returns, each among the items it returned with it. */
public final class ProviderKeyItems {

    private ProviderKeyItems() {
    }

    public record DescribedPair(ProviderKeyItem publicKey, ProviderKeyItem privateKey) {
    }

    /** Describes an item a provider returned without a sibling, such as a secret key. */
    public static ProviderKeyItem described(ProviderKeyItem item) {
        return describedTogether(List.of(item)).getFirst();
    }

    public static DescribedPair describedPair(ProviderKeyItem publicKeyItem, ProviderKeyItem privateKeyItem) {
        List<ProviderKeyItem> described = describedTogether(List.of(publicKeyItem, privateKeyItem));
        return new DescribedPair(described.getFirst(), described.getLast());
    }

    /**
     * Describes listed items, each among the items sharing its association. An unassociated item is described alone.
     *
     * @return the items, each described, in the same order
     */
    public static List<ProviderKeyItem> describedByAssociation(List<ProviderKeyItem> listed) {
        Map<String, List<Integer>> positionsByAssociation = new LinkedHashMap<>();
        List<List<Integer>> groups = new ArrayList<>();
        for (int i = 0; i < listed.size(); i++) {
            String association = listed.get(i).association();
            if (association == null || association.isEmpty()) {
                groups.add(List.of(i));
            } else {
                positionsByAssociation.computeIfAbsent(association, key -> new ArrayList<>()).add(i);
            }
        }
        groups.addAll(positionsByAssociation.values());
        ProviderKeyItem[] described = new ProviderKeyItem[listed.size()];
        for (List<Integer> positions : groups) {
            List<ProviderKeyItem> group = positions.stream().map(listed::get).toList();
            List<ProviderKeyItem> describedGroup = describedTogether(group);
            for (int i = 0; i < positions.size(); i++) {
                described[positions.get(i)] = describedGroup.get(i);
            }
        }
        return List.of(described);
    }

    private static List<ProviderKeyItem> describedTogether(List<ProviderKeyItem> related) {
        List<KeyHalf> halves = related.stream().map(ProviderKeyItems::halfOf).toList();
        List<ProviderKeyItem> described = new ArrayList<>(related.size());
        for (int i = 0; i < related.size(); i++) {
            described.add(related.get(i).describedAs(RelatedKeyDescriber.describe(halves.get(i), halves)));
        }
        return described;
    }

    private static KeyHalf halfOf(ProviderKeyItem item) {
        return new KeyHalf(item.type(), item.algorithm(), item.length(), item.material());
    }
}

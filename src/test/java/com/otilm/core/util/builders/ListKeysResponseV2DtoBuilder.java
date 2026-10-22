package com.otilm.core.util.builders;

import com.otilm.api.model.connector.cryptography.v2.key.ListKeysResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ListedKeyV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.UnusableKeyV2Dto;
import java.util.List;

/**
 * Builds an empty page of a connector's key listing. The listing's total counts the page's keys unless a test sets a
 * larger one, as a page from the middle of a listing has.
 */
public final class ListKeysResponseV2DtoBuilder {

    private List<ListedKeyV2Dto> keys = List.of();
    private List<UnusableKeyV2Dto> unusableKeys = List.of();
    private Long totalItems;

    public static ListKeysResponseV2DtoBuilder aKeyListing() {
        return new ListKeysResponseV2DtoBuilder();
    }

    public ListKeysResponseV2DtoBuilder withKeys(ListedKeyV2Dto... keys) {
        this.keys = List.of(keys);
        return this;
    }

    public ListKeysResponseV2DtoBuilder withUnusableKeys(UnusableKeyV2Dto... unusableKeys) {
        this.unusableKeys = List.of(unusableKeys);
        return this;
    }

    public ListKeysResponseV2DtoBuilder withTotalItems(long totalItems) {
        this.totalItems = totalItems;
        return this;
    }

    public ListKeysResponseV2Dto build() {
        ListKeysResponseV2Dto listing = new ListKeysResponseV2Dto();
        listing.setItems(keys);
        listing.setUnusableKeys(unusableKeys);
        listing.setTotalItems(totalItems == null ? keys.size() + unusableKeys.size() : totalItems);
        return listing;
    }
}

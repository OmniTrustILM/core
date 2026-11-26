package com.otilm.core.util.builders;

import com.otilm.api.model.connector.cryptography.v2.key.ListKeysResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ListedKeyEntryV2Dto;
import java.util.List;

/**
 * Builds an empty page of a connector's key listing. The listing's total counts the page's entries unless a test sets a
 * larger one, as a page from the middle of a listing has.
 */
public final class ListKeysResponseV2DtoBuilder {

    private List<ListedKeyEntryV2Dto> entries = List.of();
    private Long totalItems;

    public static ListKeysResponseV2DtoBuilder aKeyListing() {
        return new ListKeysResponseV2DtoBuilder();
    }

    public ListKeysResponseV2DtoBuilder withEntries(ListedKeyEntryV2Dto... entries) {
        this.entries = List.of(entries);
        return this;
    }

    public ListKeysResponseV2DtoBuilder withTotalItems(long totalItems) {
        this.totalItems = totalItems;
        return this;
    }

    public ListKeysResponseV2Dto build() {
        ListKeysResponseV2Dto listing = new ListKeysResponseV2Dto();
        listing.setItems(entries);
        listing.setTotalItems(totalItems == null ? entries.size() : totalItems);
        return listing;
    }
}

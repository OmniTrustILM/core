package com.otilm.core.model.crypto;

import java.util.List;

/** A page of a token's key entries in the token's order, with the number of entries in the whole listing. */
public record ProviderKeyEntryPage(List<ProviderKeyEntry> entries, long totalItems) {

    public ProviderKeyEntryPage {
        entries = List.copyOf(entries);
    }
}

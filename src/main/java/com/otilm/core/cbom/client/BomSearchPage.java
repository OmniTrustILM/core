package com.otilm.core.cbom.client;

import com.otilm.core.model.cbom.BomEntryDto;
import java.net.URI;
import java.util.List;

/**
 * One page of the cbom-repository search feed.
 *
 * @param entries the page body, never null (an empty last page is legal)
 * @param nextPage Core's own {@code /api/v1/bom} URL carrying the continuation query the repository's
 * {@code Link rel="next"} header named, or null when the response carried no such header -- which, not the page size,
 * is what says the run is complete. Opaque to callers: hand it back to {@code CbomRepositoryClient#nextPage}.
 */
public record BomSearchPage(List<BomEntryDto> entries, URI nextPage) {

    public BomSearchPage {
        entries = entries == null ? List.of() : List.copyOf(entries);
    }

    public boolean hasNext() {
        return nextPage != null;
    }
}

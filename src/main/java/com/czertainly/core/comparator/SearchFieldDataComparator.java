package com.czertainly.core.comparator;

import com.otilm.api.model.core.search.SearchFieldDataDto;

import java.util.Comparator;

public class SearchFieldDataComparator implements Comparator<SearchFieldDataDto> {
    @Override
    public int compare(SearchFieldDataDto o1, SearchFieldDataDto o2) {
        return o1.getFieldLabel().compareTo(o2.getFieldLabel());
    }

}

package com.otilm.core.util;

import java.util.Arrays;
import java.util.Iterator;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchResult;

/** Supplies LDAP search results backed by real directory attributes. */
public final class LdapFixtures {

    private LdapFixtures() {
    }

    public static SearchResults searchResults(Attributes... entries) {
        return new SearchResults(Arrays.stream(entries).map(attrs -> new SearchResult("", null, attrs)).iterator());
    }

    public static final class SearchResults implements NamingEnumeration<SearchResult> {

        private final Iterator<SearchResult> entries;
        private boolean closed;

        private SearchResults(Iterator<SearchResult> entries) {
            this.entries = entries;
        }

        @Override
        public SearchResult next() {
            return entries.next();
        }

        @Override
        public boolean hasMore() {
            return entries.hasNext();
        }

        @Override
        public void close() {
            closed = true;
        }

        public boolean isClosed() {
            return closed;
        }

        @Override
        public boolean hasMoreElements() {
            return hasMore();
        }

        @Override
        public SearchResult nextElement() {
            return next();
        }
    }
}

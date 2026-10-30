package com.otilm.core.container;

import com.otilm.core.key.normalization.KeyFileRefusal;
import com.otilm.core.key.normalization.KeyNormalizer;
import com.otilm.core.key.normalization.NestingDepth;

/** The limits one uploaded file is held to, each checked before the work it guards. */
final class ContainerLimits {

    static final int MAXIMUM_CERTIFICATES = 200;

    /** The keys, secret keys and certificate requests one file may hold together. */
    static final int MAXIMUM_OTHER_ENTRIES = 100;

    private static final String CERTIFICATE_LIMIT = "certificate count";

    private static final String ENTRY_LIMIT = "entry count";

    private static final String NESTING_LIMIT = "nesting depth";

    private ContainerLimits() {
    }

    static void requireCertificatesWithin(int count) {
        if (count > MAXIMUM_CERTIFICATES) {
            throw KeyFileRefusal.limitExceeded(CERTIFICATE_LIMIT, MAXIMUM_CERTIFICATES);
        }
    }

    static void requireOtherEntriesWithin(int count) {
        if (count > MAXIMUM_OTHER_ENTRIES) {
            throw KeyFileRefusal.limitExceeded(ENTRY_LIMIT, MAXIMUM_OTHER_ENTRIES);
        }
    }

    /**
     * Refuses DER that nests deeper than an uploaded file may, before anything parses it.
     *
     * @param der DER from the file, or decrypted from it
     */
    static void requireNestingWithin(byte[] der) {
        if (!NestingDepth.within(der, KeyNormalizer.MAXIMUM_NESTING_DEPTH)) {
            throw KeyFileRefusal.limitExceeded(NESTING_LIMIT, KeyNormalizer.MAXIMUM_NESTING_DEPTH);
        }
    }
}

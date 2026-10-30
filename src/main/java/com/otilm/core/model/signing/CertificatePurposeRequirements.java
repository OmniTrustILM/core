package com.otilm.core.model.signing;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Per-profile constraints on what the signing certificate is <em>for</em>, over and above the default purpose rule
 * every signing certificate must satisfy. Both are off unless the profile turns them on.
 *
 * @param requireNonRepudiation demand the {@code nonRepudiation} key-usage bit specifically
 * @param requiredExtendedKeyUsageOids extended key usage OIDs the certificate must all carry; empty accepts any
 */
public record CertificatePurposeRequirements(boolean requireNonRepudiation, Set<String> requiredExtendedKeyUsageOids) {

    public static final CertificatePurposeRequirements NONE = new CertificatePurposeRequirements(false, Set.of());

    public CertificatePurposeRequirements {
        requiredExtendedKeyUsageOids = requiredExtendedKeyUsageOids == null
                ? Set.of()
                : Collections.unmodifiableSet(new LinkedHashSet<>(requiredExtendedKeyUsageOids));
    }

    public static CertificatePurposeRequirements of(boolean requireNonRepudiation,
            Collection<String> requiredExtendedKeyUsageOids) {
        return new CertificatePurposeRequirements(requireNonRepudiation,
                requiredExtendedKeyUsageOids == null ? null : new LinkedHashSet<>(requiredExtendedKeyUsageOids));
    }
}

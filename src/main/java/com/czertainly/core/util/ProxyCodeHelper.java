package com.czertainly.core.util;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Objects;

/**
 * Helper class for generating normalized proxy codes from human-readable names.
 * <p>
 * This component transforms proxy names into safe, URL-friendly, and database-compatible
 * codes by removing diacritics, normalizing whitespace, and sanitizing special characters.
 * The resulting codes are abbreviated to a maximum length while preserving readability.
 * </p>
 */
@Component
public class ProxyCodeHelper {

    /**
     * Maximum length of the generated proxy code including prefix.
     */
    private static final int LENGTH = 30;

    private final String proxyNamePrefix;

    /**
     * Constructs a ProxyCodeHelper with configurable prefix.
     *
     * @param proxyNamePrefix the prefix to prepend to generated codes,
     *                        defaults to "proxy-" if not configured via {@code proxy.name-prefix}
     */
    public ProxyCodeHelper(@Value("${proxy.name-prefix:proxy-}") String proxyNamePrefix) {
        this.proxyNamePrefix = Objects.requireNonNullElse(proxyNamePrefix, "");
    }

    /**
     * Calculates a normalized proxy code from the given name.
     * <p>
     * The transformation process:
     * <ol>
     *   <li>Removes diacritical marks and accents (using Apache Commons stripAccents)</li>
     *   <li>Converts to lowercase using ROOT locale (avoids locale-specific issues)</li>
     *   <li>Replaces whitespace with hyphens</li>
     *   <li>Removes all characters except [a-z0-9-]</li>
     *   <li>Deduplicates consecutive hyphens to a single hyphen</li>
     *   <li>Prepends the configured prefix</li>
     *   <li>Abbreviates to maximum length, preserving start and end</li>
     * </ol>
     * </p>
     *
     * @param name the human-readable proxy name to transform
     * @return normalized proxy code (max 30 characters, URL-safe, lowercase)
     * @throws IllegalArgumentException if name is blank or null
     */
    public String calculateCode(String name) {
        if (StringUtils.isBlank(name)) {
            throw new IllegalArgumentException("Proxy name must not be blank");
        }

        String normalized = StringUtils.stripAccents(name.trim())
            // Lowercase using ROOT locale (avoids locale-specific issues like Turkish 'I')
            .toLowerCase(Locale.ROOT)
            // Replace whitespace with hyphens
            .replaceAll("\\s", "-")
            // Remove everything except [a-z0-9-]
            .replaceAll("[^a-z0-9-]", "")
            // Deduplicate consecutive hyphens to single hyphen
            .replaceAll("-+", "-");

        // Prepend prefix and abbreviate from the middle if exceeds max length
        return StringUtils.abbreviateMiddle(proxyNamePrefix + normalized, "-", LENGTH);
    }
}

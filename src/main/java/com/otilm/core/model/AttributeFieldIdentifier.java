package com.otilm.core.model;

import com.otilm.api.model.common.attribute.common.content.AttributeContentType;

/**
 * The two parts an attribute-sourced field identifier carries: the attribute's name, and the content type that
 * distinguishes two definitions registered under that same name.
 *
 * <p>
 * Split at the <em>last</em> separator. An attribute name carries no separator restriction, so a name holding a
 * {@code |} would be misread by a split at the first one - {@code team|region|TEXT} would name the attribute
 * {@code team} with a content type of {@code region}. Every site that reads an identifier - the column projection, the
 * attribute filter and the attribute sort - parses it here, so they cannot disagree about which field a request names.
 */
public record AttributeFieldIdentifier(String attributeName, String contentTypeName) {

    public static final String SEPARATOR = "|";

    /**
     * The parts of an identifier, or {@code null} when it names no attribute-sourced field - it carries no separator,
     * or nothing before one.
     */
    public static AttributeFieldIdentifier parse(final String fieldIdentifier) {
        if (fieldIdentifier == null) {
            return null;
        }
        final int separator = fieldIdentifier.lastIndexOf(SEPARATOR);
        return separator <= 0
                ? null
                : new AttributeFieldIdentifier(fieldIdentifier.substring(0, separator),
                        fieldIdentifier.substring(separator + 1));
    }

    /** The content type the identifier names, or {@code null} when it names none that exists. */
    public AttributeContentType contentType() {
        try {
            return AttributeContentType.valueOf(contentTypeName);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}

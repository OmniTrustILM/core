package com.otilm.core.security.authz;

/**
 * One resolved property of an {@code @ExternalAuthorization} annotation on its way to the OPA request.
 *
 * <p>
 * Deliberately not a Spring Security {@code ConfigAttribute}: nothing in the framework consumes these, and that
 * interface is removed in Spring Security 7.
 */
public record ExternalAuthorizationConfigAttribute(String attributeName, Object attributeValue) {

    /** Renders the attribute for trace logging. */
    public String describe() {
        return "%s=%s".formatted(this.attributeName, this.attributeValue);
    }

    public String attributeValueAsString() {
        return attributeValue.toString();
    }
}

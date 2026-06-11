package com.otilm.core.security.authz;

import org.springframework.security.access.ConfigAttribute;

public record ExternalAuthorizationConfigAttribute(String attributeName,
                                                   Object attributeValue) implements ConfigAttribute {

    @Override
    public String getAttribute() {
        return "%s=%s".formatted(this.attributeName, this.attributeValue);
    }

    public String getAttributeValueAsString() {
        return attributeValue.toString();
    }
}

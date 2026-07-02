package com.otilm.core.certificate.request;

import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.core.attribute.CsrAttributes;
import com.otilm.core.util.AttributeDefinitionUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * Resolution/seeding helper for the platform default request-attribute set.
 */
public final class DefaultRequestAttributeSet {

    /**
     * Platform {@code CERTIFICATES}-category setting name holding the serialized default-set definitions.
     */
    public static final String SETTING_NAME = "certificatesRequestAttributes";

    /**
     * Platform {@code CERTIFICATES}-category setting name holding the default external-CSR strictness flag.
     */
    public static final String STRICT_SETTING_NAME = "certificatesRequestAttributesStrict";

    private DefaultRequestAttributeSet() {
    }

    /**
     * The built-in seed.
     */
    public static List<BaseAttribute> seed() {
        return new ArrayList<>(CsrAttributes.csrAttributesAsDataAttributesV3());
    }

    /**
     * @param storedValue the serialized JSON from the platform settings, or {@code null}/blank if unset
     * @return the parsed stored set, or the built-in seed when the stored value is absent/blank
     */
    public static List<BaseAttribute> resolve(String storedValue) {
        if (storedValue == null || storedValue.isBlank()) {
            return seed();
        }
        return AttributeDefinitionUtils.deserialize(storedValue, BaseAttribute.class);
    }
}

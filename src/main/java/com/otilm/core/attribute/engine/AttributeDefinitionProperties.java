package com.otilm.core.attribute.engine;

import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.CustomAttribute;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.properties.BaseAttributeProperties;

/**
 * The properties of an attribute definition, read whatever shape the definition holds.
 *
 * <p>
 * {@link BaseAttribute} declares no accessor for them: each of the three attribute shapes narrows the return type to
 * its own properties class, so a caller that holds only the base type has to resolve the shape first.
 */
public final class AttributeDefinitionProperties {

    private AttributeDefinitionProperties() {
    }

    /**
     * Whether a definition says its values may be shown to a user, which is what a column does with them. A definition
     * of no known shape, or one carrying no properties, is treated as visible - the same default the flag itself
     * carries.
     */
    public static boolean isVisible(BaseAttribute definition) {
        BaseAttributeProperties properties = propertiesOf(definition);
        return properties == null || properties.isVisible();
    }

    private static BaseAttributeProperties propertiesOf(BaseAttribute definition) {
        if (definition instanceof CustomAttribute custom) {
            return custom.getProperties();
        }
        if (definition instanceof DataAttribute data) {
            return data.getProperties();
        }
        if (definition instanceof MetadataAttribute metadata) {
            return metadata.getProperties();
        }
        return null;
    }
}

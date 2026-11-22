package com.otilm.core.signing.contentsigning.formatting;

import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import java.util.List;
import java.util.stream.Stream;

/**
 * The attribute definitions a content-signing formatter lists for the operations a profile reaches. A signing request
 * may set only the request attributes.
 */
public record ContentSigningFormattingDefinitions(List<BaseAttribute> profileAttributes,
        List<DataAttribute> requestAttributes) {

    public ContentSigningFormattingDefinitions {
        profileAttributes = List.copyOf(profileAttributes);
        requestAttributes = List.copyOf(requestAttributes);
    }

    /** Both kinds of attribute, since the operator sets profile values for each. */
    public List<BaseAttribute> all() {
        return Stream.<BaseAttribute>concat(profileAttributes.stream(), requestAttributes.stream()).toList();
    }
}

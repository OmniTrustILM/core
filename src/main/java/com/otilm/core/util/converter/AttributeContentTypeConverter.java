package com.otilm.core.util.converter;

import com.otilm.api.model.common.attribute.common.content.AttributeContentType;

import java.beans.PropertyEditorSupport;

public class AttributeContentTypeConverter extends PropertyEditorSupport {
    public void setAsText(final String text) throws IllegalArgumentException {
        setValue(AttributeContentType.fromCode(text));
    }
}
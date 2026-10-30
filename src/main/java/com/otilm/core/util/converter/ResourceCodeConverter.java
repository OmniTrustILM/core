package com.otilm.core.util.converter;

import com.otilm.api.model.core.auth.Resource;

import java.beans.PropertyEditorSupport;

public class ResourceCodeConverter extends PropertyEditorSupport {
    public void setAsText(final String text) throws IllegalArgumentException {
        setValue(Resource.findByCode(text));
    }
}

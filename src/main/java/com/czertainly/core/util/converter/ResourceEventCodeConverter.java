package com.czertainly.core.util.converter;

import com.czertainly.api.model.core.other.ResourceEvent;

import java.beans.PropertyEditorSupport;

public class ResourceEventCodeConverter extends PropertyEditorSupport {

    @Override
    public void setAsText(final String text) throws IllegalArgumentException {
        setValue(ResourceEvent.findByCode(text));
    }
}

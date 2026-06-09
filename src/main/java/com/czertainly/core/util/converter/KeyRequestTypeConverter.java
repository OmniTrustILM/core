package com.czertainly.core.util.converter;

import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.core.auth.Resource;

import java.beans.PropertyEditorSupport;

public class KeyRequestTypeConverter extends PropertyEditorSupport {
    public void setAsText(final String text) throws IllegalArgumentException {
        setValue(KeyRequestType.findByCode(text));
    }
}
package com.czertainly.core.util.converter;

import com.otilm.api.model.connector.secrets.SecretType;

import java.beans.PropertyEditorSupport;

public class SecretTypeConverter extends PropertyEditorSupport {

    @Override
    public void setAsText(String text) throws IllegalArgumentException {
        setValue(SecretType.findByCode(text));
    }
}

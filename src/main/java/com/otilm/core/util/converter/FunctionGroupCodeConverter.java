package com.otilm.core.util.converter;

import com.otilm.api.model.core.connector.FunctionGroupCode;

import java.beans.PropertyEditorSupport;

public class FunctionGroupCodeConverter extends PropertyEditorSupport {
    public void setAsText(final String text) throws IllegalArgumentException {
        setValue(FunctionGroupCode.findByCode(text));
    }
}
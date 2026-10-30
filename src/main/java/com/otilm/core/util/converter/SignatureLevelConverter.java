package com.otilm.core.util.converter;

import com.otilm.api.model.common.signature.SignatureLevel;

import java.beans.PropertyEditorSupport;

public class SignatureLevelConverter extends PropertyEditorSupport {
    @Override
    public void setAsText(final String text) throws IllegalArgumentException {
        setValue(SignatureLevel.findByCode(text));
    }
}

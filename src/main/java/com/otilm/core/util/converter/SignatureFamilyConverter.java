package com.otilm.core.util.converter;

import com.otilm.api.model.common.signature.SignatureFamily;

import java.beans.PropertyEditorSupport;

public class SignatureFamilyConverter extends PropertyEditorSupport {
    @Override
    public void setAsText(final String text) throws IllegalArgumentException {
        setValue(SignatureFamily.findByCode(text));
    }
}

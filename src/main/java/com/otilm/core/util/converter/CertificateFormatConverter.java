package com.otilm.core.util.converter;

import com.otilm.api.model.core.certificate.CertificateFormat;

import java.beans.PropertyEditorSupport;

public class CertificateFormatConverter extends PropertyEditorSupport {
    public void setAsText(final String text) throws IllegalArgumentException {
        setValue(CertificateFormat.fromCode(text));
    }
}
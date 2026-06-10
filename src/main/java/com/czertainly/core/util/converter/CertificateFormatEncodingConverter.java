package com.czertainly.core.util.converter;

import com.otilm.api.model.core.certificate.CertificateFormatEncoding;

import java.beans.PropertyEditorSupport;

public class CertificateFormatEncodingConverter extends PropertyEditorSupport {
    public void setAsText(final String text) throws IllegalArgumentException {
        setValue(CertificateFormatEncoding.fromCode(text));
    }
}
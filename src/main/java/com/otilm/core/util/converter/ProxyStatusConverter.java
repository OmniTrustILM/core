package com.otilm.core.util.converter;

import com.otilm.api.model.core.proxy.ProxyStatus;

import java.beans.PropertyEditorSupport;

public class ProxyStatusConverter extends PropertyEditorSupport {
    @Override
    public void setAsText(final String text) throws IllegalArgumentException {
        setValue(ProxyStatus.findByCode(text));
    }
}

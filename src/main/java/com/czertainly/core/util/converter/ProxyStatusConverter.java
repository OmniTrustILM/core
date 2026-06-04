package com.czertainly.core.util.converter;

import com.czertainly.api.model.core.proxy.ProxyStatus;

import java.beans.PropertyEditorSupport;

public class ProxyStatusConverter extends PropertyEditorSupport {
    @Override
    public void setAsText(final String text) throws IllegalArgumentException {
        setValue(ProxyStatus.findByCode(text));
    }
}

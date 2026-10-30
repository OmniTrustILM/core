package com.otilm.core.util.converter;

import com.otilm.api.model.core.connector.ConnectorStatus;

import java.beans.PropertyEditorSupport;

public class ConnectorStatusConverter extends PropertyEditorSupport {
    public void setAsText(final String text) throws IllegalArgumentException {
        setValue(ConnectorStatus.findByCode(text));
    }
}

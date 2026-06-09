package com.czertainly.core.util.converter;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.connector.FunctionGroupCode;

import java.beans.PropertyEditorSupport;
import java.util.Optional;

public class OptionalEnumConverter extends PropertyEditorSupport {
    public void setAsText(final String text) throws IllegalArgumentException {
        // TODO: different way how to make generic optional enum converter
        ConnectorStatus status;
        FunctionGroupCode functionGroupCode;
        try {
            functionGroupCode = FunctionGroupCode.findByCode(text);
            setValue(Optional.of(functionGroupCode));
            return;
        } catch (Exception e) {
        }

        try {
            status = ConnectorStatus.findByCode(text);
            setValue(Optional.of(status));
            return;
        } catch (Exception e) {
        }

        throw new ValidationException(ValidationError.create("Unknown enum value {}", text));
    }
}
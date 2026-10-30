package com.otilm.core.util.converter;

import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;

import java.beans.PropertyEditorSupport;

public class SigningWorkflowTypeConverter extends PropertyEditorSupport {
    @Override
    public void setAsText(final String text) throws IllegalArgumentException {
        setValue(SigningWorkflowType.findByCode(text));
    }
}

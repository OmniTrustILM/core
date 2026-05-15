package com.czertainly.core.util.converter;

import com.czertainly.api.model.client.signing.profile.workflow.SigningWorkflowType;

import java.beans.PropertyEditorSupport;

public class SigningWorkflowTypeConverter extends PropertyEditorSupport {
    public void setAsText(final String text) throws IllegalArgumentException {
        setValue(SigningWorkflowType.findByCode(text));
    }
}

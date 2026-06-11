package com.otilm.core.util.converter;

import com.otilm.api.model.core.settings.SettingsSection;

import java.beans.PropertyEditorSupport;

public class SettingsSectionCodeConverter extends PropertyEditorSupport {
    public void setAsText(final String text) throws IllegalArgumentException {
        setValue(SettingsSection.findByCode(text));
    }
}

package com.czertainly.core.settings;

import com.otilm.api.model.core.settings.SettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class SettingsCache {

    // In-memory cache
    private static final Map<SettingsSection, SettingsDto> cache = new ConcurrentHashMap<>();

    // Get a setting value by key
    public static <T extends SettingsDto> T getSettings(SettingsSection settingsSection) {
        return (T) cache.get(settingsSection);
    }

    // Cache settings
    public void cacheSettings(SettingsSection settingsSection, SettingsDto settingsDto) {
        cache.put(settingsSection, settingsDto);
    }
}
